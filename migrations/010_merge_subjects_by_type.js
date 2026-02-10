const parseSubjectType = (name) => {
  const raw = String(name || '').trim();
  const match = raw.match(/\s*\(([^)]+)\)\s*$/i);
  if (!match) {
    return { base: raw, type: null };
  }
  const label = match[1].trim().toLowerCase();
  let type = null;
  if (label.startsWith('лек') || label === 'lecture' || label === 'lect') {
    type = 'lecture';
  } else if (label.startsWith('сем') || label === 'seminar') {
    type = 'seminar';
  }
  const base = raw.replace(match[0], '').trim();
  return { base, type };
};

async function loadCounts(pool, table) {
  const result = await pool.query(`SELECT subject_id, COUNT(*) AS cnt FROM ${table} GROUP BY subject_id`);
  const map = new Map();
  result.rows.forEach((row) => {
    map.set(Number(row.subject_id), Number(row.cnt || 0));
  });
  return map;
}

async function up(pool) {
  await pool.query('BEGIN');
  try {
    const subjectsRes = await pool.query(
      `SELECT id, name, group_count, default_group, show_in_teamwork, visible, is_required, is_general, course_id
       FROM subjects
       ORDER BY id`
    );
    const subjects = subjectsRes.rows || [];
    if (!subjects.length) {
      await pool.query('COMMIT');
      return;
    }

    const countTables = [
      'schedule_entries',
      'student_groups',
      'teacher_subjects',
      'user_subject_optouts',
      'course_day_subjects',
      'homework',
      'teamwork_tasks',
      'messages',
      'schedule_generator_items',
      'schedule_generator_entries',
    ];
    const usageCounts = new Map();
    for (const table of countTables) {
      const tableCounts = await loadCounts(pool, table);
      tableCounts.forEach((count, subjectId) => {
        usageCounts.set(subjectId, (usageCounts.get(subjectId) || 0) + count);
      });
    }

    const groups = new Map();
    subjects.forEach((subject) => {
      const parsed = parseSubjectType(subject.name);
      if (!parsed.base) return;
      const key = `${subject.course_id || 0}|${parsed.base.toLowerCase()}`;
      if (!groups.has(key)) {
        groups.set(key, {
          courseId: subject.course_id,
          baseName: parsed.base,
          lecture: null,
          seminar: null,
          base: null,
        });
      }
      const group = groups.get(key);
      if (parsed.type === 'lecture') {
        group.lecture = subject;
      } else if (parsed.type === 'seminar') {
        group.seminar = subject;
      } else if (String(subject.name).trim().toLowerCase() === parsed.base.toLowerCase()) {
        group.base = subject;
      }
    });

    for (const group of groups.values()) {
      if (!group.lecture || !group.seminar) continue;
      const lecture = group.lecture;
      const seminar = group.seminar;
      const baseSubject = group.base;

      let canonical = baseSubject || null;
      if (!canonical) {
        const lectureScore = usageCounts.get(lecture.id) || 0;
        const seminarScore = usageCounts.get(seminar.id) || 0;
        canonical = lectureScore === seminarScore ? lecture : lectureScore > seminarScore ? lecture : seminar;
      }

      const canonicalId = canonical.id;
      const oldIds = [lecture.id, seminar.id].filter((id) => id !== canonicalId);
      const candidates = [lecture, seminar, baseSubject].filter(Boolean);
      const mergedGroupCount = Math.max(...candidates.map((s) => Number(s.group_count) || 1), 1);
      const mergedDefaultGroup = Math.min(Math.max(Number(canonical.default_group) || 1, 1), mergedGroupCount);
      const mergedShowInTeamwork = candidates.some((s) => Number(s.show_in_teamwork) === 1) ? 1 : 0;
      const mergedVisible = candidates.some((s) => Number(s.visible) === 1) ? 1 : 0;
      const mergedRequired = candidates.some((s) => !!s.is_required);
      const mergedGeneral = candidates.some((s) => !!s.is_general);

      let finalName = canonical.name;
      const targetName = group.baseName;
      if (targetName && String(canonical.name) !== String(targetName)) {
        const nameCheck = await pool.query('SELECT id FROM subjects WHERE LOWER(name) = LOWER($1)', [targetName]);
        const conflict = nameCheck.rows.find(
          (row) =>
            Number(row.id) !== Number(canonicalId) && ![lecture.id, seminar.id].includes(Number(row.id))
        );
        if (!conflict) {
          finalName = targetName;
        }
      }


      await pool.query(
        `UPDATE subjects
         SET name = $1, group_count = $2, default_group = $3, show_in_teamwork = $4,
             visible = $5, is_required = $6, is_general = $7
         WHERE id = $8`,
        [finalName, mergedGroupCount, mergedDefaultGroup, mergedShowInTeamwork, mergedVisible, mergedRequired, mergedGeneral, canonicalId]
      );

      await pool.query(
        `UPDATE schedule_entries
         SET lesson_type = 'lecture'
         WHERE subject_id = $1`,
        [lecture.id]
      );
      await pool.query(
        `UPDATE schedule_entries
         SET lesson_type = 'seminar'
         WHERE subject_id = $1`,
        [seminar.id]
      );
      await pool.query(
        `UPDATE schedule_generator_entries
         SET lesson_type = 'lecture'
         WHERE subject_id = $1`,
        [lecture.id]
      );
      await pool.query(
        `UPDATE schedule_generator_entries
         SET lesson_type = 'seminar'
         WHERE subject_id = $1`,
        [seminar.id]
      );
      await pool.query(
        `UPDATE schedule_generator_items
         SET lesson_type = 'lecture'
         WHERE subject_id = $1`,
        [lecture.id]
      );
      await pool.query(
        `UPDATE schedule_generator_items
         SET lesson_type = 'seminar'
         WHERE subject_id = $1`,
        [seminar.id]
      );

      for (const oldId of oldIds) {
        await pool.query('UPDATE schedule_entries SET subject_id = $1 WHERE subject_id = $2', [canonicalId, oldId]);
        await pool.query('UPDATE schedule_generator_entries SET subject_id = $1 WHERE subject_id = $2', [canonicalId, oldId]);
        await pool.query('UPDATE schedule_generator_items SET subject_id = $1 WHERE subject_id = $2', [canonicalId, oldId]);
        await pool.query('UPDATE homework SET subject_id = $1 WHERE subject_id = $2', [canonicalId, oldId]);
        await pool.query('UPDATE messages SET subject_id = $1 WHERE subject_id = $2', [canonicalId, oldId]);
        await pool.query('UPDATE teamwork_tasks SET subject_id = $1 WHERE subject_id = $2', [canonicalId, oldId]);

        await pool.query(
          `INSERT INTO course_day_subjects (course_study_day_id, subject_id, sort_order, created_at)
           SELECT course_study_day_id, $1, sort_order, created_at
           FROM course_day_subjects
           WHERE subject_id = $2
           ON CONFLICT (course_study_day_id, subject_id) DO NOTHING`,
          [canonicalId, oldId]
        );
        await pool.query('DELETE FROM course_day_subjects WHERE subject_id = $1', [oldId]);

        await pool.query(
          `INSERT INTO user_subject_optouts (user_id, subject_id, created_at)
           SELECT user_id, $1, created_at
           FROM user_subject_optouts
           WHERE subject_id = $2
           ON CONFLICT (user_id, subject_id) DO NOTHING`,
          [canonicalId, oldId]
        );
        await pool.query('DELETE FROM user_subject_optouts WHERE subject_id = $1', [oldId]);

        await pool.query(
          `INSERT INTO teacher_subjects (user_id, subject_id, group_number, created_at)
           SELECT user_id, $1, group_number, created_at
           FROM teacher_subjects
           WHERE subject_id = $2
           ON CONFLICT (user_id, subject_id, group_number) DO NOTHING`,
          [canonicalId, oldId]
        );
        await pool.query('DELETE FROM teacher_subjects WHERE subject_id = $1', [oldId]);
      }

      await pool.query(
        `INSERT INTO student_groups (student_id, subject_id, group_number)
         SELECT sg.student_id, $1 AS subject_id, sg.group_number
         FROM (
           SELECT student_id, group_number FROM student_groups WHERE subject_id = $2
           UNION ALL
           SELECT student_id, group_number FROM student_groups
           WHERE subject_id = $3 AND student_id NOT IN (SELECT student_id FROM student_groups WHERE subject_id = $2)
         ) sg
         WHERE NOT EXISTS (
           SELECT 1 FROM student_groups existing WHERE existing.student_id = sg.student_id AND existing.subject_id = $1
         )`,
        [canonicalId, seminar.id, lecture.id]
      );

      if (lecture.id !== canonicalId) {
        await pool.query('DELETE FROM student_groups WHERE subject_id = $1', [lecture.id]);
      }
      if (seminar.id !== canonicalId) {
        await pool.query('DELETE FROM student_groups WHERE subject_id = $1', [seminar.id]);
      }

      await pool.query('UPDATE homework SET subject = $1 WHERE subject_id = $2', [finalName, canonicalId]);

      for (const oldId of oldIds) {
        await pool.query('DELETE FROM subjects WHERE id = $1', [oldId]);
      }
    }

    await pool.query('COMMIT');
  } catch (err) {
    await pool.query('ROLLBACK');
    throw err;
  }
}

module.exports = {
  id: '010_merge_subjects_by_type',
  up,
};
