"use strict";
const { randomUUID, createHash } = require("crypto");
const multer = require("multer");
const {
  normalizeEntityInput,
  normalizeRelationshipInput,
  cleanText,
  cleanPublicUrl,
  safeMetadata,
} = require("./security/validation");
const {
  analyzeGraph,
  buildGraph,
  commonNeighbors,
} = require("./analysis/graphEngine");
const kinds = new Set(["source", "lead", "note", "layer", "group"]);
const uuid = (v) => /^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(String(v));
function fail(message, status = 400) {
  throw Object.assign(new Error(message), { status });
}
function text(v, max = 4000, required = false) {
  if (max !== 4000) return cleanText(v, { max, required });
  const value = String(v ?? "")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .trim();
  if (value.length > max) fail("text_too_long");
  if (required && !value) fail("required_text_missing");
  return value;
}
function dataFor(kind, input) {
  const d = safeMetadata(input || {}, { maxArray: 20000, maxKeys: 200000 });
  d.title = text(d.title, 500, true);
  for (const k of ["description", "notes", "quote"])
    if (d[k] != null) d[k] = text(d[k]);
  if (d.url) d.url = cleanPublicUrl(d.url);
  for (const k of ["event_date", "valid_from", "valid_to", "observed_at"])
    if (d[k] && !Number.isFinite(Date.parse(d[k]))) fail("invalid_date");
  if (kind === "lead") {
    d.status = d.status || "NEW";
    d.priority = d.priority || "MEDIUM";
    if (
      !["NEW", "TO_CHECK", "INVESTIGATING", "CONFIRMED", "DISMISSED"].includes(
        d.status,
      )
    )
      fail("invalid_lead_status");
    if (!["LOW", "MEDIUM", "HIGH"].includes(d.priority))
      fail("invalid_priority");
  }
  if (kind === "source") {
    d.epistemic_status = d.epistemic_status || "FACT";
    if (!["FACT", "INFERENCE", "HYPOTHESIS"].includes(d.epistemic_status))
      fail("invalid_epistemic_status");
  }
  return d;
}
async function links(c, investigation, record, input) {
  if (!Array.isArray(input) || input.length > 1000) fail("invalid_links");
  await c.query("DELETE FROM workspace_links WHERE record_id=$1", [record]);
  for (const link of input) {
    const spec = {
      entity: ["entities", "entity_id"],
      relationship: ["relationships", "relationship_id"],
      lead: ["workspace_records", "lead_id"],
    }[link.kind];
    if (!spec || !uuid(link.id)) fail("invalid_reference");
    const found = await c.query(
      `SELECT id FROM ${spec[0]} WHERE id=$1 AND investigation_id=$2${link.kind === "lead" ? " AND kind='lead'" : ""}`,
      [link.id, investigation],
    );
    if (!found.rowCount) fail("reference_not_found");
    await c.query(
      `INSERT INTO workspace_links(record_id,investigation_id,${spec[1]}) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,
      [record, investigation, link.id],
    );
  }
}
async function audit(c, actor, action, id, inv, metadata = {}) {
  await c.query(
    "INSERT INTO audit_logs(user_id,action,resource_type,resource_id,metadata) VALUES($1,$2,$3,$4,$5)",
    [
      actor,
      action,
      "workspace",
      id,
      JSON.stringify({ investigation_id: inv, ...metadata }),
    ],
  );
  await c.query("UPDATE investigations SET updated_at=NOW() WHERE id=$1", [
    inv,
  ]);
}
async function snapshot(store, id) {
  const graph = await store.getGraph(id);
  const records = (
    await store.pool.query(
      `SELECT r.*, f.name AS file_name, f.mime AS file_mime, f.sha256,
    COALESCE((SELECT jsonb_agg(jsonb_build_object('kind',CASE WHEN l.entity_id IS NOT NULL THEN 'entity' WHEN l.relationship_id IS NOT NULL THEN 'relationship' ELSE 'lead' END,'id',COALESCE(l.entity_id,l.relationship_id,l.lead_id))) FROM workspace_links l WHERE l.record_id=r.id),'[]') AS links
    FROM workspace_records r LEFT JOIN evidence_files f ON f.source_id=r.id WHERE r.investigation_id=$1 ORDER BY r.created_at`,
      [id],
    )
  ).rows;
  const observations = (
    await store.pool.query(
      "SELECT * FROM observations WHERE investigation_id=$1 ORDER BY observed_at",
      [id],
    )
  ).rows;
  return {
    investigation: await store.getInvestigation(id),
    ...graph,
    records,
    observations,
    findings: await store.listFindings(id),
  };
}
function csv(rows, columns) {
  const cell = (v) => {
    let s =
      typeof v === "object" && v !== null ? JSON.stringify(v) : String(v ?? "");
    if (/^[\s]*[=+\-@]/.test(s)) s = `'${s}`;
    return `"${s.replace(/"/g, '""')}"`;
  };
  return [
    columns.join(","),
    ...rows.map((r) => columns.map((k) => cell(r[k])).join(",")),
  ].join("\r\n");
}
function registerWorkspace(app, { store, config }) {
  const base = "/osint/api/investigations/:id";
  const wrap = (fn) => async (req, res, next) => {
    try {
      if (!uuid(req.params.id)) fail("invalid_investigation_id");
      await store.ensureInvestigation(req.params.id);
      await fn(req, res);
    } catch (e) {
      if (e.status)
        return res.status(e.status).json({ ok: false, error: e.message });
      if (e.code === "23505")
        return res.status(409).json({ ok: false, error: "duplicate_record" });
      if (["22P02", "23514", "23503", "22007", "22008"].includes(e.code))
        return res.status(400).json({ ok: false, error: "invalid_record" });
      next(e);
    }
  };
  const mutate = async (req, action, work) =>
    store.withTransaction(async (c) => {
      // One case lock serializes edits, limits and merges; all references are scoped to this case.
      await c.query("SELECT id FROM investigations WHERE id=$1 FOR UPDATE", [
        req.params.id,
      ]);
      const result = await work(c);
      await audit(
        c,
        req.osintActor.id,
        action,
        result?.id || req.params.id,
        req.params.id,
      );
      return result;
    });
  app.get(
    `${base}/workspace`,
    wrap(async (req, res) => {
      const workspace = await snapshot(store, req.params.id);
      res.json({
        ok: true,
        workspace,
        analysis: analyzeGraph(workspace.entities, workspace.relationships),
      });
    }),
  );
  app.patch(
    base,
    wrap(async (req, res) => {
      const result = await mutate(req, "investigation.edit", (c) =>
        c.query(
          "UPDATE investigations SET name=$2,description=$3 WHERE id=$1 RETURNING *",
          [
            req.params.id,
            text(req.body.name, 160, true),
            text(req.body.description, 2000),
          ],
        ),
      );
      res.json({ ok: true, investigation: result.rows[0] });
    }),
  );
  app.post(
    `${base}/manual/entities`,
    wrap(async (req, res) => {
      const result = await mutate(req, "entity.create", async (c) => {
        const n = normalizeEntityInput(req.body);
        const count = await c.query(
          "SELECT count(*)::int n FROM entities WHERE investigation_id=$1",
          [req.params.id],
        );
        if (count.rows[0].n >= config.maxGraphNodes)
          fail("graph_node_limit_exceeded", 409);
        const metadata = safeMetadata({
          ...n.metadata,
          platform: n.platform,
          username: n.username,
          url: n.profileUrl,
          notes: text(req.body.notes || n.metadata.notes),
          ...dateFields(req.body),
        });
        return (
          await c.query(
            "INSERT INTO entities(id,investigation_id,type,canonical_name,display_name,metadata,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *",
            [
              randomUUID(),
              req.params.id,
              n.type,
              n.canonicalName,
              n.displayName,
              JSON.stringify(metadata),
              req.osintActor.id,
            ],
          )
        ).rows[0];
      });
      res.status(201).json({ ok: true, entity: result });
    }),
  );
  app.patch(
    `${base}/entities/:entityId`,
    wrap(async (req, res) => {
      const entity = await mutate(req, "entity.edit", async (c) => {
        const old = (
          await c.query(
            "SELECT * FROM entities WHERE id=$1 AND investigation_id=$2",
            [req.params.entityId, req.params.id],
          )
        ).rows[0];
        if (!old) fail("entity_not_found", 404);
        const n = normalizeEntityInput({ ...old, ...req.body });
        const metadata = safeMetadata({
          ...old.metadata,
          ...n.metadata,
          ...dateFields(req.body),
        });
        for (const k of ["notes", "platform", "username"])
          if (req.body[k] !== undefined) metadata[k] = text(req.body[k]);
        if (req.body.url !== undefined)
          metadata.url = cleanPublicUrl(req.body.url);
        const row = (
          await c.query(
            "UPDATE entities SET type=$3,canonical_name=$4,display_name=$5,metadata=$6,updated_at=now() WHERE id=$1 AND investigation_id=$2 RETURNING *",
            [
              old.id,
              req.params.id,
              n.type,
              n.canonicalName,
              n.displayName,
              JSON.stringify(metadata),
            ],
          )
        ).rows[0];
        // The platform-agnostic metadata is authoritative for manual edits, including legacy accounts.
        await c.query("DELETE FROM social_accounts WHERE entity_id=$1", [
          old.id,
        ]);
        return row;
      });
      res.json({ ok: true, entity });
    }),
  );
  for (const type of ["entities", "relationships"])
    app.delete(
      `${base}/${type}/:recordId`,
      wrap(async (req, res) => {
        await mutate(req, `${type}.delete`, async (c) => {
          const old = (
            await c.query(
              `DELETE FROM ${type} WHERE id=$1 AND investigation_id=$2 RETURNING *`,
              [req.params.recordId, req.params.id],
            )
          ).rows[0];
          if (!old) fail("record_not_found", 404);
          await audit(
            c,
            req.osintActor.id,
            `${type}.deleted_snapshot`,
            old.id,
            req.params.id,
            { previous: old },
          );
          return old;
        });
        res.json({ ok: true });
      }),
    );
  async function relationship(req, res) {
    const row = await mutate(
      req,
      req.params.relationshipId ? "relationship.edit" : "relationship.create",
      async (c) => {
        let old = {};
        if (req.params.relationshipId) {
          old = (
            await c.query(
              "SELECT * FROM relationships WHERE id=$1 AND investigation_id=$2",
              [req.params.relationshipId, req.params.id],
            )
          ).rows[0];
          if (!old) fail("relationship_not_found", 404);
        }
        const input = { ...old, ...req.body };
        const n = normalizeRelationshipInput(input);
        const found = await c.query(
          "SELECT id FROM entities WHERE investigation_id=$1 AND id=ANY($2::uuid[])",
          [req.params.id, [n.source, n.target]],
        );
        if (found.rowCount !== 2) fail("reference_not_found");
        const meta = safeMetadata({
          ...old.metadata,
          ...n.metadata,
          label: text(input.label || n.metadata.label, 160),
          notes: text(input.notes ?? n.metadata.notes),
          ...dateFields(input),
        });
        if (input.source_ids !== undefined && !Array.isArray(input.source_ids))
          fail("invalid_sources");
        const priorSources = old.id
          ? (
              await c.query(
                "SELECT record_id FROM workspace_links l JOIN workspace_records r ON r.id=l.record_id WHERE l.relationship_id=$1 AND r.kind='source'",
                [old.id],
              )
            ).rows.map((r) => r.record_id)
          : [];
        const sourceIds = input.source_ids ?? priorSources;
        if (
          n.status === "FACT" &&
          !text(input.explanation || meta.notes) &&
          !sourceIds.length
        )
          fail("fact_requires_evidence_or_direct_observation");
        let result;
        if (old.id)
          result = await c.query(
            "UPDATE relationships SET source_entity_id=$3,target_entity_id=$4,relationship_type=$5,epistemic_status=$6,confidence=$7,metadata=$8,explanation=$9,last_observed_at=now() WHERE id=$1 AND investigation_id=$2 RETURNING *",
            [
              old.id,
              req.params.id,
              n.source,
              n.target,
              n.type,
              n.status,
              n.confidence,
              JSON.stringify(meta),
              text(input.explanation),
            ],
          );
        else {
          const count = await c.query(
            "SELECT count(*)::int n FROM relationships WHERE investigation_id=$1",
            [req.params.id],
          );
          if (count.rows[0].n >= config.maxGraphRelationships)
            fail("graph_relationship_limit_exceeded", 409);
          result = await c.query(
            "INSERT INTO relationships(id,investigation_id,source_entity_id,target_entity_id,relationship_type,epistemic_status,confidence,metadata,explanation,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *",
            [
              randomUUID(),
              req.params.id,
              n.source,
              n.target,
              n.type,
              n.status,
              n.confidence,
              JSON.stringify(meta),
              text(input.explanation),
              req.osintActor.id,
            ],
          );
        }
        if (input.source_ids !== undefined)
          await c.query(
            "DELETE FROM workspace_links l USING workspace_records r WHERE l.record_id=r.id AND r.kind='source' AND l.relationship_id=$1 AND NOT (l.record_id=ANY($2::uuid[]))",
            [result.rows[0].id, sourceIds],
          );
        for (const source of sourceIds) {
          const exists = await c.query(
            "SELECT id FROM workspace_records WHERE id=$1 AND investigation_id=$2 AND kind='source'",
            [source, req.params.id],
          );
          if (!exists.rowCount) fail("source_not_found");
          await c.query(
            "INSERT INTO workspace_links(record_id,investigation_id,relationship_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
            [source, req.params.id, result.rows[0].id],
          );
        }
        return result.rows[0];
      },
    );
    res.json({ ok: true, relationship: row });
  }
  app.post(`${base}/relationships`, wrap(relationship));
  app.patch(`${base}/relationships/:relationshipId`, wrap(relationship));
  async function record(req, res) {
    const result = await mutate(req, "workspace.record.save", async (c) => {
      const old = req.params.recordId
        ? (
            await c.query(
              "SELECT * FROM workspace_records WHERE id=$1 AND investigation_id=$2",
              [req.params.recordId, req.params.id],
            )
          ).rows[0]
        : null;
      if (req.params.recordId && !old) fail("record_not_found", 404);
      const kind = old?.kind || req.body.kind;
      if (!kinds.has(kind)) fail("invalid_record_kind");
      const data = dataFor(kind, { ...old?.data, ...req.body.data });
      const id = old?.id || randomUUID();
      const row = old
        ? await c.query(
            "UPDATE workspace_records SET data=$3,updated_at=now() WHERE id=$1 AND investigation_id=$2 RETURNING *",
            [id, req.params.id, JSON.stringify(data)],
          )
        : await c.query(
            "INSERT INTO workspace_records(id,investigation_id,kind,data,created_by) VALUES($1,$2,$3,$4,$5) RETURNING *",
            [id, req.params.id, kind, JSON.stringify(data), req.osintActor.id],
          );
      if (req.body.links !== undefined)
        await links(c, req.params.id, id, req.body.links);
      await audit(
        c,
        req.osintActor.id,
        `${kind}.${old ? "edit" : "create"}`,
        id,
        req.params.id,
      );
      return row.rows[0];
    });
    res.json({ ok: true, record: result });
  }
  app.post(`${base}/records`, wrap(record));
  app.patch(`${base}/records/:recordId`, wrap(record));
  app.delete(
    `${base}/records/:recordId`,
    wrap(async (req, res) => {
      await mutate(req, "workspace.record.delete", async (c) => {
        const old = (
          await c.query(
            "DELETE FROM workspace_records WHERE id=$1 AND investigation_id=$2 RETURNING *",
            [req.params.recordId, req.params.id],
          )
        ).rows[0];
        if (!old) fail("record_not_found", 404);
        await audit(
          c,
          req.osintActor.id,
          `${old.kind}.removed`,
          old.id,
          req.params.id,
          { previous: old },
        );
        return old;
      });
      res.json({ ok: true });
    }),
  );
  const restoreUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024, files: 1, fields: 0 },
  });
  app.post(
    `${base}/restore`,
    restoreUpload.single("file"),
    wrap(async (req, res) => {
      if (!req.file) fail("file_required");
      let data;
      try {
        data = JSON.parse(req.file.buffer.toString("utf8"));
      } catch {
        fail("invalid_json");
      }
      const result = await mutate(req, "investigation.restore", (c) =>
        restore(c, req.params.id, data, req.osintActor.id, config),
      );
      res.json({ ok: true, result });
    }),
  );
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024, files: 1, fields: 0 },
  });
  app.post(
    `${base}/sources/:sourceId/file`,
    upload.single("file"),
    wrap(async (req, res) => {
      if (!req.file) fail("file_required");
      await mutate(req, "source.file.add", async (c) => {
        const found = await c.query(
          "SELECT id FROM workspace_records WHERE id=$1 AND investigation_id=$2 AND kind='source'",
          [req.params.sourceId, req.params.id],
        );
        if (!found.rowCount) fail("source_not_found", 404);
        await c.query(
          "INSERT INTO evidence_files(source_id,name,mime,content,sha256) VALUES($1,$2,$3,$4,$5) ON CONFLICT(source_id) DO UPDATE SET name=EXCLUDED.name,mime=EXCLUDED.mime,content=EXCLUDED.content,sha256=EXCLUDED.sha256",
          [
            req.params.sourceId,
            text(req.file.originalname, 255, true),
            text(req.file.mimetype, 120, true),
            req.file.buffer,
            createHash("sha256").update(req.file.buffer).digest("hex"),
          ],
        );
        return { id: req.params.sourceId };
      });
      res.json({ ok: true });
    }),
  );
  app.get(
    `${base}/sources/:sourceId/file`,
    wrap(async (req, res) => {
      const f = (
        await store.pool.query(
          "SELECT f.* FROM evidence_files f JOIN workspace_records r ON r.id=f.source_id WHERE r.investigation_id=$1 AND r.id=$2",
          [req.params.id, req.params.sourceId],
        )
      ).rows[0];
      if (!f) fail("file_not_found", 404);
      res
        .set("Cache-Control", "no-store")
        .set("Content-Type", "application/octet-stream")
        .set(
          "Content-Disposition",
          `attachment; filename*=UTF-8''${encodeURIComponent(f.name)}`,
        )
        .send(f.content);
    }),
  );
  app.get(
    `${base}/export`,
    wrap(async (req, res) => {
      const data = await snapshot(store, req.params.id);
      const format = req.query.format || "json";
      await store.audit(
        req.osintActor.id,
        "investigation.export",
        "investigation",
        req.params.id,
        { format },
      );
      res.set("Cache-Control", "no-store");
      if (format === "json") {
        const files = (
          await store.pool.query(
            "SELECT f.* FROM evidence_files f JOIN workspace_records r ON r.id=f.source_id WHERE r.investigation_id=$1",
            [req.params.id],
          )
        ).rows.map((f) => ({ ...f, content: f.content.toString("base64") }));
        return res
          .attachment("investigation.json")
          .json({ schema: "osint-investigation/v1", ...data, files });
      }
      if (!["entities", "relationships"].includes(format))
        fail("invalid_export_format");
      const columns =
        format === "entities"
          ? [
              "id",
              "type",
              "display_name",
              "canonical_name",
              "metadata",
              "created_by",
              "created_at",
            ]
          : [
              "id",
              "source_entity_id",
              "target_entity_id",
              "relationship_type",
              "epistemic_status",
              "confidence",
              "explanation",
              "metadata",
              "created_by",
              "created_at",
            ];
      res
        .attachment(`${format}.csv`)
        .type("text/csv")
        .send("\ufeff" + csv(data[format], columns));
    }),
  );
  app.get(
    `${base}/common-neighbors`,
    wrap(async (req, res) => {
      const g = await store.getGraph(req.params.id);
      res.json({
        ok: true,
        ids: commonNeighbors(
          buildGraph(g.entities, g.relationships),
          req.query.from,
          req.query.to,
        ),
      });
    }),
  );
  app.post(
    `${base}/merge-preview`,
    wrap(async (req, res) =>
      res.json({
        ok: true,
        preview: await mergePreview(store.pool, req.params.id, req.body),
      }),
    ),
  );
  app.post(
    `${base}/merge`,
    wrap(async (req, res) => {
      const result = await mutate(req, "entity.merge", async (c) => {
        const p = await mergePreview(c, req.params.id, req.body);
        const from = p.from.id,
          to = p.to.id;
        // Preserve the removed entity and collapsed edges as immutable provenance before rewiring.
        const archive = randomUUID();
        await c.query(
          "INSERT INTO workspace_records(id,investigation_id,kind,data,created_by) VALUES($1,$2,'source',$3,$4)",
          [
            archive,
            req.params.id,
            JSON.stringify({
              title: `Merge: ${p.from.display_name}`,
              description: "Original entity and relationships before merge",
              merge_snapshot: p,
              epistemic_status: "FACT",
            }),
            req.osintActor.id,
          ],
        );
        await links(c, req.params.id, archive, [{ kind: "entity", id: to }]);
        for (const r of p.relationships) {
          const source = r.source_entity_id === from ? to : r.source_entity_id,
            target = r.target_entity_id === from ? to : r.target_entity_id;
          if (source === target) {
            await c.query(
              "DELETE FROM workspace_links a USING workspace_links b WHERE a.relationship_id=$1 AND b.entity_id=$2 AND a.record_id=b.record_id",
              [r.id, to],
            );
            await c.query(
              "UPDATE workspace_links SET entity_id=$2,relationship_id=NULL WHERE relationship_id=$1",
              [r.id, to],
            );
            await c.query("DELETE FROM relationships WHERE id=$1", [r.id]);
            continue;
          }
          const duplicate = (
            await c.query(
              "SELECT id FROM relationships WHERE investigation_id=$1 AND source_entity_id=$2 AND target_entity_id=$3 AND relationship_type=$4 AND epistemic_status=$5 AND id<>$6",
              [
                req.params.id,
                source,
                target,
                r.relationship_type,
                r.epistemic_status,
                r.id,
              ],
            )
          ).rows[0];
          if (duplicate) {
            await c.query(
              "INSERT INTO relationship_evidence(id,relationship_id,observation_id,source_type,source_url,collector,observed_at,confidence,metadata) SELECT gen_random_uuid(),$2,observation_id,source_type,source_url,collector,observed_at,confidence,metadata FROM relationship_evidence WHERE relationship_id=$1 ON CONFLICT(relationship_id,collector,source_url) DO UPDATE SET metadata=relationship_evidence.metadata || EXCLUDED.metadata",
              [r.id, duplicate.id],
            );
            await c.query(
              "DELETE FROM workspace_links a USING workspace_links b WHERE a.relationship_id=$1 AND b.relationship_id=$2 AND a.record_id=b.record_id",
              [r.id, duplicate.id],
            );
            await c.query(
              "UPDATE workspace_links SET relationship_id=$2 WHERE relationship_id=$1",
              [r.id, duplicate.id],
            );
            await c.query("DELETE FROM relationships WHERE id=$1", [r.id]);
          } else
            await c.query(
              "UPDATE relationships SET source_entity_id=$2,target_entity_id=$3 WHERE id=$1",
              [r.id, source, target],
            );
        }
        await c.query(
          "DELETE FROM workspace_links a USING workspace_links b WHERE a.entity_id=$1 AND b.entity_id=$2 AND a.record_id=b.record_id",
          [from, to],
        );
        await c.query(
          "UPDATE workspace_links SET entity_id=$2 WHERE entity_id=$1",
          [from, to],
        );
        await c.query(
          "UPDATE observations SET entity_id=$2 WHERE entity_id=$1",
          [from, to],
        );
        await c.query(
          "UPDATE interactions SET source_entity_id=CASE WHEN source_entity_id=$1 THEN $2 ELSE source_entity_id END,target_entity_id=CASE WHEN target_entity_id=$1 THEN $2 ELSE target_entity_id END WHERE investigation_id=$3",
          [from, to, req.params.id],
        );
        await c.query(
          "UPDATE analysis_findings SET entity_ids=array_replace(entity_ids,$1::uuid,$2::uuid) WHERE investigation_id=$3",
          [from, to, req.params.id],
        );
        await c.query(
          "UPDATE entities SET metadata=$2,updated_at=now() WHERE id=$1",
          [
            to,
            JSON.stringify({
              ...p.from.metadata,
              ...p.to.metadata,
              notes: [p.to.metadata.notes, p.from.metadata.notes]
                .filter(Boolean)
                .join("\n")
                .slice(0, 4000),
              aliases: [
                ...new Set([
                  ...(p.to.metadata.aliases || []),
                  p.from.display_name,
                  p.from.canonical_name,
                ]),
              ],
            }),
          ],
        );
        await c.query("DELETE FROM entities WHERE id=$1", [from]);
        return { id: to };
      });
      res.json({ ok: true, ...result });
    }),
  );
}
function dateFields(input) {
  const result = {};
  for (const k of ["event_date", "valid_from", "valid_to", "observed_at"])
    if (input[k] !== undefined) {
      if (input[k] && !Number.isFinite(Date.parse(input[k])))
        fail("invalid_date");
      result[k] = input[k] || null;
    }
  return result;
}
async function mergePreview(c, inv, input) {
  if (!uuid(input.from) || !uuid(input.to) || input.from === input.to)
    fail("invalid_merge");
  const rows = (
    await c.query(
      "SELECT * FROM entities WHERE investigation_id=$1 AND id=ANY($2::uuid[])",
      [inv, [input.from, input.to]],
    )
  ).rows;
  if (rows.length !== 2) fail("entity_not_found", 404);
  const relationships = (
    await c.query(
      "SELECT r.*, COALESCE((SELECT jsonb_agg(e) FROM relationship_evidence e WHERE e.relationship_id=r.id),'[]') evidence FROM relationships r WHERE investigation_id=$1 AND (source_entity_id=$2 OR target_entity_id=$2)",
      [inv, input.from],
    )
  ).rows;
  const inferenceInputs = (
    await c.query(
      "SELECT i.* FROM inference_inputs i JOIN relationships r ON r.id=i.inference_relationship_id WHERE r.investigation_id=$1",
      [inv],
    )
  ).rows;
  const accounts = (
    await c.query("SELECT * FROM social_accounts WHERE entity_id=$1", [
      input.from,
    ])
  ).rows;
  return {
    from: rows.find((r) => r.id === input.from),
    to: rows.find((r) => r.id === input.to),
    relationships,
    accounts,
    inferenceInputs,
  };
}
async function restore(c, inv, d, actor, config) {
  if (
    d?.schema !== "osint-investigation/v1" ||
    !Array.isArray(d.entities) ||
    !Array.isArray(d.relationships) ||
    !Array.isArray(d.records)
  )
    fail("invalid_dataset_shape");
  if (
    d.entities.length > config.maxGraphNodes ||
    d.relationships.length > config.maxGraphRelationships ||
    d.records.length > 10000
  )
    fail("too_many_records");
  const existing = await c.query(
    "SELECT id FROM entities WHERE investigation_id=$1 UNION ALL SELECT id FROM workspace_records WHERE investigation_id=$1",
    [inv],
  );
  if (existing.rowCount) fail("restore_requires_empty_investigation", 409);
  const map = new Map();
  const mapped = (id) => {
    if (!map.has(id)) fail("reference_not_found");
    return map.get(id);
  };
  for (const row of [
    ...d.entities,
    ...d.relationships,
    ...d.records,
    ...(d.observations || []),
  ]) {
    if (!uuid(row.id) || map.has(row.id)) fail("invalid_record_id");
    map.set(row.id, randomUUID());
  }
  for (const e of d.entities) {
    const n = normalizeEntityInput(e);
    await c.query(
      "INSERT INTO entities(id,investigation_id,type,canonical_name,display_name,metadata,created_by,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
      [
        mapped(e.id),
        inv,
        n.type,
        n.canonicalName,
        n.displayName,
        JSON.stringify({
          ...n.metadata,
          platform: n.metadata.platform || e.platform,
          username: n.metadata.username || e.username,
          url: n.metadata.url || e.profile_url,
        }),
        actor,
        e.created_at || new Date(),
      ],
    );
  }
  for (const o of d.observations || [])
    await c.query(
      "INSERT INTO observations(id,investigation_id,entity_id,source_type,source_url,collector,raw_data,observed_at,epistemic_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
      [
        mapped(o.id),
        inv,
        o.entity_id ? mapped(o.entity_id) : null,
        text(o.source_type, 80, true),
        text(o.source_url, 2048, true),
        text(o.collector, 100, true),
        JSON.stringify(o.raw_data || {}),
        o.observed_at || new Date(),
        o.epistemic_status || "HYPOTHESIS",
      ],
    );
  for (const r of d.relationships) {
    const n = normalizeRelationshipInput(r);
    await c.query(
      "INSERT INTO relationships(id,investigation_id,source_entity_id,target_entity_id,relationship_type,epistemic_status,weight,confidence,metadata,explanation,created_by,created_at,first_observed_at,last_observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
      [
        mapped(r.id),
        inv,
        mapped(n.source),
        mapped(n.target),
        n.type,
        n.status,
        n.weight,
        n.confidence,
        JSON.stringify(n.metadata),
        text(r.explanation),
        actor,
        r.created_at || new Date(),
        r.first_observed_at || new Date(),
        r.last_observed_at || new Date(),
      ],
    );
    for (const e of r.evidence || [])
      await c.query(
        "INSERT INTO relationship_evidence(id,relationship_id,source_type,source_url,collector,observed_at,confidence) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
        [
          randomUUID(),
          mapped(r.id),
          text(e.source_type || "IMPORT", 80),
          text(e.source_url, 2048, true),
          text(e.collector || "manual-import", 100),
          e.observed_at || new Date(),
          e.confidence ?? 1,
        ],
      );
  }
  for (const r of d.records) {
    if (!kinds.has(r.kind)) fail("invalid_record_kind");
    const data = dataFor(r.kind, r.data);
    await c.query(
      "INSERT INTO workspace_records(id,investigation_id,kind,data,created_by,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7)",
      [
        mapped(r.id),
        inv,
        r.kind,
        JSON.stringify(data),
        actor,
        r.created_at || new Date(),
        r.updated_at || new Date(),
      ],
    );
  }
  for (const r of d.records)
    await links(
      c,
      inv,
      mapped(r.id),
      (r.links || []).map((l) => ({ kind: l.kind, id: mapped(l.id) })),
    );
  for (const f of d.files || []) {
    if (!d.records.some((r) => r.id === f.source_id && r.kind === "source"))
      fail("source_not_found");
    const content = Buffer.from(String(f.content), "base64");
    if (content.length > 10 * 1024 * 1024) fail("file_too_large", 413);
    const hash = createHash("sha256").update(content).digest("hex");
    if (hash !== f.sha256) fail("file_checksum_mismatch");
    await c.query(
      "INSERT INTO evidence_files(source_id,name,mime,content,sha256) VALUES($1,$2,$3,$4,$5)",
      [
        mapped(f.source_id),
        text(f.name, 255, true),
        text(f.mime, 120, true),
        content,
        hash,
      ],
    );
  }
  // Retain original authors, identifiers and all exported ancillary provenance in the archive.
  const provenance = {
    title: "Import provenance",
    description:
      "Original authors, identifiers and relationships from imported investigation",
    original_investigation: d.investigation,
    entity_origins: d.entities.map((e) => ({
      id: e.id,
      restored_id: mapped(e.id),
      created_by: e.created_by,
    })),
    relationship_origins: d.relationships.map((r) => ({
      id: r.id,
      restored_id: mapped(r.id),
      created_by: r.created_by,
    })),
    record_origins: d.records.map((r) => ({
      id: r.id,
      restored_id: mapped(r.id),
      created_by: r.created_by,
    })),
    interactions: d.interactions || [],
    findings: d.findings || [],
  };
  await c.query(
    "INSERT INTO workspace_records(id,investigation_id,kind,data,created_by) VALUES($1,$2,'source',$3,$4)",
    [randomUUID(), inv, JSON.stringify(provenance), actor],
  );
  return {
    entities: d.entities.length,
    relationships: d.relationships.length,
    records: d.records.length,
  };
}
module.exports = { registerWorkspace, dataFor, csv, mergePreview };
