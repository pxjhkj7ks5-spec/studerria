"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const request = require("supertest");
const { Pool } = require("pg");
const { migrate } = require("../../src/db");
const { OsintStore } = require("../../src/store");
const { createApp } = require("../../src/app");
const { loadConfig } = require("../../src/config");
const { dataFor, csv } = require("../../src/workspace");
test("validates statuses and neutralizes spreadsheet formulas", () => {
  assert.throws(
    () => dataFor("lead", { title: "x", status: "DONE" }),
    /invalid_lead_status/,
  );
  assert.throws(
    () => dataFor("source", { title: "x", url: "javascript:alert(1)" }),
    /invalid_url/,
  );
  assert.match(csv([{ name: "=SUM(1,2)" }], ["name"]), /"'=SUM/);
});
test(
  "manual workflow, isolation, merge, evidence and export restore",
  { skip: !process.env.OSINT_TEST_DATABASE_URL },
  async () => {
    const pool = new Pool({
        connectionString: process.env.OSINT_TEST_DATABASE_URL,
      }),
      cases = [];
    try {
      await migrate(pool);
      const config = loadConfig({
        NODE_ENV: "test",
        OSINT_DATABASE_URL: process.env.OSINT_TEST_DATABASE_URL,
        OSINT_API_RATE_LIMIT_PER_MINUTE: "2000",
      });
      const store = new OsintStore(pool),
        app = createApp({
          config,
          store,
          collectors: new Map(),
          executor: {
            enqueue() {
              throw Error("must not enqueue");
            },
          },
        }),
        agent = request.agent(app);
      await agent
        .post("/osint/api/auth/login")
        .send({
          username: config.adminUsername,
          password: config.adminPassword,
        })
        .expect(200);
      const csrf = (await agent.get("/osint/api/auth/session")).body.csrfToken;
      const create = async (name) => {
        const r = await agent
          .post("/osint/api/investigations")
          .set("x-osint-csrf", csrf)
          .send({ name })
          .expect(201);
        cases.push(r.body.investigation.id);
        return r.body.investigation.id;
      };
      const id = await create("Workspace"),
        other = await create("Isolation");
      const call = (method, path, body = {}, inv = id) =>
        agent[method](`/osint/api/investigations/${inv}${path}`)
          .set("x-osint-csrf", csrf)
          .send(body);
      await agent
        .post(`/osint/api/investigations/${id}/records`)
        .send({})
        .expect(403);
      await call("post", "/collect", { collector: "github" }).expect(410);
      const entity = async (name, inv = id) =>
        (
          await call(
            "post",
            "/manual/entities",
            { type: "PERSON", display_name: name, notes: name + " notes" },
            inv,
          ).expect(201)
        ).body.entity;
      const a = await entity("Alice"),
        b = await entity("A. Example"),
        c = await entity("Company"),
        foreign = await entity("Foreign", other);
      const layout = [
        { id: a.id, x: 12.25, y: -40 },
        { id: b.id, x: 400, y: 500 },
      ];
      await request(app)
        .patch(`/osint/api/investigations/${id}/layout`)
        .send({ positions: layout })
        .expect(401);
      await agent
        .patch(`/osint/api/investigations/${id}/layout`)
        .send({ positions: layout })
        .expect(403);
      await call("patch", "/layout", { positions: layout }).expect(200);
      let persisted = (
        await pool.query("SELECT metadata FROM entities WHERE id=$1", [a.id])
      ).rows[0].metadata;
      assert.deepEqual(persisted.position, { x: 12.25, y: -40 });
      assert.equal(persisted.notes, "Alice notes");
      for (const positions of [
        [
          { id: a.id, x: 8, y: 9 },
          { id: foreign.id, x: 1, y: 2 },
        ],
        [{ id: a.id, x: "1", y: 0 }],
        [{ id: a.id, x: null, y: 0 }],
        [{ id: a.id, x: 1e20, y: 0 }],
        [layout[0], layout[0]],
      ])
        await call("patch", "/layout", { positions }).expect(400);
      persisted = (
        await pool.query("SELECT metadata FROM entities WHERE id=$1", [a.id])
      ).rows[0].metadata;
      assert.deepEqual(persisted.position, { x: 12.25, y: -40 });
      assert.equal(
        (
          await pool.query(
            "SELECT count(*)::int AS n FROM audit_logs WHERE action='layout.save' AND metadata->>'investigation_id'=$1",
            [id],
          )
        ).rows[0].n,
        1,
      );
      await call("post", "/relationships", {
        source: a.id,
        target: foreign.id,
        type: "OWNS",
      }).expect(400);
      await call("post", "/relationships", {
        source: a.id,
        target: c.id,
        type: "OWNS",
        epistemic_status: "FACT",
      }).expect(400);
      const edge = async (source) =>
        (
          await call("post", "/relationships", {
            source,
            target: c.id,
            type: "OWNS",
            epistemic_status: "FACT",
            explanation: "Observed register",
          }).expect(200)
        ).body.relationship;
      const e = await edge(a.id),
        dup = await edge(b.id);
      await call("post", "/relationships", {
        source: a.id,
        target: b.id,
        type: "POSSIBLY_SAME_PERSON_AS",
        epistemic_status: "HYPOTHESIS",
      }).expect(200);
      const record = async (kind, title, links, data = {}) =>
        (
          await call("post", "/records", {
            kind,
            data: { title, ...data },
            links,
          }).expect(200)
        ).body.record;
      const source = await record(
        "source",
        "Register",
        [
          { kind: "entity", id: b.id },
          { kind: "relationship", id: dup.id },
        ],
        { url: "https://example.org/source", quote: "Observed text" },
      );
      const content = Buffer.from("proof test file");
      await agent
        .post(`/osint/api/investigations/${id}/sources/${source.id}/file`)
        .set("x-osint-csrf", csrf)
        .attach("file", content, {
          filename: "proof.txt",
          contentType: "text/plain",
        })
        .expect(200);
      await call("get", `/sources/${source.id}/file`, {}, other).expect(404);
      const previewPath = `/osint/api/investigations/${id}/sources/${source.id}/preview`;
      await request(app).get(previewPath).expect(401);
      await call("get", `/sources/${source.id}/preview`, {}, other).expect(404);
      await agent.get(previewPath).expect(415);
      await agent
        .post(`/osint/api/investigations/${id}/sources/${source.id}/file`)
        .set("x-osint-csrf", csrf)
        .attach("file", Buffer.from('<svg onload="alert(1)"></svg>'), {
          filename: "fake.png",
          contentType: "image/png",
        })
        .expect(200);
      await agent.get(previewPath).expect(415);
      const png = Buffer.from(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l1sAAAAASUVORK5CYII=",
        "base64",
      );
      await agent
        .post(`/osint/api/investigations/${id}/sources/${source.id}/file`)
        .set("x-osint-csrf", csrf)
        .attach("file", png, {
          filename: "proof.png",
          contentType: "application/octet-stream",
        })
        .expect(200);
      const preview = await agent.get(previewPath).expect(200);
      assert.equal(preview.headers["content-type"], "image/png");
      assert.equal(preview.headers["x-content-type-options"], "nosniff");
      assert.equal(preview.headers["cache-control"], "no-store");
      assert.match(preview.headers["content-disposition"], /^inline/);
      // Keep the existing round-trip fixture unchanged after preview security checks.
      await agent
        .post(`/osint/api/investigations/${id}/sources/${source.id}/file`)
        .set("x-osint-csrf", csrf)
        .attach("file", content, {
          filename: "proof.txt",
          contentType: "text/plain",
        })
        .expect(200);
      const lead = await record(
        "lead",
        "Verify ownership",
        [{ kind: "entity", id: b.id }],
        { status: "TO_CHECK", priority: "HIGH" },
      );
      await record(
        "note",
        "Reasoning",
        [
          { kind: "lead", id: lead.id },
          { kind: "relationship", id: dup.id },
        ],
        { description: "Keep uncertainty" },
      );
      await record("layer", "Business", [
        { kind: "entity", id: b.id },
        { kind: "relationship", id: dup.id },
      ]);
      await record("group", "Company group", [
        { kind: "entity", id: b.id },
        { kind: "entity", id: c.id },
      ]);
      await call("post", "/records", {
        kind: "source",
        data: { title: "Forbidden" },
        links: [{ kind: "entity", id: foreign.id }],
      }).expect(400);
      await pool.query(
        "INSERT INTO relationship_evidence(id,relationship_id,source_type,source_url,collector,metadata) VALUES(gen_random_uuid(),$1,'MANUAL','https://example.org/legacy','manual',$2)",
        [dup.id, JSON.stringify({ note: "legacy evidence" })],
      );
      await call("post", "/merge-preview", { from: b.id, to: a.id }).expect(
        200,
      );
      await call("post", "/merge", { from: b.id, to: a.id }).expect(200);
      const w = (await call("get", "/workspace").expect(200)).body.workspace;
      assert.equal(w.entities.length, 2);
      assert.equal(w.relationships.length, 1);
      assert.equal(w.relationships[0].id, e.id);
      assert.equal(w.relationships[0].evidence.length, 1);
      assert.match(
        w.entities.find((x) => x.id === a.id).metadata.notes,
        /A. Example notes/,
      );
      assert.ok(
        w.records
          .find((r) => r.id === source.id)
          .links.some((l) => l.id === e.id),
      );
      assert.ok(
        w.records
          .find((r) => r.id === lead.id)
          .links.some((l) => l.id === a.id),
      );
      assert.ok(w.records.some((r) => r.data.merge_snapshot));
      const exported = (await call("get", "/export?format=json").expect(200))
        .body;
      assert.equal(exported.files[0].content, content.toString("base64"));
      const restored = await create("Restored");
      const restore = (inv, data) =>
        agent
          .post(`/osint/api/investigations/${inv}/restore`)
          .set("x-osint-csrf", csrf)
          .attach("file", Buffer.from(JSON.stringify(data)), {
            filename: "investigation.json",
            contentType: "application/json",
          });
      const result = await restore(restored, exported);
      assert.equal(result.status, 200, JSON.stringify(result.body));
      const rw = (await call("get", "/workspace", {}, restored)).body.workspace;
      assert.equal(rw.entities.length, 2);
      assert.equal(rw.relationships[0].epistemic_status, "FACT");
      assert.equal(rw.records.filter((r) => r.kind === "lead").length, 1);
      const restoredSource = rw.records.find(
        (r) => r.file_name === "proof.txt",
      );
      assert.ok(restoredSource);
      await call(
        "get",
        `/sources/${restoredSource.id}/file`,
        {},
        restored,
      ).expect(200);
      const empty = await create("Rollback");
      await restore(empty, {
        ...exported,
        files: [{ ...exported.files[0], sha256: "bad" }],
      }).expect(400);
      assert.equal(
        (await call("get", "/workspace", {}, empty)).body.workspace.entities
          .length,
        0,
      );
      const audits = (
        await pool.query(
          "SELECT action FROM audit_logs WHERE metadata->>'investigation_id'=$1",
          [id],
        )
      ).rows;
      assert.ok(audits.some((r) => r.action === "entity.merge"));
      assert.ok(audits.some((r) => r.action === "source.file.add"));
    } finally {
      for (const id of cases)
        await pool.query("DELETE FROM investigations WHERE id=$1", [id]);
      await pool.end();
    }
  },
);

test(
  "migration preserves populated legacy graphs and promotes evidence",
  { skip: !process.env.OSINT_TEST_DATABASE_URL },
  async () => {
    const pool = new Pool({
        connectionString: process.env.OSINT_TEST_DATABASE_URL,
      }),
      c = await pool.connect();
    try {
      await c.query("BEGIN");
      const schema = "workspace_upgrade_" + Date.now();
      await c.query(`CREATE SCHEMA ${schema}`);
      await c.query(`SET LOCAL search_path TO ${schema}`);
      await require("../../src/migrations/001_initial_graph").up(c);
      const { randomUUID } = require("crypto");
      const inv = randomUUID(),
        a = randomUUID(),
        b = randomUUID(),
        edge = randomUUID(),
        obs = randomUUID(),
        evidence = randomUUID();
      await c.query(
        "INSERT INTO investigations(id,name,created_by) VALUES($1,$2,1)",
        [inv, "Legacy"],
      );
      for (const [id, name] of [
        [a, "A"],
        [b, "B"],
      ])
        await c.query(
          "INSERT INTO entities(id,investigation_id,type,canonical_name,display_name) VALUES($1,$2,'PERSON',$3,$3)",
          [id, inv, name],
        );
      await c.query(
        "INSERT INTO relationships(id,investigation_id,source_entity_id,target_entity_id,relationship_type) VALUES($1,$2,$3,$4,'LINKED_TO')",
        [edge, inv, a, b],
      );
      await c.query(
        "INSERT INTO observations(id,investigation_id,entity_id,source_type,source_url,collector) VALUES($1,$2,$3,'PUBLIC_SOURCE','https://example.org','legacy')",
        [obs, inv, a],
      );
      await c.query(
        "INSERT INTO relationship_evidence(id,relationship_id,source_type,source_url,collector) VALUES($1,$2,'PUBLIC_SOURCE','https://example.org/proof','legacy')",
        [evidence, edge],
      );
      await require("../../src/migrations/002_investigation_workspace").up(c);
      assert.equal(
        (await c.query("SELECT * FROM workspace_records")).rowCount,
        2,
      );
      assert.equal(
        (await c.query("SELECT * FROM workspace_links")).rowCount,
        2,
      );
      assert.equal(
        (await c.query("SELECT epistemic_status FROM relationships")).rows[0]
          .epistemic_status,
        "FACT",
      );
      assert.equal((await c.query("SELECT * FROM observations")).rowCount, 1);
    } finally {
      await c.query("ROLLBACK");
      c.release();
      await pool.end();
    }
  },
);
