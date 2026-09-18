# OSINT Investigation Graph

Manual investigation workspace at `/osint`. The separate service, PostgreSQL database, operator session, CSRF, rate limits and Docker boundary remain in place. No collector is enabled or instantiated; `/collect` returns `410`. Existing collector modules are retained solely as future adapters.

## Operator workflow

Create an investigation, add entities with **Додати сутність** or a double click on the canvas, then connect them with **З’єднати**, the node context menu, or **Shift + drag**. The sidebar searches names, identifiers, URLs, metadata and linked notes. The inspector shows an object's author, time, relationship status, confidence, sources, notes, connected objects and leads.

Entity and relationship type fields accept the suggested types or a custom name. Social accounts use platform, username, URL and notes in platform-agnostic entity metadata. FACT relationships require a source or a written direct observation. New relationships default to HYPOTHESIS. Solid, dashed and dotted edges distinguish FACT, INFERENCE and HYPOTHESIS; no analytics operation creates relationships.

Sources can link to multiple entities, relationships or leads. Upload a screenshot, image or document (10 MiB per source) and record its URL, quote, observation date and notes. Files are stored in the isolated PostgreSQL database, hashed with SHA-256 and downloaded through authenticated, non-cacheable attachment routes. No URL is fetched by the service. Use a new source for a separate evidence item.

Leads have NEW / TO_CHECK / INVESTIGATING / CONFIRMED / DISMISSED statuses and LOW / MEDIUM / HIGH priorities. Create an entity or relationship from a lead through its inspector; linked evidence and notes are carried across. Use **Підтвердити**, **Відхилити** or **Повернути в роботу** in the inspector.

Layers and groups are operator-created records with object memberships. A node/edge in several layers remains visible while any of its layers is enabled. Unlayered objects stay visible. Groups are visual containers, not real entities; when group memberships overlap, the first group is used on the canvas. Select multiple nodes with box selection, then use **Створити групу** or **Об’єднати дублікати** (exactly two entities). Merge shows a preview, preserves original entity/edge data in an evidence record, rewires memberships and notes, and coalesces duplicate edges. A relationship between the two merged nodes becomes archived provenance rather than an invalid self-edge.

Graph, Table, Timeline, Evidence, Leads and Notes are independent views of the same case. Timeline uses event_date, valid_from, valid_to or observed_at, falling back to creation time. Analysis contains degree centrality, connected components, bridges, communities, shortest path and common neighbors.

The Ukrainian vocabulary in `public/uk.js` covers standard wire types, epistemic statuses, priorities, dates and actionable errors; operator content and API/export codes remain unchanged. Confidence is entered as a percentage and sent as 0–1. Unedited date fields retain the original timestamp string, including sub-millisecond precision and timezone.

Search highlights matches; **Лише збіги на графі** explicitly hides other objects. Filters update Cytoscape visibility in place and preserve viewport and selection. Relationship filters retain their endpoint entities. Dragging nodes/groups and automatic layout queue a case-scoped batch save with retry and visible status. The compact toolbar, left sections, tabbed inspector and mobile drawers keep the canvas available. Native checkbox lists and focusable table rows provide keyboard alternatives to graph selection.

A source can be created within a relationship draft; its successful creation is retained across failed attachment uploads. Retrying uploads to the existing source instead of creating a duplicate. Discarding edited forms uses a named Ukrainian confirmation dialog. Safe raster previews are authenticated; SVG/HTML/unknown formats remain downloads.

## Data and compatibility

Migration `002_investigation_workspace` extends existing entities/relationships without recreating them. `workspace_records` stores typed source, lead, note, layer and group documents with common author/time columns. `workspace_links` stores case-scoped references. Typed API validation, foreign keys and serialized case mutations prevent cross-investigation associations. `evidence_files` stores attachments. Existing public observations and relationship evidence are copied into first-class source records while the original records remain available.

JSON/CSV graph imports remain available. Missing relationship status defaults to HYPOTHESIS; supplied FACT, INFERENCE and HYPOTHESIS are preserved. Entity CSV supports `id,type,name` or exported entity columns; relationship CSV supports `source,target,type,epistemic_status,source_url` or exported relationship columns. Separate entity and relationship CSV files can be imported together. Spreadsheet formula prefixes are neutralized on export.

**Export → Full JSON** includes graph data, observations, records, memberships, dates, original provenance and base64 attachments. Import this `osint-investigation/v1` file into an empty investigation to restore it transactionally with fresh IDs and checksummed files. Original author/ID mappings remain in an import-provenance source. Restore is bounded to 50 MiB per JSON; regular graph imports retain `OSINT_MAX_IMPORT_BYTES` (default 5 MiB). Database backups are the recovery path for investigations larger than these transfer limits. Manual investigations are never automatically deleted for age.

MVP uses the existing single operator account; `created_by` identifies that isolated account. There is no multi-user role management or collaborative live editing. CRUD updates the workspace without reloading the page; simultaneous edits from different browsers use last-write-wins fields.

## API additions

All paths below are relative to `/osint/api/investigations/:id`; mutations require `X-OSINT-CSRF`.

- `GET /workspace` — investigation, entities, relationships, observations, records and analysis.
- `PATCH /` — investigation name/description.
- `PATCH /layout` — `{positions:[{id,x,y}]}`; finite bounded coordinates, unique case-owned entity IDs, all-or-nothing metadata updates and audit.
- `GET /sources/:sourceId/preview` — PNG/JPEG/WebP signature-checked inline images with `nosniff`, `no-store` and restrictive CSP. Unknown formats return 415; the download route remains available.
- `POST /manual/entities`, `PATCH|DELETE /entities/:entityId`.
- `POST /relationships`, `PATCH|DELETE /relationships/:relationshipId`.
- `POST /records`, `PATCH|DELETE /records/:recordId` — `{kind,data,links:[{kind,id}]}`.
- `POST|GET /sources/:sourceId/file` — multipart `file` upload or attachment download.
- `POST /merge-preview`, `POST /merge` — `{from,to}`.
- `GET /export?format=json|entities|relationships`.
- `POST /restore` — multipart `file`, empty investigation required.
- `GET /common-neighbors?from=...&to=...`; existing path/analysis/run APIs remain.

Significant mutations and exports are audited. File replacement, deletion and graph merges should be treated as operator edits; use PostgreSQL backups for full point-in-time recovery.

## Verification and release

```sh
cd services/osint-graph
npm test
OSINT_TEST_DATABASE_URL='postgresql:///disposable_osint_test?host=/tmp' node --test --test-concurrency=1
```

Use a disposable database. Integration tests delete only the investigations they create. Tests cover authenticated CRUD, CSRF, scoped references, merge preservation, evidence attachments, restore rollback, layout validation/atomicity/audit, preview authentication/format spoofing/security headers, Ukrainian vocabulary and collector disablement. No database migration is needed for the Ukrainian workspace update.

From the server repository root, deploy only the existing OSINT target:

```sh
bash scripts/server-update.sh osint
```

Migrations run during service startup. Existing OSINT credentials and database isolation remain unchanged. No SSH connection or server deployment is performed as part of the current local release.
