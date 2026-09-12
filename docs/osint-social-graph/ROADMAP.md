# Roadmap

## MVP delivered

The first release establishes the isolated database/service boundary, permission gateway, investigations, manual creation/import, GitHub and safe website collectors, provenance, deterministic graph analytics, transparent scoring, graph-first UI, audit log, retention, demo fixture and security/tests.

## Version 2 priorities

1. Operator-level investigation sharing and ownership rules instead of the shared `osint-access` workspace.
2. Durable worker lease/queue and multi-replica replay/rate limiting after real workload measurements; avoid Redis until it solves an observed problem.
3. Review workflow for imported facts, annotations and explicit entity merge/split with provenance preservation.
4. Temporal observations, graph deltas and scheduled re-collection with source-specific retention.
5. GraphML and Maltego-compatible import/export, followed by a carefully generated OSINT report PDF.
6. Case collaboration and finer permissions (`view`, `collect`, `delete`, `manage`).
7. Optional deterministic entity-resolution suggestions, always labelled inference and requiring human confirmation.
8. Performance evaluation above 500 nodes; only then consider Sigma/WebGL, server-side graph processing or Neo4j.

## Deferred source work

Instagram advanced collection, Telegram network analysis, X, TikTok and LinkedIn remain disabled until official access, cost and use-case approval are established. Also deferred: username enumeration, image similarity, cross-platform identity resolution and automated scraping.

## Optional AI layer

An `analysis/summarizer` seam exists, but MVP output is deterministic. A future LLM may receive only structured entities, relationships, metrics and provenance. It must cite input fact IDs, decline unsupported conclusions and never infer absent links. This needs dedicated hallucination, privacy and prompt-injection evaluation before activation.

## Cost discipline

Stay on the existing Compose host while validating demand. Measure graph counts, run duration, API use, disk growth and operator activity before buying a queue, graph database or separate cloud instance. If Cloud Run is adopted, keep minimum instances at zero where latency permits and use a separate database in the existing Cloud SQL instance first; move to an isolated instance only when the stronger availability/security boundary justifies the recurring compute/storage/backup cost.
