# Contracts

Owner: A1. Changes require a documented proposal and review by every affected module owner (CLAUDE.md section 5.3 and 5.4).

No contracts exist yet. They are approved in Phase 1, limited to what the first vertical slice needs:

- Asset identity model
- Device capability model
- Event and timestamp schema
- Adapter invocation and result contract
- Error and timeout semantics
- Authentication and authorization boundaries
- Inter-module communication
- Persistent data ownership
- Audit event format
- API versioning and compatibility expectations

Each contract ships with its own deterministic tests. Module owners (A2–A5) must not invent incompatible representations of these concepts in their modules.
