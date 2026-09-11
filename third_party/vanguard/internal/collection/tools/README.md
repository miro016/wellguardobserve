# Collection tools

This folder groups actors that contact targets or external providers. It is a
navigation folder, not a Go package.

- `reconpassive/` reads public records and third-party providers without
  contacting the target.
- `reconactive/` probes approved targets directly.
- `scopecheck`, `redact`, and `toolerr` are small shared leaves used by those
  actors.

Each tool owns its configuration, typed result, and operational events. Tools do
not construct domain events or depend on orchestration, projections, or
persistence; orchestration translates their results after they return.
