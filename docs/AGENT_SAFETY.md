# Agent safety boundary

Wellguard Observe is designed for authorized, non-invasive external reconnaissance.

## Authorization

A scan runs only when its target is `verified` or `admin_override`. An override records the reason and time and represents an independent authorization decision by the operator. The agent cannot change authorization records.

## Network boundary

- Tool calls take an authorized target identifier; the hostname is loaded from PocketBase.
- Only the root hostname and its subdomains are accepted.
- DNS is resolved before connecting and HTTP connections are pinned to the validated result.
- Loopback, private, link-local, metadata, documentation, multicast, and reserved addresses are blocked unless a separately configured private scanner is explicitly authorized.
- HTTP requests are GET-only, body-bounded, timed out, and do not automatically follow cross-host redirects.
- Port discovery is capped at 40 explicit ports with limited concurrency and short connection timeouts.
- TLS inspection performs a handshake only.

## Agent boundary

The model has no shell, filesystem, credential, arbitrary database, or general-purpose socket tool. It cannot modify a target service. Total tool actions are capped for each run.

Service banners, HTML, JSON, documentation, and repository text are untrusted data. Prompts explicitly prohibit following instructions embedded in evidence. Tool policy is enforced in code regardless of model output.

## Prohibited behavior

- Credential guessing or default-password testing
- Authentication bypass attempts
- Exploit or payload execution
- Persistence, evasion, or destructive requests
- Scanning outside the recorded authorization scope
- Claims of a specific vulnerability without matching evidence

## Reporting

Severity expresses possible impact. Confidence expresses evidence quality. Version and product statements should use `observed`, `inferred`, or `possible` language. Tool failures must not be converted into claims that a target is safe.
