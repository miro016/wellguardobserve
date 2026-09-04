# Agent safety boundary

Wellguard Observe is designed for authorized, non-invasive external reconnaissance.

## Authorization

A scan runs only when its target is `verified` or `admin_override`. An override records the reason and time and represents an independent authorization decision by the operator. An administrator may add a related provider hostname as exact-only scope; the parent and sibling hostnames remain prohibited. The observer cannot create or change authorization records.

## Network boundary

- Tool calls take an authorized target identifier; the hostname is loaded from PocketBase.
- Only the root hostname, its subdomains, and separately stored exact related hostnames are accepted. Exact related scope does not extend to children, parents, or siblings.
- DNS is resolved before connecting and HTTP connections are pinned to the validated result.
- Loopback, private, link-local, metadata, documentation, multicast, and reserved addresses are blocked unless a separately configured private scanner is explicitly authorized.
- HTTP requests are GET-only, body-bounded, timed out, and do not automatically follow cross-host redirects.
- Service-host discovery makes one fixed HackerTarget passive query and verifies at most 80 in-scope HTTPS candidates with concurrency capped at five. It may follow one relative redirect on the same validated hostname to capture the rendered page identity and technology markers. Wildcard/missing responses are excluded.
- Port discovery is capped at 40 explicit ports with limited concurrency and short connection timeouts.
- TLS inspection performs a handshake only.
- Banner inspection listens briefly for service-initiated SSH, FTP, or SMTP greetings and sends no command or authentication material.
- RDAP starts with the fixed IANA bootstrap registry, preserves registry redaction, and retains only fields the authoritative service publishes.
- Configuration and versioned application adapters use bounded anonymous GET requests against fixed or explicitly selected metadata paths. The WordPress tool uses public REST `view` context only; it never requests authenticated `edit` fields. The Keycloak adapter makes at most four public GETs for identity, OIDC metadata, canonical-host, and administration-route evidence.
- A user stop aborts the LangChain run before another tool begins; a bounded request already in flight is allowed to return or time out rather than being replaced with a more forceful action.

## Agent boundary

The model has no shell, filesystem, credential, arbitrary database, or general-purpose socket tool. It cannot modify a target service. Total tool actions are capped for each run.

Service banners, HTML, JSON, documentation, fingerprints, and repository text are untrusted data. Prompts explicitly prohibit following instructions embedded in evidence. Public fingerprint packs are pinned to exact revisions, size-bounded, normalized, and limited to supported fields. Product names require direct response evidence and cannot be inferred from hostnames or generic tool notes. Tool policy is enforced in code regardless of model output.

PocketBase users cannot change their own role. Administrative routes have both an Angular guard and PocketBase collection rules. The observer authenticates through a dedicated `workers` collection; its process environment does not receive the PocketBase superuser credentials, and it cannot change a target's hostname, owner, authorization, private-address policy, or related-host scope.

Public identity records are tenant-private and derived only from fields a scoped service or authoritative registry directly returned. Wellguard does not search for a person by name, infer a LinkedIn URL, scrape social networks, or infer employment from the absence of public information. Current/former labels are owner review metadata, not agent conclusions.

## Prohibited behavior

- Credential guessing or default-password testing
- Authentication bypass attempts
- Exploit or payload execution
- Persistence, evasion, or destructive requests
- Scanning outside the recorded authorization scope
- Claims of a specific vulnerability without an exact observed version and matching applicability evidence

## Reporting

Severity expresses possible impact. Confidence expresses evidence quality. Version and product statements should use `observed`, `inferred`, or `possible` language. Tool failures must not be converted into claims that a target is safe.
