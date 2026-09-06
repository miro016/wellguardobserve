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
- Configuration and versioned application adapters use bounded anonymous GET requests against fixed paths. The 30-product catalog enforces one to four GETs per manifest, requires a declared product signature, and discards response bodies from adapter results. The WordPress specialist uses public REST `view` context only; it never requests authenticated `edit` fields. The Keycloak adapter makes at most four public GETs for identity, OIDC metadata, canonical-host, and administration-route evidence.
- Frontend API discovery reads the entry page and at most twelve same-origin JavaScript bundles, each capped at 1.25 MiB. It retains API-shaped route names and backend client markers, discards query values, does not invoke discovered business routes, and requests `/api/health` only after a shipped PocketBase marker is observed.
- Public-directory inspection accepts only a directory-shaped path already observed in robots, sitemap, or page evidence. It performs one GET and may follow only the exact same-path slash redirect. It retains generated-index filenames, never requests an entry, and rejects file-like paths, queries, fragments, and traversal syntax.
- The `safe-recon-v1` audit performs five sequential GET requests from an in-repository allowlist. Strict response signatures prevent generic SPA fallbacks from becoming findings. It never returns environment/configuration values and excludes authentication, payload injection, fuzzing, headless actions, out-of-band callbacks, CVE exploit checks, and arbitrary downloaded templates.
- Scan capability is resolved from a server-owned Baseline, Standard, or Active validation policy. All three are selectable in the PoC after the target itself is authorized. The chosen version, maximum actions, methods, and enabled tools are snapshotted on the job when the worker claims it.
- Standard and Active validation may run the browser/session control tool. It makes one baseline GET and one GET with the fixed synthetic origin `https://wellguard.invalid`. It retains cookie names and attributes but never values, never sends credentials, and never replays a cookie.
- Active validation may run the quoted-input differential once on a previously observed anonymous read-only path and parameter. It sends a neutral value, inert text containing one quote, and the same neutral value again. The tool cannot send SQL keywords, operators, comments, semicolons, timing functions, stacked statements, or extraction syntax. A finding requires stable controls, a 5xx response, and a strict database error marker; it is classified as error disclosure and never proof of SQL injection.
- Active validation may run a sequential rate-control check on a previously observed anonymous read-only path. It stops at HTTP 429 or ten GETs. Only after 429 may it make at most three comparisons using reserved RFC 5737 `X-Forwarded-For` identities. It sends no body, cookie, credentials or authorization header and performs no concurrency, proxy rotation, continued bypass, capacity or denial-of-service test.
- Active validation may run Nuclei 3.11.1 only against a pre-resolved authorized public address with the authorized Host and TLS SNI. It uses five local GET-only templates, concurrency one, a two-request-per-second ceiling, 6-second request timeouts, bounded responses, and no redirects, local-network access, OOB callbacks, runtime template updates, code, headless, fuzzing, or DAST. Raw responses are discarded.
- Active unknown-web recognition performs one root GET and one fixed favicon GET, then compares selected headers and the favicon MD5 with pinned Rapid7 Recog rules. It stores the SHA-256 as evidence and treats a lone fingerprint as a hypothesis rather than proof.
- A user stop aborts the LangChain run before another tool begins; a bounded request already in flight is allowed to return or time out rather than being replaced with a more forceful action.
- While a request is processing, the worker updates a five-second heartbeat and a human-readable phase. The phase describes execution state but does not expose hidden model chain-of-thought.

## Agent boundary

The model has no shell, filesystem, credential, arbitrary database, or general-purpose socket tool. It cannot modify a target service. Total tool actions are capped for each run.

Service banners, HTML, JSON, documentation, fingerprints, and repository text are untrusted data. Prompts explicitly prohibit following instructions embedded in evidence. Public fingerprint packs are pinned to exact revisions, size-bounded, normalized, and limited to supported fields. Product names require direct response evidence and cannot be inferred from hostnames or generic tool notes. Tool policy is enforced in code regardless of model output.

PocketBase users cannot change their own global or workspace role. Workspace access, operator actions, and governance actions are enforced by PocketBase rules; administrative routes also have an Angular guard. The observer authenticates through a dedicated `workers` collection; its process environment does not receive the PocketBase superuser credentials, and it cannot change a target's hostname, workspace, owner, authorization, private-address policy, or related-host scope.

Public identity records are tenant-private and derived only from fields a scoped service or authoritative registry directly returned. Wellguard does not search for a person by name, infer a LinkedIn URL, scrape social networks, or infer employment from the absence of public information. Current/former labels are owner review metadata, not agent conclusions.

OWASP WSTG mappings describe test methods, OWASP ASVS 5.0.0 mappings describe verification requirements, and EU Cyber Resilience Act mappings describe possible regulatory relevance. They do not represent certification, a legal-scope decision, or a CRA conformity assessment.

## Prohibited behavior

- Credential guessing or default-password testing
- Authentication bypass attempts
- Exploit payload or arbitrary injection execution
- Persistence, broad evasion, load testing, or destructive requests
- Scanning outside the recorded authorization scope
- Claims of a specific vulnerability without an exact observed version and matching applicability evidence

## Reporting

Severity expresses possible impact. Confidence expresses evidence quality. Version and product statements should use `observed`, `inferred`, or `possible` language. Tool failures must not be converted into claims that a target is safe.

Every retained finding receives a customer-facing incident path generated from server-owned templates. Its first step summarizes observed evidence; every downstream step is explicitly labelled possible and untested. The fixed evidence boundary states that Wellguard did not authenticate, upload, run commands, elevate privileges, read private data, or prove the downstream scenario. This permits useful consequence modeling without turning a hypothetical chain into a false penetration-test claim.
