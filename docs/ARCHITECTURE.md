# Architecture

## Browser and data plane

The Angular SPA uses the official PocketBase client directly. Collection API rules enforce record ownership. Public registration is disabled because preview users are invited by an administrator.

Users can read their own targets, scans, findings, TLS observations, assets, relationships, private identity evidence, and agent actions. They can create a `scanRequests` record only for a target they own and only in the `queued` state. An authenticated owner can change an active request only to `cancelling`/`cancelled`; all other lifecycle transitions remain worker-controlled. Users cannot change their role. Administrators can create an `admin_override` target owned by their own account and approve exact related hostnames after recording authorization; public and member target creation remains blocked.

## Observer plane

The Bun process authenticates as a dedicated least-privilege worker, finalizes stale processing records left by a previous single-instance process, claims queued requests, loads the immutable authorized root plus exact-host scope, and resolves the requested scan profile against server-owned policy. It stores a profile snapshot (version, tool budget, methods, enabled capabilities, and Nuclei policy) on the request before creating a scan and starting LangChain. LangChain state is streamed: messages and completed tool calls are persisted during the run so the browser can show a live audit trail. A five-second request heartbeat and current execution phase distinguish a healthy long-running model/tool wait from an unavailable worker. The worker polls the request control state and aborts the agent before another tool call when cancellation is requested. Each agent tool is a small typed capability rather than a shell or generic network client.

The agent chooses investigation order and depth. One bounded discovery tool combines stored host hints, exact related hosts, a fixed passive-host query, and safe HTTPS verification before presenting distinct services to the agent. A single relative redirect may be followed only on the already validated hostname so locale/home redirects do not hide the application stack. Wildcard and generic reverse-proxy missing routes are removed. Direct HTML/header markers and pinned ProjectDiscovery fingerprints preserve technology evidence; passive protocol banners can be compared with pinned Rapid7 Recog rules. Neither the topology nor the agent may identify a product from a hostname or policy note alone.

Deeper service checks are inspectors registered through typed tools and a 30-product adapter registry. Each adapter declares an id, version, products, capabilities, methods, request ceiling, and vendor source. Twenty-nine products use a common declarative engine; Keycloak retains bespoke OIDC relationship analysis. The system prompt is product-neutral: the agent lists installed inspectors and dispatches one only after direct response evidence matches its declared products. See [Product adapters](ADAPTERS.md). Frontend API discovery separately inspects shipped same-origin bundles and can create an application → backend service relationship from direct client/health evidence. Standard adds the curated `safe-recon-v1` audit and observable cookie/CORS review. Active validation adds fixed quoted-input and throttling/header-trust comparisons, an unknown-web recognizer (root, favicon, selected headers, and pinned Recog packs), and a checksum-verified Nuclei binary that receives only the committed `nuclei/templates` directory. Every active tool enforces its own path, method, header, input, request-count and response-retention policy in code. Adapter and tool output can create asset relationships, such as a service advertising a different hostname, while the scope guard still prevents probing an unapproved destination.

After investigation, deterministic graph assembly turns observations into typed assets and relationships. Facts retain their basis (`observed`, `registry`, `inferred`, or `owner_confirmed`) and confidence. Public URLs are first-class assets, and ports are keyed to the observed machine/address rather than repeated for every hostname alias. The primary architecture lens can therefore show authorized root → hostname → URL → observed machine → machine port → application, while a separate routing lens carries provider and registered-network context. Findings reference `assetKey`, optional related asset keys, and an optional relationship key, so the UI can show both where to fix a problem and which other asset was disclosed or affected. Hover traversal walks directed ancestors and descendants, highlighting the complete evidence path without crossing into sibling branches. Each finding also receives a deterministic customer narrative with an observed step, possible next step, possible business impact, and fixed non-exploitation boundary. Domain control-plane tools add authoritative RDAP, DNSSEC, CAA and mail-policy evidence. NVD correlation requires an exact observed product version and returned CPE applicability before a CVE can be confirmed. The executor controls destination scope, private-address policy, request sizes, timeouts, candidate and port counts, protocol behavior, and total action budget.

Finding records retain a bounded observation trail and run count. The browser compares each record with the latest completed scan for its target to derive `new`, `persistent`, `not_observed`, and `resolved` views. Only explicit owner workflow produces `resolved`; a finding absent from the latest run remains `not_observed` because scan coverage can change. Adjacent immutable asset snapshots also produce deterministic `added`, `changed`, and `not_observed` surface events. The Change review collection stores only the owner's disposition and note, never a mutable copy of the observed event. The same comparison drives the map time rail and visual overlay, preventing the inbox and topology from disagreeing.

The browser computes a Wellguard priority score from technical severity, public reachability, owner-set target criticality, evidence confidence, lifecycle, and retained threat context. The threat-source layer can query CISA KEV and FIRST EPSS for confirmed CVEs while NVD contributes an unmodified CVSS base metric and vector. Absent KEV, EPSS, or CVSS evidence is displayed as unavailable rather than scored as zero. Asset criticality is environmental context for Wellguard priority; the application does not claim to recalculate or replace CVSS. The worker also emits a deterministic knowledge observation for each finding using its category, observed technology, weakness IDs, framework controls, and asset type. See [Knowledge base](KNOWLEDGE_BASE.md).

## Collections

- `users`: invited application users and role.
- `targets`: hostname scope, optional owned-host hints, authorization evidence, owner-set business criticality, and portfolio tags.
- `targetScopes`: administrator-approved exact related hostnames and their authorization evidence.
- `scanRequests`: browser-to-worker queue, current phase, worker heartbeat, and immutable-at-run profile snapshot.
- `scans`: investigation lifecycle and final summary.
- `findings`: evidence, severity, confidence, remediation, sources, CWE weakness IDs, confirmed CVE IDs, retained KEV/EPSS/CVSS threat context, curated OWASP/CRA references, and the customer-facing potential-impact narrative.
- `tlsObservations`: structured certificate and protocol evidence.
- `agentActions`: auditable tool calls and bounded outputs.
- `agentMessages`: the application-visible LangChain transcript for each scan.
- `assets`: per-scan typed nodes and evidence facts.
- `assetRelations`: per-scan typed edges, relationship evidence, and linked findings.
- `changeReviews`: administrator disposition and notes keyed to a deterministic change in one scan comparison.
- `observationSchedules`: opt-in daily, weekly, or monthly monitoring contracts. The worker can enqueue only the Baseline or Standard profiles; schedules default to absent/off and saving one never launches an immediate run.
- `knowledgeObservations`: immutable per-run pattern facts used to measure recurring configuration and technology risks without another model call.
- `publicIdentities`: tenant-private, directly published person/mailbox/organization evidence plus optional owner review.
- `workers`: isolated internal observer identities; no browser login or collection-list access.

## Production image

nginx serves Angular and proxies `/api` to PocketBase. PocketBase listens only on loopback. Its administrative dashboard is blocked at nginx. The Bun observer also reaches PocketBase through loopback. Persistent state lives under `/data`.
