# Architecture

## Browser and data plane

The Angular SPA uses the official PocketBase client directly. Collection API rules enforce record ownership. Public registration is disabled because preview users are invited by an administrator.

Users can read their own targets, scans, findings, TLS observations, assets, relationships, private identity evidence, and agent actions. They can create a `scanRequests` record only for a target they own and only in the `queued` state. An authenticated owner can change an active request only to `cancelling`/`cancelled`; all other lifecycle transitions remain worker-controlled. Users cannot change their role. Administrators can create an `admin_override` target owned by their own account and approve exact related hostnames after recording authorization; public and member target creation remains blocked.

## Observer plane

The Bun process authenticates as a dedicated least-privilege worker, claims queued requests, loads the immutable authorized root plus exact-host scope, creates a scan, and starts a LangChain investigation. LangChain state is streamed: messages and completed tool calls are persisted during the run so the browser can show a live audit trail. A five-second request heartbeat and current execution phase distinguish a healthy long-running model/tool wait from an unavailable worker. The worker polls the request control state and aborts the agent before another tool call when cancellation is requested. Each agent tool is a small typed capability rather than a shell or generic network client.

The agent chooses investigation order and depth. One bounded discovery tool combines stored host hints, exact related hosts, a fixed passive-host query, and safe HTTPS verification before presenting distinct services to the agent. A single relative redirect may be followed only on the already validated hostname so locale/home redirects do not hide the application stack. Wildcard and generic reverse-proxy missing routes are removed. Direct HTML/header markers and pinned ProjectDiscovery fingerprints preserve technology evidence; passive protocol banners can be compared with pinned Rapid7 Recog rules. Neither the topology nor the agent may identify a product from a hostname or policy note alone.

Deeper service checks are adapters registered in `agent/adapters/registry.ts`. Each adapter declares an id, version, products, capabilities, methods, request ceiling, and vendor source. The current Keycloak adapter inspects four fixed public routes; another adapter is added by implementing the same typed contract and registering it. Frontend API discovery separately inspects shipped same-origin bundles and can create an application → backend service relationship from direct client/health evidence. The curated `safe-recon-v1` template engine provides a reviewed GET-only alternative to unrestricted active scanners. Adapter and tool output can create asset relationships, such as a service advertising a different hostname, while the scope guard still prevents probing an unapproved destination.

After investigation, deterministic graph assembly turns observations into typed assets and relationships. Facts retain their basis (`observed`, `registry`, `inferred`, or `owner_confirmed`) and confidence. Findings reference `assetKey`, optional related asset keys, and an optional relationship key, so the UI can show both where to fix a problem and which other asset was disclosed or affected. Domain control-plane tools add authoritative RDAP, DNSSEC, CAA and mail-policy evidence. NVD correlation requires an exact observed product version and returned CPE applicability before a CVE can be confirmed. The executor controls destination scope, private-address policy, request sizes, timeouts, candidate and port counts, protocol behavior, and total action budget.

## Collections

- `users`: invited application users and role.
- `targets`: hostname scope, optional owned-host hints, and authorization evidence.
- `targetScopes`: administrator-approved exact related hostnames and their authorization evidence.
- `scanRequests`: browser-to-worker queue, current phase, and worker heartbeat.
- `scans`: investigation lifecycle and final summary.
- `findings`: evidence, severity, confidence, remediation, sources, CWE weakness IDs, and confirmed CVE IDs.
- `tlsObservations`: structured certificate and protocol evidence.
- `agentActions`: auditable tool calls and bounded outputs.
- `agentMessages`: the application-visible LangChain transcript for each scan.
- `assets`: per-scan typed nodes and evidence facts.
- `assetRelations`: per-scan typed edges, relationship evidence, and linked findings.
- `publicIdentities`: tenant-private, directly published person/mailbox/organization evidence plus optional owner review.
- `workers`: isolated internal observer identities; no browser login or collection-list access.

## Production image

nginx serves Angular and proxies `/api` to PocketBase. PocketBase listens only on loopback. Its administrative dashboard is blocked at nginx. The Bun observer also reaches PocketBase through loopback. Persistent state lives under `/data`.
