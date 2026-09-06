# Wellguard Observe

Wellguard Observe is an agent-led external exposure monitor for developers and small infrastructure teams. It investigates infrastructure from the public internet, explains what it can observe, and records the evidence behind every conclusion.

It is intentionally bounded: no credential guessing, exploit payloads, exploit execution, load testing, or state-changing requests. The Active validation profile adds only fixed, code-reviewed GET comparisons with hard request ceilings.

## What the MVP does

- Direct Angular-to-PocketBase authentication and workspace-scoped data access, with a one-second live investigation view for the private-preview MVP.
- Administrator-created accounts and administrator-approved target creation; there is no public registration. A platform administrator manages isolated workspaces, assigns multiple users as owner, admin, operator, or viewer, and places multiple targets in each workspace.
- Verified root/subdomain scope plus administrator-approved exact related hostnames. Approving `service.provider.example` never authorizes its parent or sibling tenants.
- LangChain investigation driven by an Ollama model.
- Five freely selectable PoC scan contracts, from Baseline through the explicitly consented Advanced and non-production Unbounded profiles. Target ownership approval remains mandatory, and the worker snapshots the selected limits and available tools into the job before investigation starts.
- Safe DNS, RDAP registration, certificate-transparency, passive hostname search, verified subdomain/service discovery, TCP reachability, passive service banners, HTTP, TLS, public metadata, frontend-to-API discovery, curated safe web audits, bounded unknown-service recognition, a 30-product versioned adapter catalog, NVD, MITRE CWE, GitHub Advisory, OSV, CISA KEV, FIRST EPSS, endoflife.date lifecycle data, canonical CVE Program records, OpenSSF Scorecard context, and bounded public-document tools.
- Findings with separate severity and confidence, preserved evidence, remediation, source URLs, CWE weakness mappings, version-matched CVE identifiers, curated OWASP/CRA relevance links, and a non-technical potential-incident path that visually separates observed facts from untested consequences.
- TLS hostname, trust, issuer, validity window, protocol, cipher, expiry, and explicitly published certificate-email monitoring, plus a browsable certificate-transparency record inventory.
- DNS control-plane visibility for registrar lifecycle, public registration contacts, nameservers, DNSSEC, CAA, MX, SPF, DMARC, MTA-STS, and SMTP TLS reporting.
- Read-only service configuration audits for HTTP security headers, CORS, fixed public API/metadata paths, public directory indexes without file retrieval, and WordPress REST/login/readme/XML-RPC surfaces; directly observed WordPress generator/component versions trigger up to three transparent NVD correlations.
- Evidence-backed technology detection using local markers and pinned, size-bounded ProjectDiscovery WappalyzerGo and Rapid7 Recog catalogues. Active validation can compare server/auth headers and a fixed public favicon against Recog; single-source matches remain labelled hypotheses.
- A checksum-verified Nuclei 3.11.1 engine in the production image. It can run only five committed Wellguard templates, only in Active validation: Go expvar, Prometheus metrics, public OpenAPI, Spring Actuator metadata, and diagnostics indexes. Community downloads, redirects, OOB callbacks, code, headless, fuzzing, and DAST are disabled.
- Bounded active checks: two anonymous GETs for cookie/CORS posture; three GETs comparing a neutral value with inert text containing one quote; and up to ten sequential anonymous GETs plus at most three reserved-address `X-Forwarded-For` comparisons after an observed HTTP 429. Values, cookies, and response secrets are not retained or replayed.
- Report-level OWASP coverage receipts show which external checks actually ran. CRA references are explicitly evidence relevance only, never a legal conclusion or conformity assessment.
- Historical scan, finding, TLS, agent-message, and tool-action records in PocketBase. Current findings are explicitly separated into new, persistent, not observed in the latest run, and owner-confirmed resolved states; absence is never silently treated as remediation.
- A pannable, zoomable evidence-linked topology with architecture, network-routing, and full-evidence lenses. It can expand into a full-viewport operations workspace from the toolbar or with `F`, and `Esc` restores the normal workspace. Hovering an asset highlights its complete directed upstream and downstream path without lighting sibling branches. The default hierarchy is authorized root → hostname → public URL → observed machine/address → one port per machine → application, while provider/network records remain available without crowding the primary view. A time rail replays immutable snapshots and overlays newly observed, changed, and not-observed assets. Branch focus/collapse, tag-filtered portfolio maps, saved local views, SVG export, and print-to-PDF support larger estates.
- An opt-in recurring observation scheduler (daily, weekly, or monthly; Baseline/Standard only) feeds a deterministic change-review inbox. It compares adjacent asset snapshots and lets an administrator approve expected changes, escalate unexpected changes, or confirm remediation. Review state is separate from immutable observation evidence.
- A transparent Wellguard priority score that combines public reachability, owner-set asset criticality, evidence confidence, finding lifecycle, and any retained CISA KEV, FIRST EPSS, and unmodified CVSS data. Missing threat intelligence remains unknown; the score is explicitly not presented as CVSS.
- A deterministic exposure knowledge layer that groups recurring mistakes by weakness, technology, and configuration category. Existing finding histories provide an immediate workspace view; every future run also writes immutable `knowledgeObservations` records for longer-term prevention analysis without an additional model call.
- A target-scoped public identity ledger for names and mailboxes directly disclosed by owned services, RDAP, or `security.txt`. It supports owner-confirmed current/former status, shows only explicitly returned public links, and never guesses or scrapes social profiles.
- A live job console with a five-second worker heartbeat, current phase, model messages, tool inputs/results, delayed/stalled indicators, safe user cancellation, and explicit recovery of jobs interrupted by a single-instance worker restart; evidence already retained remains auditable after a stop.
- Working target administration and scan queue controls, target-scoped surface and finding views, all-target portfolio overview, scan reports, transparent agent traces, source catalog, and workspace settings.
- A custom responsive light/dark security-operations interface and public product landing page.

The seeded acceptance target is `miroslav-petro.com`, with `electric-keycloak.qtgksk.easypanel.host` stored as a separately approved exact hostname. Live observations can change; the UI distinguishes current evidence, inference, registry data, and owner confirmation.

## Architecture

```text
Angular SPA ───────────── PocketBase API
    │                      auth + application records
    │                              ▲
    └─ enqueue scan request        │ results + live action trace
                                   │
                            Bun observer service
                                   │
                            LangChain + Ollama
                                   │
                         policy-bounded read-only tools
```

The Angular application does not use a Bun web API. Bun is an internal worker only. PocketBase rules enforce workspace membership even if the browser UI is bypassed. See [Architecture](docs/ARCHITECTURE.md), [Knowledge base](docs/KNOWLEDGE_BASE.md), [Product adapters](docs/ADAPTERS.md), and [Agent safety](docs/AGENT_SAFETY.md).

## Local development

Requirements:

- Node.js 24 or newer
- Bun 1.3 or newer
- PocketBase 0.40.2
- Ollama signed in for the configured cloud model

Install and validate the code:

```bash
npm install
npm run check
```

Start PocketBase with the committed migrations:

```bash
./pocketbase serve --dir=./pb_data --migrationsDir=./pocketbase/pb_migrations
```

Create a PocketBase superuser, set the variables from `.env.example`, then seed the authorized development target:

```bash
bun run scripts/seed-worker.ts
bun run scripts/seed.ts
```

Run the web application and observer in separate terminals:

```bash
npm start
bun run agent
```

The Angular dev server proxies `/api` to PocketBase on `127.0.0.1:8090`.

To run a one-off authorized investigation without PocketBase:

```bash
bun run agent:once -- --target example.com --profile standard --json report.json
```

Only use the CLI against infrastructure you own or have explicit permission to test.

## Container

The production image contains the compiled Angular application, PocketBase, the Bun observer, nginx, and a minimal process supervisor. One persistent volume stores PocketBase data.

```bash
cp .env.example .env
docker compose up --build
```

Open `http://localhost:8080`. The PocketBase superuser dashboard is deliberately not exposed through nginx. Invite users with:

```bash
docker compose exec wellguard bun run scripts/create-user.ts person@example.com 'a-long-password' 'Person Name'
```

For a production deployment, set long random PocketBase credentials, a precise `PUBLIC_ORIGIN`, and an Ollama URL reachable from the container. Back up the `/data` volume.

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `POCKETBASE_SUPERUSER_EMAIL` | Startup provisioning identity; removed from the observer process environment | required |
| `POCKETBASE_SUPERUSER_PASSWORD` | Startup provisioning credential; removed from the observer process environment | required |
| `POCKETBASE_WORKER_EMAIL` | Least-privilege `workers` collection identity used by the observer | required |
| `POCKETBASE_WORKER_PASSWORD` | Separate observer credential, at least 16 characters | required |
| `POCKETBASE_URL` | Internal PocketBase API | `http://127.0.0.1:8090` |
| `POCKETBASE_DATA_DIR` | Persistent data path | `/data` |
| `WELLGUARD_ADMIN_EMAIL` | Optional first invited administrator | unset |
| `WELLGUARD_ADMIN_PASSWORD` | Optional first administrator password | unset |
| `PUBLIC_ORIGIN` | Allowed browser origin | `*` |
| `OLLAMA_BASE_URL` | Ollama API used by LangChain | `http://127.0.0.1:11434` |
| `OLLAMA_MODEL` | Investigator model | `glm-5.3:cloud` |
| `OLLAMA_REASONING_EFFORT` | Ollama named reasoning level (`low`, `high`, or `max`) | `high` |
| `WELLGUARD_NUCLEI_TEMPLATES` | Immutable reviewed Nuclei template directory | `/app/nuclei/templates` |
| `NUCLEI_BINARY` | Pinned Nuclei executable | `nuclei` |
| `SCAN_POLL_MS` | Queue polling interval | `4000` |

## Free public evidence sources

- Certificate Transparency through `crt.sh`
- IANA's RDAP bootstrap registry and the TLD's authoritative RDAP service
- Passive hostname candidates through the free HackerTarget Host Search API; candidates are never trusted until an in-scope HTTPS response is verified
- ProjectDiscovery WappalyzerGo web fingerprints, pinned to a reviewed MIT-licensed revision
- Rapid7 Recog fingerprints, pinned to a reviewed BSD-2-Clause revision and limited to passive SSH/FTP/SMTP greetings plus web server/auth headers and favicon hashes
- ProjectDiscovery Nuclei 3.11.1 as an execution engine for the committed Wellguard GET-only allowlist; public community templates are not downloaded at runtime
- NIST NVD CVE API 2.0 and the MITRE CWE REST API
- CVE Program canonical CVE Record API (CC0 data)
- endoflife.date API v1 lifecycle catalogue (MIT)
- OpenSSF Scorecard precomputed public API for vendor-confirmed official source repositories
- GitHub reviewed Security Advisories and Releases APIs
- CISA Known Exploited Vulnerabilities feed
- FIRST Exploit Prediction Scoring System API
- OSV.dev package vulnerability API
- DNS records, mail-security policies, and public TLS handshakes
- Public application metadata, shipped same-origin frontend bundles, the audited `safe-recon-v1` GET-only exposure checks, and the versioned 30-product adapter catalog
- OWASP Web Security Testing Guide, OWASP ASVS 5.0.0, and the official EUR-Lex Cyber Resilience Act text as curated evidence references
- Vendor documentation selected by the investigator

External responses are untrusted evidence and are never treated as agent instructions.

## Transparency

New investigations persist each application-visible LangChain message as it is emitted alongside every completed bounded tool input and result. The worker also publishes its current phase and heartbeat while a model or network request is in flight. Product identity requires a direct response fingerprint; hostnames and generic tool policy text are not product evidence. Adapters are registered through a small manifest-driven registry, so another service can be added without changing the agent's safety boundary. The UI intentionally does not infer hidden infrastructure facts: for example, a Cloudflare edge location is never presented as an origin-server location, and service versions remain “Not observed” until direct or corroborated evidence supports them.

## Current MVP limitations

- PocketBase-backed polling is intended for a limited-access, single-instance MVP.
- Cloudflare and other CDNs obscure origin reachability; a future read-only provider integration can evaluate origin firewall configuration.
- Product/version identification remains probabilistic and is labelled with confidence. CVEs are only recordable after exact version and NVD applicability correlation; no-version product names never become CVE claims. Wildcard DNS records and missing reverse-proxy routes are explicitly excluded from the service inventory.
- Neither audit is an unrestricted Nuclei service. Standard provides `safe-recon-v1`; Active validation adds five local Nuclei templates at two requests per second and concurrency one. Both use strict response signatures and exclude fuzzing, authentication, exploit payloads, OOB callbacks, headless actions, code, DAST, and CVE exploit templates. Expanding either allowlist requires a code review.
- The quoted-input differential is deliberately not presented as proof of SQL injection. A strict database error proves an error-disclosure/input-handling condition and requires code review or isolated testing to establish exploitability.
- Ten anonymous GETs without HTTP 429 do not prove that rate limiting is missing. The result applies only to that endpoint, identity, cost and short observation window.
- Cookie/session checks inspect attributes only. They do not authenticate, replay cookies, test session fixation, or verify logout. Generic default-password testing is prohibited because even one attempt can create sessions, trigger audit state or contribute to account lockout.
- External observations can support OWASP verification and CRA risk assessment, but they do not establish OWASP certification, CRA applicability, or CRA conformity.
- The current container bundles three processes for convenient MVP deployment. They should become separate services when scaling independently.

## License

MIT. See [LICENSE](LICENSE).
