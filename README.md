# Wellguard Observe

Wellguard Observe is an agent-led external exposure monitor for developers and small infrastructure teams. It investigates infrastructure from the public internet, explains what it can observe, and records the evidence behind every conclusion.

It is intentionally reconnaissance-only: no credential guessing, payload delivery, exploit execution, or state-changing requests.

## What the MVP does

- Direct Angular-to-PocketBase authentication and data access, with a one-second live investigation view for the private-preview MVP.
- Administrator-created accounts and administrator-approved target creation; there is no public registration.
- Verified or explicitly administrator-authorized target scope.
- LangChain investigation driven by an Ollama model.
- Safe DNS, RDAP registration, certificate-transparency, passive hostname search, verified subdomain/service discovery, TCP reachability, HTTP, TLS, public metadata, WordPress configuration, NVD, MITRE CWE, GitHub Advisory, OSV, CISA KEV, and bounded public-document tools.
- Findings with separate severity and confidence, preserved evidence, remediation, source URLs, CWE weakness mappings, and version-matched CVE identifiers.
- TLS hostname, trust, issuer, validity window, protocol, cipher, expiry, and explicitly published certificate-email monitoring, plus a browsable certificate-transparency record inventory.
- DNS control-plane visibility for registrar lifecycle, public registration contacts, nameservers, DNSSEC, CAA, MX, SPF, DMARC, MTA-STS, and SMTP TLS reporting.
- Read-only service configuration audits for HTTP security headers, CORS, fixed public API/metadata paths, and WordPress REST/login/readme/XML-RPC surfaces; directly observed WordPress generator/component versions trigger up to three transparent NVD correlations.
- Evidence-backed web technology detection for common frameworks, CMS products, generators, runtimes, and server headers so same-title applications remain distinguishable.
- Historical scan, finding, TLS, agent-message, and tool-action records in PocketBase.
- A pannable, zoomable evidence-linked topology connecting domains, edge providers, hidden origins, ports, and every identified service without collapsing nodes behind a “more” counter.
- A live scan console with model messages, tool inputs/results, progress, and safe user cancellation; evidence already retained remains auditable after a stop.
- Working target administration and scan queue controls, target-scoped surface and finding views, all-target portfolio overview, scan reports, transparent agent traces, source catalog, and workspace settings.
- A custom responsive light/dark security-operations interface and public product landing page.

The first authorized acceptance target is `miroslav-petro.com`. The agent independently identified eleven distinct service hosts, including its public Easypanel management surface, a public Keycloak master realm and administration console, Keycloak canonical-host disclosure, a Beszel monitoring hub, Cloudflare edge behavior, and healthy TLS state.

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

The Angular application does not use a Bun web API. Bun is an internal worker only. See [Architecture](docs/ARCHITECTURE.md) and [Agent safety](docs/AGENT_SAFETY.md).

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
bun run agent:once -- --target example.com --json report.json
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
| `POCKETBASE_SUPERUSER_EMAIL` | Internal worker identity | required |
| `POCKETBASE_SUPERUSER_PASSWORD` | Internal worker credential | required |
| `POCKETBASE_URL` | Internal PocketBase API | `http://127.0.0.1:8090` |
| `POCKETBASE_DATA_DIR` | Persistent data path | `/data` |
| `WELLGUARD_ADMIN_EMAIL` | Optional first invited administrator | unset |
| `WELLGUARD_ADMIN_PASSWORD` | Optional first administrator password | unset |
| `PUBLIC_ORIGIN` | Allowed browser origin | `*` |
| `OLLAMA_BASE_URL` | Ollama API used by LangChain | `http://127.0.0.1:11434` |
| `OLLAMA_MODEL` | Investigator model | `glm-5.3:cloud` |
| `SCAN_POLL_MS` | Queue polling interval | `4000` |

## Free public evidence sources

- Certificate Transparency through `crt.sh`
- IANA's RDAP bootstrap registry and the TLD's authoritative RDAP service
- Passive hostname candidates through the free HackerTarget Host Search API; candidates are never trusted until an in-scope HTTPS response is verified
- NIST NVD CVE API 2.0 and the MITRE CWE REST API
- GitHub reviewed Security Advisories and Releases APIs
- CISA Known Exploited Vulnerabilities feed
- OSV.dev package vulnerability API
- DNS records, mail-security policies, and public TLS handshakes
- Public application metadata and documented unauthenticated WordPress REST view endpoints
- Vendor documentation selected by the investigator

External responses are untrusted evidence and are never treated as agent instructions.

## Transparency

New investigations persist each application-visible LangChain message as it is emitted alongside every completed bounded tool input and result. Product identity requires a direct response fingerprint; hostnames and generic tool policy text are not product evidence. The UI intentionally does not infer hidden infrastructure facts: for example, a Cloudflare edge location is never presented as an origin-server location, and service versions remain “Not observed” until direct or corroborated evidence supports them.

## Current MVP limitations

- PocketBase-backed polling is intended for a limited-access, single-instance MVP.
- Cloudflare and other CDNs obscure origin reachability; a future read-only provider integration can evaluate origin firewall configuration.
- Product/version identification remains probabilistic and is labelled with confidence. CVEs are only recordable after exact version and NVD applicability correlation; no-version product names never become CVE claims. Wildcard DNS records and missing reverse-proxy routes are explicitly excluded from the service inventory.
- The current container bundles three processes for convenient MVP deployment. They should become separate services when scaling independently.

## License

MIT. See [LICENSE](LICENSE).
