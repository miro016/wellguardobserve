// Package threats holds the curated attack-path scenarios and the logic that
// derives them. It is the threat-scenario analogue of the findings package: one
// scenario per file over a read-only asset graph, plus a Build entry point.
//
// # Scenarios
//
// A scenario is a pure function from the asset graph to zero or more ThreatScenario.
// Each lives in its own file (credential_stuffing.go, transport_downgrade.go, ...) so
// the gating logic for one attack path stays in one place. Unlike a detector finding
// (one event, one weakness), a scenario chains independent findings/facets across
// related assets into a plausible attacker story. Scenarios fire only on qualifying
// combinations, so they stay evidenced rather than speculative.
//
// Most scenarios gate on findings on a single asset kind, but a scenario may walk the
// graph edges to chain across kinds: DowngradeToExposedApp (downgrade_to_exposed_app.go)
// starts from a domain's weak-tls-version finding and fires on a build-disclosing endpoint
// the name reaches - its own web face, or one addressed by an IP the name resolves to -
// joining a domain-level interception weakness to the exposed application, a path that
// was unexpressible before the graph and canonical asset identity.
//
// The join is on what an endpoint URL itself names. A URL-scoped finding is an Endpoint
// finding (entities.AssetKindEndpoint, keyed by the normalized URL), so IISWebExposure
// pairs a version disclosure and missing headers only when both were seen on the same
// URL, and DowngradeToExposedApp names an address only when the endpoint URL is addressed
// by it. Neither invents a serving address for a hostname URL, because an HTTP response
// never proves which address answered it.
//
// A scenario whose narrative describes one transport gates on it. RemoteAccessExposure
// (remote_access_exposure.go) tells the story of an interactive TCP login to Telnet,
// RDP, or VNC, so it fires only on a service asset whose AssetRef.Proto is tcp: a
// service seen on udp is a different service, and one whose reporting provider never
// named a transport is not evidence that the login path exists.
//
// ExposedDatabase (exposed_database.go) joins risky-open-port and
// default-credentials only when both findings name the same canonical service. It
// identifies the database from their structured ServiceFacet product or port and
// never parses the asset id or evidence prose for classification.
//
// A scenario may also up-weight on an inferred facet rather than fire on it:
// CredentialStuffing (credential_stuffing.go) raises its severity to critical when the
// exposed host is reputation-flagged (Graph.FlaggedMalicious). The verdict is inferred,
// so it sharpens an existing evidenced path rather than standing one up on its own - an
// exposure on a host reputation engines already flag is a stronger vector than either
// signal alone.
//
// Build runs the curated set (registered in threats.go) and returns the scenarios
// that fired, ordered by severity, then validation (a validated scenario sorts
// above an equal-severity unvalidated one), then name then asset for a stable
// report.
//
// # Narrative and summary
//
// A scenario carries two prose forms of the same attack path. Narrative names the
// assets it fired on; Summary is the same sentence with the assets left out. One
// scenario class firing on thirteen assets therefore produces thirteen narratives
// and one summary, and a report can explain the path once and then list what it
// fired on rather than repeating the explanation beside every asset.
//
// Both carry the same temporal qualification, so an instance resting on historical
// evidence never shares a summary with one resting on current evidence. A consumer
// that groups by summary is therefore grouping only instances the summary is true
// of, which is what makes grouping safe rather than merely tidy.
//
// # Asset graph
//
// Scenarios never touch the projection directly. They receive a read-only
// assetgraph.Graph (internal/projections/assetgraph), assembled by the caller
// (internal/projections, in BuildThreats) from the folded read models. A
// scenario reads the findings on an asset (FindingAssets/Findings), walks the
// inventory edges (a domain's IPs, an IP's services, a certificate's names), and
// asks the few cross-asset facets it gates on (HasAuthSurface, LiveDomain,
// FlaggedMalicious, NetblockCount). Keeping the scenarios pure over the graph interface avoids an
// import cycle with the projection that assembles them and keeps them trivially
// testable against a small fake.
//
// Scenarios are report artifacts, not persisted events: they are recomputed
// deterministically on every build and replay.
package threats
