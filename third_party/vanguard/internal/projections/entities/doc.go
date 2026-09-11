// Package entities defines the projection-owned assets and assessment facets built
// from Vanguard's immutable collection event stream. Projection folds construct and
// enrich these values; collection records observations as events and does not use
// this package.
//
// # Domain Concepts (Ubiquitous Language)
//
//   - Scan: The aggregate root for a single reconnaissance run. It owns the scan identity
//     (ID matching EventMeta.ScanID), root target, and timing. Constructed via NewScan
//     which enforces non-empty ID and target invariants.
//   - Domain: An Entity capturing the lifecycle of a unique domain name, maintaining
//     invariants regarding structural hierarchy (parent references), tracking provenance
//     via its DiscoverySource, and depth metrics. The Domain aggregates all of its
//     DNS findings via an owned DnsInfo, so every DNS fact about a name lives in one place.
//   - DnsInfo: A component of the Domain aggregate holding the records resolved for a
//     name (A, AAAA, CNAME, MX, NS, TXT, PTR, SOA, DNSSEC) plus any records leaked by a
//     zone transfer. Ordinary DNS resolution is passive collection; zone-transfer
//     records are an explicitly enabled active observation folded into the same facet.
//   - MailSecurity: A component of the Domain aggregate holding the email-authentication
//     posture (SPF with static lookup analysis, DMARC with a graded severity, DKIM
//     selectors, BIMI). Like DnsInfo and Registration it is a facet of the owning Domain,
//     not a standalone asset.
//   - Certificate: An Entity (or distinct Aggregate boundary) encapsulating cryptographic
//     identity state from historical logs or live probes, tracking CN, SANs, serial
//     numbers, ValidFrom/ValidUntil, LoggedAt, and LiveVerifiedAt. NewCertificate
//     rejects empty serial or common name.
//   - IPAddress: An asset Entity for a single resolved address. It bridges a Domain (DNS)
//     to its infrastructure (Netblock, ASN) and is the target of the active phase.
//     NewIPAddress validates the address with net.ParseIP and derives the IP version.
//   - Netblock: An asset Entity for a routed BGP prefix and its owning ASN, grouping
//     addresses by the infrastructure that announces them. NewNetblock validates the CIDR.
//   - Service: An asset Entity for an open port and the service answering on it, produced
//     by the active phase. NewService enforces a valid port range and a tcp/udp protocol.
//   - Finding: A potential weakness discovered against an asset (TLS, DNS, exposure,
//     misconfiguration, or vulnerability). NewFinding enforces a non-empty rule, title,
//     and asset, and derives a stable ID from rule + asset so the same weakness reported
//     by different tools collapses into one Finding with accumulated provenance. A Finding
//     is distinct from a tool Issue: it concerns the target, not the scan. AssetRef points
//     at the affected asset; Reference links to external catalogues (CWE/CVE/URL).
//   - Evidence: A redacted proof artifact captured during a probe (Kind, Summary,
//     RedactedSnippet, Hash, CapturedAt). It never holds credentials, PII, session tokens,
//     or full sensitive bodies; the raw bytes are not persisted.
//   - DiscoverySource: A Value Object enumerating the bounded operational origins of a
//     discovery (e.g., Root Domain, Transparency Log Parser, DNS Resolver, Network Scanner,
//     or HTTP Redirect). A redirect source means the name was referenced in Location; it
//     does not imply the destination was contacted.
//   - Provenance: A Value Object recording how a fact about an asset was established
//     (contributing EventID, Source, Phase, ObservationKind, CapturedAt). An asset accumulates several
//     provenance records as multiple events touch it, giving an auditable lineage.
//   - Confidence: A Value Object expressing how trustworthy an attribution is, either
//     "confirmed" (directly observed) or "inferred" (derived and not yet corroborated).
//
// # Canonical asset identity
//
// AssetRef.Kind fixes the form of AssetRef.ID, and this package owns the functions that
// build each form: ServiceID for a socket, EndpointID for an HTTP(S) URL, and
// CertificateID for a certificate. Finding rules and facts normalizers both use these
// helpers so the asset reference and materialized node agree byte for byte.
//
// Endpoint and Service are separate kinds on purpose. A Service is keyed by the address it
// was observed on; an HTTP response does not prove which address served a hostname URL, so
// flattening a URL into "host/port/tcp" invented a socket the scan never saw. An Endpoint
// keeps the scheme, explicit port, and path the tool actually reported.
//
// A ServiceID carries the transport, and it is load-bearing rather than decorative: a
// TCP and a UDP service on one port are two services, and AssetRef.Proto reads the
// transport back out so a rule that models one of them - a validator that dials, a
// remote-access scenario - gates on it instead of assuming tcp. ProtocolUnknown is the
// third value, for a passive provider that reported a port without ever naming the
// transport it saw. It keeps that observation visible without letting it key the same
// asset as a confirmed TCP service or satisfy a TCP-only rule. NewService still admits
// only tcp and udp, so an unknown transport never becomes an inventory Service.
//
// EndpointID returns an error instead of a best-effort key, and callers fail closed on it.
// An asset id no normalizer would produce is worse than a missing finding: it is a
// dangling reference that the graph reports as an integrity failure.
//
// # Design Decisions & Architectural Alignment
//
//   - Projection Isolation: Entities remain entirely ignorant of storage engines,
//     transport mechanics, and collection event types. Translation from events to
//     entities and provenance lives in the projection folds.
//   - State Sanity via Invariants: Every asset entity has a New* constructor that enforces
//     its invariants (valid IP, valid CIDR, non-empty serial and common name, non-empty
//     normalized domain name, non-negative depth) and is the only sanctioned write path.
//     The exported field structs stay readable so projections can consume them directly.
//
// # Assessment facets and disagreement
//
// A Service and an IPAddress each carry facets an active assessment produced:
// HostProfile on the address (the names, other addresses, OS candidates, uptime,
// and traceroute a host scan gathered), and ServiceScript, TlsAssessment, and
// SshPosture on the service. They are separate structs rather than fields on the
// asset because each is an assessment with its own completeness, and flattening
// them would lose exactly that.
//
// AssessmentState is why they exist in this shape. The dangerous failure mode of a
// security report is an untested check reading as a passed one, so every section of
// a TLS assessment says whether it ran. An empty vulnerability list means "clean"
// only when VulnerabilityState is tested; with any other state it means nothing was
// checked, and TlsAssessment.Assessed reports whether anything ran at all.
//
// Service also carries Conflicts. Several tools probe the same port and each sees
// part of the picture, so a repeat observation enriches an empty field rather than
// being discarded. When two of them report different non-empty values for one field
// the first stays on the asset and the disagreement is recorded here with its
// source and observation time: two tools disagreeing about a product version is
// itself worth reporting, and silently keeping one of them hides both the
// disagreement and the tool that was wrong.
//
// The service name is a second exception, for a related reason: a difference is not
// automatically a disagreement. "http" and "https" name one socket at two layers,
// and "tcpwrapped" names nothing at all, so neither pairing belongs in Conflicts.
// Only two genuinely different application protocols on one port do.
//
// Banners are the other exception, and they are kept in Banners instead. A banner is not
// a claim about what the service is; it is a sample of what the service said to one
// probe at one moment. Two tools that sent different requests, or the same request
// seconds apart, get different bytes back and neither is wrong - so filing the
// second as a conflict with the first would record a disagreement that does not
// exist, and would bury the fields where tools really do disagree.
package entities
