// Package attacksurface contracts the complete facts graph into the smaller graph an
// analyst actually reasons about: names, addresses, listening services, and web origins,
// with everything else folded onto one of those four as a property of it.
//
// It is a pure read model. It consumes a [github.com/velgard-sk/vanguard/internal/projections/facts.View]
// and produces a sorted, deterministic artifact; it does no I/O, reads no clock, decodes
// no file, and never folds a raw event. The wiring that loads a scan's stream, builds the
// facts graph, and writes the contracted artifacts lives outside this package.
//
// # Why contract at all
//
// The facts graph is the record: every asset a source ever mentioned, every observation
// behind it, every evidence item, every temporal assertion. That is what makes it
// auditable and what makes it unusable as a picture. A real scan produces certificates,
// DNS records, technologies, providers, netblocks, and hundreds of individual URLs as
// nodes, and an analyst opening that graph cannot see the six things that matter through
// the nine hundred that support them.
//
// So this package removes node kinds, never evidence. A folded fact keeps its statement,
// its confidence, its currentness, and the observation and evidence ids that lead back
// into the facts graph beside it, and it lands on the retained node it was always about. The
// [ContractionSummary] accounts for every facts asset type and every finding, so "where
// did the certificates go" has an answer in the file itself.
//
// # The dependency direction is one-way
//
//	events -> facts Graph -> facts View -> attack-surface Graph -> renderers
//
// The view is the only input. This package never decodes facts.json, reaches into the
// graph's indexes, or re-folds the event stream, which keeps one authority for what a
// source claimed and when: a normalizer fix upstream reaches the attack surface on the
// next replay without a second implementation drifting behind it.
//
// # What is retained and what folds
//
// Four node types survive. Domain merges the facts Domain, Subdomain, and ExternalDomain
// types and keeps the difference as Kind and Scope, because whether a name is in scope is
// a property of the name rather than a different kind of thing. IPAddress and Service
// survive one-to-one. WebSurface groups every Endpoint by normalized URL origin, and each
// URL survives as a sorted path observation carrying the status, title, server, and
// authentication surface that URL reported.
//
// The artifact holds those four in four arrays - Domains, IPAddresses, Services,
// WebSurfaces - rather than in one mixed node list. The type vocabulary is closed, so a
// reader asking "what is listening" takes the services instead of filtering a
// heterogeneous list by a discriminator, and the file states the shape of the surface at
// its top level. Every array is written even when empty, so a kind the scan found none of
// never reads as a key the writer forgot. [Graph.AllNodes] gives the flat list to code
// that reasons about all four at once.
//
// Everything else folds:
//
//   - Certificate becomes a coverage facet on each name it covers. A certificate in a CT
//     log proves someone asked a CA to issue for a name, not that anything serves it
//     today, so the facet keeps the validity window and the source's currentness verbatim
//     and no live deployment is inferred.
//   - DnsRecord becomes a record facet on the owning name, carrying the record value,
//     which is what a DNS policy question is actually about.
//   - Technology attaches to the address, service, or web surface the source relationship
//     named, and the relation travels with it. A passive host observation stays
//     host_observed and never becomes runs: nothing in such a claim identifies which
//     listening service carries the product.
//   - Provider and Netblock fold into the provider attribution facets of the addresses
//     they concern. A netblock reaches an address by prefix containment, which is exact,
//     rather than through a shared ASN, which would attach a prefix to addresses outside
//     it.
//   - MailService reuses or creates the Domain node for the exchanger host and is reached
//     by mail_routes_to. An exchanger is a name, and a second node type for it would split
//     one name across two identities.
//   - Observations become facets on the node they were recorded against. The default is to
//     keep: an observation type this package has never heard of still lands on its node
//     with its statement and provenance, and the short exception list names, for each
//     entry, the node, edge, or path that already carries the same content.
//   - Findings attach to the retained node they concern. Because a finding names the
//     canonical key of a facts asset, most attach directly through the typed mapping: an
//     Endpoint finding contracts onto the WebSurface for its origin exactly as its
//     endpoint asset does. A certificate finding lands on the names the certificate
//     covers, with the original certificate key preserved on the finding; no Certificate
//     node enters this graph, because a certificate is a credential over names rather
//     than something an operator attacks. Each attachment records the rule that placed
//     it. A finding with no defensible target - a wildcard-only certificate covering no
//     retained name, for example - goes to UnmappedFindings rather than to a
//     plausible-looking wrong node, because an unmapped finding an analyst can see beats
//     a misattributed one they cannot. There are no identity-repair fallbacks here: a key
//     that resolves to nothing is a facts-integrity failure that stops generation before
//     this contraction runs, not something to guess at.
//   - Issues and coverage stay counts. Scan-health faults are not attack topology, and
//     mixing them into the node list is how a report starts describing the scanner instead
//     of the target.
//
// # Which host a web surface hangs from
//
// A web surface joins the host named in its URL authority, and only that host. When the
// authority is a name, the surface hangs from the Domain node; when it is a literal
// address, it hangs from the IPAddress node. It is never joined to the address a name
// resolves to, because the endpoint events this graph is built from do not record which
// address answered the request: the probe recorded a URL, a status, and a response, and
// the address that served it is not in the event. Joining the surface to every address the
// name resolves to would assert something no observation established, and picking one of
// them would be a guess dressed as a fact. An analyst who needs that link reads it through
// the name: Domain -> resolves_to -> IPAddress, where each hop is separately evidenced.
//
// The one exception is an origin whose endpoints arrived with no facts edge at all. It is
// joined to its authority host at low confidence and unknown currentness, marked
// derived_from url_authority, so the derivation is visible rather than indistinguishable
// from an observed relationship.
//
// # Contraction never strengthens a claim
//
// Merging is always a maximum over grades that already existed. Fifty endpoints served by
// one name become one serves_web_surface edge whose confidence and currentness are the
// strongest any contributing edge carried, and a set of passive claims therefore contracts
// into a passive edge. No rule computes a class none of its inputs had. This is the single
// property that makes the contracted view safe to act on: an analyst reading
// live_verified here can rely on something in the facts graph having been live verified.
//
// The one derived edge is tls_assessed_for, and it is derived narrowly. It comes from a
// TLS assessment's own assessed-names metadata and nothing else. The names that happen to
// resolve to the assessed address are not what the scanner measured, and inferring the
// edge from them would attach a certificate verdict to names nobody tested; an assessment
// naming only the address, or nothing, produces no edge and stays a facet.
//
// # Integrity is part of the artifact
//
// [Build] always returns a graph and records its structural verdict in [Graph.Integrity]:
// unique typed node ids, both endpoints of every edge resolving, no duplicate edge
// identity after the merge, no isolated node outside the one documented allowance, every
// finding either attached or unmapped, every facts asset type covered by a rule, and no
// facts asset that had a relationship to fold through and landed nowhere. [Graph.Err]
// turns that verdict into the error a writer refuses to write on, because an artifact
// whose edges do not resolve renders as a picture that disagrees with its own data.
//
// The asset accounting closes as an identity: for every type, Count equals Contracted plus
// Standalone. Standalone counts the assets the facts graph itself joined to nothing, so
// the contraction had no relationship to fold them through - a certificate covering only
// wildcard names is the standing example, a wildcard being a zone directive rather than a
// name that can carry the coverage. Separating that from Contracted is what keeps a
// legitimately isolated asset from looking exactly like a lost one: both would otherwise
// read as a number smaller than Count. An asset the facts graph did join and the
// contraction still dropped breaks the identity and is reported as an uncontracted_asset.
//
// Only Domain nodes may stand alone, and the reason is stated where the allowance is: an
// enumeration source can report a name and never establish another thing about it. An
// address with nothing on it, a service on no address, or a web origin no host serves is
// an error in this package rather than a fact about the target.
//
// # The source-collection verdict rides along, and changes nothing
//
// [Build] takes an optional [SourceCollection]: the compact collection verdict for the
// collection the view was folded from (status, health total). It is
// attached to the finished graph and rendered before the totals, so a reader never
// sizes an estate from a scan that stopped short of looking. It is deliberately compact:
// the exact lost identities are listed once, in the operator report, and a second ledger
// here would be one more thing to disagree with.
//
// It is metadata about acquisition, so it touches nothing structural. Nodes, edges,
// facets, findings, the contraction summary, and the integrity verdict are identical
// whether or not it is present, and no severity or risk value depends on it.
package attacksurface
