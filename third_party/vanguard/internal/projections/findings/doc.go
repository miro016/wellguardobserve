// Package findings is the home for everything about target weaknesses: the rules
// that derive them and the read model that rolls them up.
//
// # Rules
//
// A rule is a pure function from a single domain event to zero or more
// events.FindingRaised. Rules read only the event they are given and set the
// finding content plus its severity and category; they do not stamp scan
// correlation metadata (EventID, ScanID, CausationID), which the orchestrator
// applies when it publishes the finding. Each rule lives in its own file
// (expired_cert.go, wildcard_cert.go, ...) so the deterministic logic for one
// finding type - and the methods that will grow around it - stays in one place.
//
// Rules must use value-form type assertions (evt.(events.X), not
// evt.(*events.X)) because the orchestrator emits events as values. All
// DomainEvent implementations use value receivers, so the value form is the
// canonical form throughout the codebase.
//
// Rules are exported so the orchestration detector Registry can compose them
// (internal/collection/orchestration/detectors). Keeping the rules here, next to the read
// model that folds their output, keeps the whole notion of a "finding" in one
// package.
//
// # Read model
//
// Findings (findings.go) deduplicates raised findings by ID (hash of rule +
// asset) and rolls them up by severity, category, and affected asset. It is
// distinct from Projection.Issues, which holds scan errors (IssueObserved), not
// target weaknesses.
//
// Because the fold key is rule plus asset, a rule ID must be specific enough that
// two different weaknesses on one asset cannot share it. Where a scanner reports a
// family of named checks, the check's own name belongs in the rule ID rather than
// in the title alone: a family-wide ID keeps whichever member folds first and drops
// the others, which is silent loss of a real weakness rather than deduplication.
// The TLS vulnerability rule (tls_security.go) derives one ID per named check for
// exactly this reason. Sharing an ID deliberately is still correct where two rules
// prove the same weakness from different evidence, which is what weak-tls-version
// does across the HTTPS probe and the service assessment.
//
// # Believing a scanner
//
// A rule may report a scanner's conclusion only as far as the scanner's test
// supports it. Where a named check is known to be weaker than the vulnerability it
// names, the rule requires corroborating evidence from the assessment before it
// raises the finding, and drops the check only when that evidence positively
// refutes it (tlsVulnerabilityRefuted in tls_security.go).
//
// Refutation and silence are not the same. An assessment that was capped, or that
// never ran the section the refutation reads, cannot refute anything, and the
// finding stands for a human to judge. Suppressing on absent data would turn "not
// measured" into "measured and fine", which is the failure this codebase treats
// most seriously.
//
// # Temporal relevance
//
// Confidence and temporal relevance are two independent
// dimensions. An inferred finding can be recent, and a confirmed one can be old.
// Collapsing them makes a complete historical record read as a current risk
// statement.
//
// The fold accumulates the raw evidence times a rule supplied (temporal.go):
// EvidenceObservedFirst/Last bound when the sources actually observed the subject,
// LastCorroboratedAt records when Vanguard last recorded a supporting claim, and
// EvidenceKinds collects the acquisition methods. A merge only ever widens these, so
// a second contributing event adds evidence and never erases the first one's.
//
// Classify then derives TemporalStatus, TemporalReason, and CurrentCorroboration
// against one fixed cutoff. It is a finalize pass rather than part of Apply because
// the cutoff is only known once the whole stream has been folded - a session's last
// execution decides it - and classifying mid-fold would judge early findings against
// an incomplete cutoff. Nothing is removed: every finding stays in the ledger with
// its classification attached.
//
// A provider that supplied no observation time yields "unknown", never "current" and
// never "historical". Unknown is a real answer meaning the finding needs
// re-observation; treating it as either of the others would overstate or understate
// posture.
//
// # Certificate findings and CT logs
//
// Certificate rules must distinguish a certificate observed live (an active TLS
// handshake) from a historical Certificate Transparency log entry (crt.sh).
// They require EventMeta.ObservationKind active_probe and a non-zero
// CertificateData.LiveVerifiedAt. This is a deliberate, load-bearing invariant: the
// expired-cert, expiring-cert, long-lived-cert, and wildcard-cert rules all rely
// on it to avoid flagging the many rotated certs that naturally appear and expire
// in CT logs. expiring-cert is the pre-expiry sibling of expired-cert: it flags a
// still-valid live cert whose ValidUntil is within three weeks, so a renewal can
// happen before the outage.
// LoggedAt is retained independently as historical detail and is never used as a
// proxy for live verification.
//
// # Mail-security findings
//
// The mail-security rule (mail_security.go) raises spoofing-exposure findings
// (missing/unenforced DMARC, and SPF that is missing, over-limit, duplicated,
// pass-all, or neutral) from MailSecurityDiscovered.
// They are gated on any sign of mail intent (MX, SPF, DMARC, or DKIM present),
// not MX alone: the MX lookup can transiently fail, and suppressing a real
// finding on a lookup gap would hide data. A bare subdomain with none of these
// (e.g. www.*) is not flagged for inheriting the organizational policy.
//
// # SPF policy quality
//
// Three of those rules read the published policy rather than its absence.
// spf-pass-all (medium) fires when the record reaches a bare "all" or "+all", which
// authorizes every sender on the internet. spf-neutral-policy (low) fires on an
// explicit "?all" and on a record that lists senders but has no "all" and no
// redirect, both of which end evaluation at Neutral: SPF then makes no authorization
// statement at all about an unlisted sender. spf-multiple-records (medium) fires on
// SPFAnalysis.Multiple, because receivers must treat a domain publishing two SPF
// records as a permanent error.
//
// The terminal policy is read by a small local classifier (spf_policy.go) from the
// raw record the event carries. It is deliberately not an SPF evaluator: it resolves
// no sender IP, follows no include, and performs no DNS. It reads terms left to
// right and stops at the first exact "all", because "all" always matches and nothing
// after it is reachable. Matching is on exact tokens with at most one qualifier
// stripped, so "include:all.example" and "all.example" are not the "all" mechanism
// and "+-all" is malformed rather than a policy. A record carrying any term the
// classifier does not recognize is reported unknown and raises nothing: calling an
// invalid record neutral would raise a finding about a policy nobody published.
//
// Multiple records take precedence over every other SPF policy judgement. Only one of
// the published records is stored, and it is not the domain effective policy - there
// is none - so describing its terminal qualifier would describe something that is not
// in force. On a single valid record the lookup limit and the terminal policy are
// independent weaknesses and both are raised: a record can be both unresolvable and
// permissive, and reporting one would leave the other unfixed.
//
// Three conditions are deliberately left unreported. "~all" is a real posture
// question but its operational severity depends on DMARC enforcement, which this rule
// does not read, so it stays posture detail rather than becoming a finding whose
// severity nobody can defend. A redirect delegates the terminal decision to another
// domain this rule does not resolve, so the root record alone says nothing. And no
// conclusion is drawn from void counts, include errors, recursion limits, or DNS
// failures: the current accounting cannot separate a target-owned void from an
// operational resolver failure well enough to accuse a domain of either.
//
// The active mx-no-starttls rule (mx_no_starttls.go) gates the other way: it
// flags an MX host only when STARTTLS was actually observed absent on a
// successful probe (empty MxTlsHost.Error). A host whose probe errored (port 25
// blocked from the scanner, dial timeout) has unknown STARTTLS support, so
// flagging it would be a false positive.
//
// # Web-exposure findings
//
// The version-disclosure rule (version_disclosure.go) raises an info finding from
// a TechnologyFingerprinted event only when a concrete Version was detected: a
// bare technology name (no version) is a stack hint, not a disclosure, so flagging
// it would be noise.
//
// It also skips technologies the fingerprint database classifies as client-side
// (clientSideTechCategories: JavaScript libraries, SEO, WordPress plugins, WordPress
// themes). A site built on those publishes their versions in the asset URLs every
// visitor fetches, so there is no banner for an operator to suppress, and the volume
// buries the server-side disclosure on the same endpoint. Suppression keys on the
// event's Categories rather than a product-name blocklist, because the category comes
// from the fingerprint database and keeps working as that database grows. Any
// client-side category suppresses, even beside a server-sounding one (Elementor is
// "Page builders" and "WordPress plugins"); a producer that reports no categories is
// never suppressed, so header-derived server banners are unaffected.
//
// The HTTP findings (version-disclosure, missing-security-headers, and
// plaintext-http) are Endpoint findings: they key on the
// canonical Endpoint id of the URL the probe fetched (endpointAssetID:
// entities.EndpointID), which is exactly the key the facts projection materializes as
// an Endpoint asset.
//
// They deliberately do not key on a service. A service is a socket, identified by the
// address it was observed on, and an HTTP response never proves which address served a
// hostname URL; deriving "host/port/tcp" from the URL produced a hostname-shaped service
// key that named an asset no normalizer can create, so those findings pointed at nothing.
// Keying on the URL also keeps path and explicit-port identity, so a disclosure on /admin/
// and one on / stay distinct. A URL that cannot be normalized raises no finding at all:
// the same normalizer quarantines the event, so a fallback id would be an unowned key.
//
// The probe URL is still retained as the finding's Location for a validator to target.
// Findings collapse by rule+asset, so several versioned components on one endpoint yield
// one finding with the extra events accumulating as Locations and provenance.
//
// # Certificate findings
//
// The certificate rules (expired-cert, expiring-cert, long-lived-cert, wildcard-cert) key
// on the canonical certificate asset id (certificateAssetID: entities.CertificateID),
// never the raw serial the producer reported. Producers spell a serial differently (case,
// ":" separators, a leading DER sign-padding byte), and the asset key pairs the canonical
// serial with the leaf common name so a CT record and a live handshake for one leaf
// converge without colliding across issuers. A consumer that needs the serial alone
// extracts it with entities.CertSerialFromID rather than re-parsing the key by hand.
//
// A service-kind finding that has a platform identity also carries a structured
// ServiceFacet (port/proto, product, version, CPEs): version-disclosure fills it from
// the fingerprinted technology (serviceFacet, port/proto from the probe URL, no CPE),
// risky-open-port fills it from the nmap ServiceDiscovered (product, version, CPEs),
// and default-credentials preserves the same service identity so a scenario can pair
// the candidate with its exposure without parsing prose.
// Consumers match on that facet instead of parsing Evidence prose - the IIS scenario
// reads the product/CPE, not a "Microsoft-IIS" substring. Merges fill empty facet
// fields and union CPEs, so a later event contributes the identity the first lacked.
//
// # Provider-reported risky ports (inferred, upgradeable)
//
// RiskyProviderPortShodan/Netlas/Censys (risky_provider_port.go) raise the
// same "risky-open-port" finding as the active RiskyOpenPort rule
// (risky_open_port.go), but from a passive host-intel provider's reported port
// instead of the active port scan - so a sensitive port (RDP/SQL/Redis/...) a
// provider-only host exposes is no longer invisible to the risk model just
// because the provider-host policy has not approved active probing for that host
// (orchestration.Config.ProviderHostProbePolicy). They share sensitivePorts, Rule, and
// AssetKind/AssetID ("service", "ip:port") with RiskyOpenPort, so
// entities.FindingID collapses a provider report and an active confirmation of the
// same ip:port into one Finding: Findings.Apply's Stronger merge upgrades it to
// Confidence confirmed in either arrival order, and a provider-only sighting that
// is never actively confirmed stays inferred, down-weighted by
// risk.effectiveWeight so it cannot outrank a confirmed finding of equal
// severity. The asset identity these rules assert is a TCP service, so they fire only
// on a transport the provider actually named as tcp. A service observed on udp is
// skipped rather than renamed, and so is one whose transport the provider left
// unknown: neither is evidence of the TCP exposure the finding claims. RiskyOpenPort
// applies the same gate to the active scan, which leaves sensitive UDP services to
// their own rule instead of lending them a TCP label. One caveat: Findings.Apply keeps the first event's Evidence text on a
// merge, so whichever of the provider or active event arrives first sets the
// displayed evidence string; the finding's Confidence and Provenance are still
// correct either way.
//
// # UDP exposure findings
//
// UDPManagementPlaneExposure, UDPReflectorSurface and UDPRemoteAccessSurface
// (udp_exposure.go) are the UDP half of the exposure rules. Each reads a
// ServiceDiscovered whose transport is udp, which the scanner raises only for a UDP
// port that answered - a probe sent and a reply received - so each rests on a
// confirmed response rather than on silence. A port nobody answered is
// open|filtered, never becomes a service, and therefore never reaches these rules.
//
// Their asset ids carry the udp transport, so a UDP finding never dedups into, or
// overwrites, the risky-open-port finding on the TCP service of the same number.
//
// The hard line these rules hold is between exposure and behaviour. A responding
// UDP/53 is an exposed DNS service, not an open resolver; a responding UDP/161 is an
// exposed SNMP agent, not a default community string; a responding UDP/123 carries
// no amplification factor. Discovery sent one probe and read one reply, and the
// wording of every finding stays inside that. Each behavioural claim needs its own
// bounded protocol validator and its own collected event, which the
// finding model owns - never a port number reinterpreted.
//
// # Service-level TLS and SSH rules
//
// The TLS rules read TlsSecurityAssessed, which is an assessment of one endpoint
// and server name on any port, and the SSH rules read SshPostureDiscovered. Each
// one states its evidence requirement in the same shape: it fires only when the
// section it reads was actually tested, because every field it looks at is a
// boolean or a list whose empty value is indistinguishable from "not asked".
// Reporting an unassessed chain as untrusted, or an unread algorithm list as a
// clean offer, would be a fabricated finding.
//
// The rules divide the weakness space so one underlying problem raises one finding:
// weak-tls-version owns protocol support, weak-tls-cipher owns the accepted suites,
// tls-certificate-chain-invalid owns chain trust and order, tls-missing-hardening
// owns the downgrade and renegotiation protections, and tls-known-vulnerability
// owns the named checks that are not restatements of the other three. A named check
// nobody mapped is still reported, at medium, rather than dropped: a scanner that
// gains a check must not go quiet.
//
// # Overlap with the HTTPS probe
//
// WeakTLSSecurityVersion deliberately shares the weak-tls-version rule ID with
// WeakTLSVersion, the rule over the HTTPS posture event. An assessment made under a
// server name is about that name, which is the same asset the HTTPS rule keys on,
// so a finding identity (rule + asset) computed from either is the same value and
// the Findings fold collapses them into one finding carrying both tools'
// provenance. That is the whole point: two independent tools proving one weakness
// is corroboration, and a tool-prefixed duplicate would report it as two problems.
// An assessment with no server name was made against the bare endpoint and keys on
// the service instead, where no domain-level rule can collide with it.
//
// An address is not a server name. A TLS scanner reports the target address in the
// server-name field for the connection it makes without SNI, so that value arrives
// looking exactly like a virtual host; keying on it would file findings against a
// domain asset that is not a domain and split one service's findings across two
// assets. Such an assessment keys on the service, like one with no name at all.
//
// TLSPostureChainUntrusted is the same arrangement for the chain rule: the HTTPS
// probe validates the chain the server served and raises tls-certificate-chain-invalid
// on the domain, where the service-level TLSChainUntrusted lands too. The probe runs
// against every in-scope name while the service-level scanner runs only where it was
// pointed, so this is the only chain finding a host that scanner never reached will
// get, and where both ran the two fold into one finding with two provenances.
//
// Nor does a measurement covering several names key on any of them. A scanner that
// probed several names and returned one result for them all has not said which name
// it kept, and the one it labels the result with can differ between runs of the same
// scan; keying on it would move findings between assets on an estate that never
// changed. The rules therefore key on the assessment's covered names: exactly one
// real name means the finding is about that name, and anything else - none, or
// several - means it is about the service.
//
// The same distinction decides whether chain trust is judged at all.
// tls-certificate-chain-invalid ignores an untrusted chain on a connection made
// without a server name, because a certificate issued for a domain never validates
// against an address: the rule would fire on every correctly configured server and
// stay silent about the misconfigured ones. Chain order does not depend on the name
// and is still judged. Two real scans produced 16 such findings, at high severity,
// every one of them an artefact of the scanner's own no-SNI connection, while the
// same services assessed under their real names reported a trusted chain.
package findings
