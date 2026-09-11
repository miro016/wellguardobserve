// Package crawler walks a root DNS domain and its subdomains using crt.sh
// certificate transparency searches.
//
// # Design
//
//   - CrawlerActor isolates mutable crawl state behind an inbox channel (actor
//     pattern). It drives one crtsh.SearchActor per query (exact + wildcard) and
//     recurses into newly discovered in-scope domains up to MaxDepth.
//   - Wildcard coverage avoids a per-subdomain retry storm. crt.sh's "%" wildcard
//     matches across dots (PostgreSQL ILIKE), so a successful "%.root" search
//     already returns the certificates for every subdomain at any depth. The
//     crawler records each domain whose wildcard search succeeded and skips the
//     exact+wildcard searches for any later queued name that is covered by such an
//     ancestor (its certificates are a subset already fetched). This collapses the
//     old "exact + wildcard per discovered label" fan-out to one pair of searches
//     per uncovered zone, dramatically cutting load against the flaky free endpoint
//     without dropping data: every name is still emitted via DomainNameFound, and
//     coverage is recorded only on wildcard success so a failed ancestor wildcard
//     falls back to querying descendants directly.
//   - Degraded empties are flagged, not trusted. crt.sh is the sole certificate
//     source, so an empty search result that the client marks degraded (zero certs
//     returned only after the backend flaked; see crtsh.SearchResult.DegradedEmpty)
//     emits a DomainSearchDegraded event. The domain still processes normally; the
//     event lets the orchestration layer raise a data-quality issue instead of
//     silently recording an authoritative zero that would collapse subdomain
//     discovery.
//   - Like the tool actors in internal/collection/tools, the crawler emits its own
//     package-local system events (crawler.SystemEvent) through an EventSink. It
//     does NOT import internal/collection/events and never produces domain events;
//     translating crawler system events into domain events is the responsibility
//     of the orchestration layer.
//   - Raw crt.sh search system events are forwarded to Config.OnSystemEvent for
//     observability. The configured EventSink must be safe for concurrent use
//     because events are emitted from both the actor loop and search goroutines.
//   - Retrieval provenance rides along with the data. Each search result reports
//     whether crt.sh answered it or the fixture compiled into the crtsh package did
//     (crtsh.SearchResult.RetrievalSource), and the crawler copies that value onto
//     every CertificateFound and DomainNameFound the result produced. It is a plain
//     string here because this package does not import internal/collection/events;
//     the orchestration translator copies it onto EventMeta.RetrievalSource. The root
//     DomainNameFound leaves it empty: the root is scan input, not a retrieved
//     observation.
package crawler
