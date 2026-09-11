package crawler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/crtsh"
)

// EventCategory classifies crawler system events into high-level groups.
type EventCategory string

const (
	// CategoryLifecycle marks a state transition or milestone.
	CategoryLifecycle EventCategory = "Lifecycle"
	// CategoryError marks a non-fatal error (a single domain/search is skipped).
	CategoryError EventCategory = "Error"
	// CategorySuccess marks a successful operation or a positive finding.
	CategorySuccess EventCategory = "Success"
	// CategoryFailure marks a terminal, unrecoverable event.
	CategoryFailure EventCategory = "Failure"
)

// SystemEvent is the sealed interface implemented by every crawler system event.
type SystemEvent interface {
	Category() EventCategory
	At() time.Time
	String() string
	ID() string
	isSystemEvent()
}

// EventSink receives the crawler's system events. It must be safe for concurrent
// use; events are emitted from both the actor loop and search goroutines.
type EventSink interface {
	AppendSystem(ctx context.Context, evt SystemEvent) error
}

func computeID(t time.Time, payload any) string {
	data, err := json.Marshal(payload)
	if err != nil {
		data = []byte(fmt.Sprintf("%#v", payload))
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%d_%x", t.UnixNano(), hash)
}

// IsError reports whether evt is a non-fatal error (CategoryError).
func IsError(evt SystemEvent) bool { return evt.Category() == CategoryError }

// IsFailure reports whether evt is a terminal failure (CategoryFailure).
func IsFailure(evt SystemEvent) bool { return evt.Category() == CategoryFailure }

// CrawlStarted marks the beginning of the crawl for a root domain.
type CrawlStarted struct {
	RootDomain string
	MaxDepth   int
	Timestamp  time.Time
}

// Category returns CategoryLifecycle.
func (CrawlStarted) Category() EventCategory { return CategoryLifecycle }

// At returns the timestamp of the event.
func (e CrawlStarted) At() time.Time { return e.Timestamp }

// String returns a human-readable description.
func (e CrawlStarted) String() string {
	return fmt.Sprintf("crawl started for %s (max depth: %d)", e.RootDomain, e.MaxDepth)
}

// ID returns a unique hash identifying the event.
func (e CrawlStarted) ID() string { return computeID(e.Timestamp, e) }

func (CrawlStarted) isSystemEvent() {}

// DomainNameFound indicates a domain name was discovered.
type DomainNameFound struct {
	Domain       string
	ParentDomain string
	Depth        int
	// RetrievalSource is where the certificate that carried this name came from:
	// "service" for a crt.sh answer, "cache_embedded" for the fixture compiled into
	// the crtsh package. It is empty for the root, which is scan input rather than a
	// retrieved observation. Translation copies it onto the domain event.
	RetrievalSource string
	Timestamp       time.Time
}

// Category returns CategorySuccess.
func (DomainNameFound) Category() EventCategory { return CategorySuccess }

// At returns the timestamp of the event.
func (e DomainNameFound) At() time.Time { return e.Timestamp }

// String returns a human-readable description.
func (e DomainNameFound) String() string { return "domain found: " + e.Domain }

// ID returns a unique hash identifying the event.
func (e DomainNameFound) ID() string { return computeID(e.Timestamp, e.Domain) }

func (DomainNameFound) isSystemEvent() {}

// DomainProcessingStarted marks the start of processing a specific domain.
type DomainProcessingStarted struct {
	Domain    string
	Depth     int
	Timestamp time.Time
}

// Category returns CategoryLifecycle.
func (DomainProcessingStarted) Category() EventCategory { return CategoryLifecycle }

// At returns the timestamp of the event.
func (e DomainProcessingStarted) At() time.Time { return e.Timestamp }

// String returns a human-readable description.
func (e DomainProcessingStarted) String() string {
	return fmt.Sprintf("processing %s (depth %d)", e.Domain, e.Depth)
}

// ID returns a unique hash identifying the event.
func (e DomainProcessingStarted) ID() string { return computeID(e.Timestamp, e) }

func (DomainProcessingStarted) isSystemEvent() {}

// DomainProcessingFailed indicates a domain's searches failed completely.
type DomainProcessingFailed struct {
	Domain    string
	Err       string
	Timestamp time.Time
}

// Category returns CategoryError.
func (DomainProcessingFailed) Category() EventCategory { return CategoryError }

// At returns the timestamp of the event.
func (e DomainProcessingFailed) At() time.Time { return e.Timestamp }

// String returns a human-readable description.
func (e DomainProcessingFailed) String() string {
	return fmt.Sprintf("domain %s failed: %s", e.Domain, e.Err)
}

// ID returns a unique hash identifying the event.
func (e DomainProcessingFailed) ID() string { return computeID(e.Timestamp, e) }

func (DomainProcessingFailed) isSystemEvent() {}

// DomainProcessingSucceeded indicates a domain's searches completed.
type DomainProcessingSucceeded struct {
	Domain    string
	Certs     int
	Timestamp time.Time
}

// Category returns CategorySuccess.
func (DomainProcessingSucceeded) Category() EventCategory { return CategorySuccess }

// At returns the timestamp of the event.
func (e DomainProcessingSucceeded) At() time.Time { return e.Timestamp }

// String returns a human-readable description.
func (e DomainProcessingSucceeded) String() string {
	return fmt.Sprintf("processed %s - found %d certificate(s)", e.Domain, e.Certs)
}

// ID returns a unique hash identifying the event.
func (e DomainProcessingSucceeded) ID() string { return computeID(e.Timestamp, e) }

func (DomainProcessingSucceeded) isSystemEvent() {}

// DomainSearchDegraded indicates a crt.sh search for the domain returned zero
// certificates only after the backend emitted retryable failures during the same
// search, and a re-query after a cooldown was still empty. The empty result may be
// a degraded-backend artifact rather than an authoritative "no certificates";
// because crt.sh is the sole certificate source, a silently accepted degraded empty
// collapses subdomain discovery. The domain still processes normally - this event
// only flags the data-quality risk so the orchestrator raises an IssueObserved
// instead of recording a silent zero.
type DomainSearchDegraded struct {
	// Domain is the name whose search came back degraded-empty.
	Domain string
	// Query is the exact or "%.domain" wildcard query that returned the degraded
	// empty, so the issue names which of the two searches was affected.
	Query     string
	Timestamp time.Time
}

// Category returns CategoryError: a degraded empty is a non-fatal data-quality
// problem (one search may have lost data), so the orchestrator raises an
// IssueObserved for it without failing the crawl.
func (DomainSearchDegraded) Category() EventCategory { return CategoryError }

// At returns the timestamp of the event.
func (e DomainSearchDegraded) At() time.Time { return e.Timestamp }

// String returns a human-readable description.
func (e DomainSearchDegraded) String() string {
	return fmt.Sprintf(
		"crt.sh returned an empty result for %q (%s) only after the backend was degraded; "+
			"the empty may not be authoritative, so certificate/subdomain coverage may be incomplete",
		e.Query, e.Domain)
}

// ID returns a unique hash identifying the event.
func (e DomainSearchDegraded) ID() string { return computeID(e.Timestamp, e) }

func (DomainSearchDegraded) isSystemEvent() {}

// DomainProcessingSkipped indicates a domain's crt.sh searches were skipped
// because a successful ancestor "%.domain" wildcard search already returned its
// certificates. crt.sh's % wildcard matches across dots, so the ancestor result is
// a superset of this name's exact and wildcard searches; re-querying would only
// repeat load against a flaky endpoint. The domain is still discovered
// (DomainNameFound) and fed to the rest of discovery, so no data is lost - only the
// duplicate certificate-transparency fetch is dropped.
type DomainProcessingSkipped struct {
	Domain    string
	Depth     int
	Timestamp time.Time
}

// Category returns CategoryLifecycle: a skip is a benign control decision, not an
// error or failure, so it raises no IssueObserved downstream.
func (DomainProcessingSkipped) Category() EventCategory { return CategoryLifecycle }

// At returns the timestamp of the event.
func (e DomainProcessingSkipped) At() time.Time { return e.Timestamp }

// String returns a human-readable description.
func (e DomainProcessingSkipped) String() string {
	return fmt.Sprintf("skipped %s (certificates already covered by an ancestor wildcard)", e.Domain)
}

// ID returns a unique hash identifying the event.
func (e DomainProcessingSkipped) ID() string { return computeID(e.Timestamp, e) }

func (DomainProcessingSkipped) isSystemEvent() {}

// CertificateFound indicates a crt.sh search returned a certificate.
type CertificateFound struct {
	SearchQuery string
	Certificate crtsh.Certificate
	// RetrievalSource is where the certificate came from: "service" for a crt.sh
	// answer, "cache_embedded" for the fixture compiled into the crtsh package.
	// Translation copies it onto the domain event.
	RetrievalSource string
	Timestamp       time.Time
}

// Category returns CategorySuccess.
func (CertificateFound) Category() EventCategory { return CategorySuccess }

// At returns the timestamp of the event.
func (e *CertificateFound) At() time.Time { return e.Timestamp }

// String returns a human-readable description.
func (e *CertificateFound) String() string {
	return "certificate found: " + e.Certificate.CommonName
}

// ID returns a unique hash identifying the event.
func (e *CertificateFound) ID() string { return computeID(e.Timestamp, e.Certificate.CommonName) }

func (e *CertificateFound) isSystemEvent() {}

// CrawlSucceeded marks the successful completion of the crawl.
type CrawlSucceeded struct {
	TotalDomainsProcessed int
	TotalCertsFound       int
	Timestamp             time.Time
}

// Category returns CategorySuccess.
func (CrawlSucceeded) Category() EventCategory { return CategorySuccess }

// At returns the timestamp of the event.
func (e CrawlSucceeded) At() time.Time { return e.Timestamp }

// String returns a human-readable description.
func (e CrawlSucceeded) String() string {
	return fmt.Sprintf("crawl complete: %d domain(s), %d certificate(s)", e.TotalDomainsProcessed, e.TotalCertsFound)
}

// ID returns a unique hash identifying the event.
func (e CrawlSucceeded) ID() string { return computeID(e.Timestamp, e) }

func (CrawlSucceeded) isSystemEvent() {}

// CrawlCanceled indicates the crawl was canceled (e.g. context canceled).
type CrawlCanceled struct {
	Err       string
	Timestamp time.Time
}

// Category returns CategoryFailure.
func (CrawlCanceled) Category() EventCategory { return CategoryFailure }

// At returns the timestamp of the event.
func (e CrawlCanceled) At() time.Time { return e.Timestamp }

// String returns a human-readable description.
func (e CrawlCanceled) String() string { return "crawl canceled: " + e.Err }

// ID returns a unique hash identifying the event.
func (e CrawlCanceled) ID() string { return computeID(e.Timestamp, e) }

func (CrawlCanceled) isSystemEvent() {}
