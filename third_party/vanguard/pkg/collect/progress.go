package collect

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/collection/health"
)

// progressSink renders the live domain event stream as concise operator text and
// accumulates the counts the closing summary reports. It is the whole of the
// package's human-readable output: every line a run produces goes through one of
// these, which is what lets an embedding application decide where progress lands -
// or that there is none.
//
// It is also an [io.Writer], so the notices the collection tooling prints
// (authorization banners) serialize with the event lines instead of racing them.
// Tool results arrive concurrently, so every write holds the same lock.
type progressSink struct {
	mu sync.Mutex
	// w is the caller's writer, or io.Discard when the caller supplied none. It is
	// never closed: it stays the caller's for the whole run and afterwards.
	w io.Writer
	// writeErr is the first write failure. It is kept because a caller's writer
	// failing is a fact the run has to report even if the collection itself finishes:
	// a progress stream that silently stopped would be mistaken for a quiet scan.
	writeErr     error
	domainEvents int
	domains      int
	certs        int
	ips          int
	services     int
	findings     int
	issues       int
}

// newProgress prepares the sink for one run. A nil writer makes the run silent,
// which is the default for an embedded library: nothing reaches a process stream
// that the caller did not ask for.
func newProgress(w io.Writer) *progressSink {
	if w == nil {
		w = io.Discard
	}
	return &progressSink{w: w}
}

// Write implements io.Writer so the collection tooling's operator notices share this
// sink's serialization and its error handling.
func (s *progressSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	n, err := s.w.Write(p)
	if err != nil {
		s.writeErr = fmt.Errorf("write collection progress: %w", err)
		return n, s.writeErr
	}
	return n, nil
}

// printf writes one operator line.
func (s *progressSink) printf(format string, args ...any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeLocked(format, args...)
}

// writeLocked writes one line and remembers the first failure. Once the writer has
// failed, nothing else is attempted: a writer that reported an error owes no further
// output, and the run reports the original failure rather than the last one.
func (s *progressSink) writeLocked(format string, args ...any) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	if _, err := fmt.Fprintf(s.w, format, args...); err != nil {
		s.writeErr = fmt.Errorf("write collection progress: %w", err)
		return s.writeErr
	}
	return nil
}

// err reports the first write failure, if any, so the run returns it rather than
// leaving the caller to notice that its writer went quiet.
func (s *progressSink) err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeErr
}

// AppendDomain implements events.DomainEventSink. It is attached behind the capture
// sink, so an event is durable before it is ever described here, and a failing
// progress writer is reported rather than swallowed.
func (s *progressSink) AppendDomain(_ context.Context, evt events.DomainEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.domainEvents++

	// Switch on the value form the orchestrator emits live; normalize first so a
	// pointer-form event is counted too (see events.AsValue).
	switch e := events.AsValue(evt).(type) {
	case events.ScanStarted:
		return s.writeLocked("[scan]    started: %s\n", e.RootTarget)
	case events.ScanCompleted:
		return s.writeLocked("[scan]    completed in %s\n", e.Duration)
	case events.DnsDomainNameDiscovered:
		s.domains++
		return s.writeLocked("[domain]  %s\n", e.Domain)
	case events.CertificateDiscovered:
		s.certs++
	case events.IPAddressDiscovered:
		s.ips++
	case events.ServiceDiscovered:
		s.services++
		return s.writeLocked("[service] %s:%d (%s)\n", e.IP, e.Port, e.Service)
	case events.FindingRaised:
		s.findings++
		return s.writeLocked("[finding] %s %s on %s %s\n", e.Meta().Severity, e.Rule, e.AssetKind, e.AssetID)
	case events.IssueObserved:
		s.issues++
	}
	return nil
}

// healthProblem reports one collection problem the moment a tool reports it, so a
// degraded run is visible while it is still running rather than only in its closing
// error. It is the live half of the health monitor's contract and is called once per
// distinct problem identity; repeats are counted, not printed.
//
// It shares the sink's lock and its remembered write error with every other line, so
// a tool worker's problem cannot interleave with a domain event and a broken writer
// is still reported to the caller. The tool actor calling it is blocked for exactly
// one formatted write.
func (s *progressSink) healthProblem(p health.Problem) {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := fmt.Sprintf("[degraded] %s tool=%s", p.Code, p.Tool)
	if p.Component != "" {
		line += " component=" + p.Component
	}
	if p.Target != "" {
		line += " target=" + p.Target
	}
	if p.SafeDetail != "" {
		line += " detail=" + p.SafeDetail
	}
	_ = s.writeLocked("%s\n", line)
}

// summary writes the accumulated counts at the end of a run, followed by the
// collection-health verdict when the run lost work. The verdict is counts only: the
// per-identity rows belong in the returned error and the capture manifest, where a
// program can read them.
func (s *progressSink) summary(assessment health.Assessment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := fmt.Sprintf("\nsummary: %d domain events | %d domains | %d certs | %d IPs | %d services | %d findings | %d issues",
		s.domainEvents, s.domains, s.certs, s.ips, s.services, s.findings, s.issues)
	if assessment.Degraded() {
		line += fmt.Sprintf(" | %d collection problems across %d identities",
			assessment.Total, len(assessment.Problems))
	}
	return s.writeLocked("%s\n", line)
}
