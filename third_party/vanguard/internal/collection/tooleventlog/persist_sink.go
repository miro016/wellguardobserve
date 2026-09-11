package tooleventlog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// PersistSink is an EventSink decorator that persists every tool event as a
// structured ToolEventEnvelope to a shared canonical log (tools/tooling.jsonl below the collection root) and
// then forwards the event to the wrapped sink, preserving the per-tool text log
// and any live consumer. The envelope and its correlation are added here, around
// the tools, so tool code stays pure.
//
// One PersistSink is built per tool, but all share the same encoder (one
// tools/tooling.jsonl for the whole collection, all tools interleaved in arrival order) and
// the same monotonic Seq, exactly like the domain-event canonical log.
type PersistSink struct {
	seq  *atomic.Int64
	w    io.Writer
	mu   *sync.Mutex // guards w and the remembered errors below
	next EventSink

	// encodeErr and writeErr are the first envelope-encode and canonical-write
	// failures this sink saw. They are remembered rather than returned, because
	// EventSink.Emit is called from tool actors that have no useful way to react and
	// must keep running to preserve the evidence they can still write. The execution
	// reads them at its close barrier, where a reported failure prevents a succeeded
	// capture.
	encodeErr error
	writeErr  error
}

// NewPersistSink returns a PersistSink that appends envelopes to w and forwards
// events to next. The seq and mu are shared across every per-tool sink for one
// scan so the canonical log stays single, ordered, and goroutine-safe. The
// ScanID, phase, and target are read from the per-call context (see WithScan /
// WithTarget). next may be nil (no per-tool text log or live consumer). A nil w
// discards the structured stream while still forwarding to next.
func NewPersistSink(seq *atomic.Int64, mu *sync.Mutex, w io.Writer, next EventSink) *PersistSink {
	return &PersistSink{
		seq:  seq,
		w:    w,
		mu:   mu,
		next: next,
	}
}

// Emit builds the envelope, writes it as one line to the canonical log, then
// forwards the raw event to the wrapped sink. A failed encode or write does not
// stop the actor - it keeps collecting, and the per-tool text log may still record
// what happened - but it is remembered and reported by [PersistSink.Err], so the
// execution that could not persist its tool stream is not called succeeded.
func (s *PersistSink) Emit(ctx context.Context, e Event) {
	if s == nil {
		return
	}
	at := time.Now()
	if s.w != nil {
		env := buildEnvelope(s.seq.Add(1), correlationFrom(ctx), at, e)
		b, err := EncodeEnvelope(&env)
		s.mu.Lock()
		switch {
		case err != nil:
			if s.encodeErr == nil {
				s.encodeErr = fmt.Errorf("encode %s tool event: %w", e.ToolName(), err)
			}
		default:
			if _, err := s.w.Write(append(b, '\n')); err != nil && s.writeErr == nil {
				s.writeErr = fmt.Errorf("write %s tool event: %w", e.ToolName(), err)
			}
		}
		s.mu.Unlock()
	}
	if s.next != nil {
		s.next.Emit(ctx, e)
	}
}

// Err reports the first envelope-encode and canonical-write failures this sink saw,
// joined with whatever the wrapped text sink remembered. Safe on a nil *PersistSink.
func (s *PersistSink) Err() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	encodeErr, writeErr := s.encodeErr, s.writeErr
	s.mu.Unlock()
	var nextErr error
	if next, ok := s.next.(interface{ Err() error }); ok {
		nextErr = next.Err()
	}
	return errors.Join(encodeErr, writeErr, nextErr)
}
