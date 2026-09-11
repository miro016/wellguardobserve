package tooleventlog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// Sink implements EventSink. It writes every event as a text log line to an
// io.Writer and optionally calls a notify function for live consumers.
type Sink struct {
	logger *slog.Logger
	notify func(time.Time, Event)

	// mu guards handleErr only; the slog handler does its own locking.
	mu sync.Mutex
	// handleErr is the first text-log write failure. A tool actor cannot do anything
	// useful with it mid-scan, so it is remembered here and reported at the
	// execution's close barrier instead.
	handleErr error
}

// NewSink returns a Sink that logs events as text to w and calls notify for
// each event. Both w and notify may be nil (events are silently dropped).
func NewSink(w io.Writer, notify func(time.Time, Event)) *Sink {
	if w == nil {
		w = io.Discard
	}
	return &Sink{
		logger: slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})),
		notify: notify,
	}
}

// Emit logs e to the backing writer and calls notify if set.
// Safe to call on a nil *Sink.
func (s *Sink) Emit(ctx context.Context, e Event) {
	if s == nil {
		return
	}
	at := time.Now()
	record := slog.NewRecord(at, e.EventLevel(), e.EventName(), 0)
	record.AddAttrs(e.EventAttrs()...)
	if err := s.logger.Handler().Handle(ctx, record); err != nil {
		s.mu.Lock()
		if s.handleErr == nil {
			s.handleErr = fmt.Errorf("write %s tool log: %w", e.ToolName(), err)
		}
		s.mu.Unlock()
	}
	if s.notify != nil {
		s.notify(at, e)
	}
}

// Err reports the first text-log write failure this sink saw. Safe on a nil *Sink.
func (s *Sink) Err() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handleErr
}
