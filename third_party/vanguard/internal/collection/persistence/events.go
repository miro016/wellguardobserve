package persistence

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// maxLogLineBytes bounds a single event line. Zone transfers and certificate
// SAN lists can be large, so the default scanner buffer is raised well past it.
const maxLogLineBytes = 8 * 1024 * 1024

// LoadEvents reads the canonical event log of the collection at dir and returns
// every event in arrival order.
//
// It returns raw events rather than a folded read model on purpose: folding is the
// business of whichever phase is doing the reading. A projection folds them into its
// artifacts, a health check folds them into an assessment, and this package would
// have to import one of those to do either.
func LoadEvents(dir string) (result []events.DomainEvent, resultErr error) {
	f, err := os.Open(eventsLogPath(dir))
	if err != nil {
		return nil, fmt.Errorf("open canonical log: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close canonical log: %w", err))
		}
	}()
	return ReadEvents(f)
}

// ReadEvents decodes a canonical event stream, one envelope per line, in arrival
// order. It is the stream form of [LoadEvents], for a caller that already holds the
// bytes.
func ReadEvents(r io.Reader) ([]events.DomainEvent, error) {
	var out []events.DomainEvent
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLogLineBytes)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		evt, err := DecodeEvent(line)
		if err != nil {
			return nil, fmt.Errorf("decode event: %w", err)
		}
		out = append(out, evt)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read canonical log: %w", err)
	}
	return out, nil
}
