package persistence

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// collectionReadme documents the collection directory's layout and how to project
// it. It is static (no scan-specific data), so it is written eagerly when the
// directory is opened, in the version this build describes.
//
//go:embed collection_readme.md
var collectionReadme string

// PrepareFresh makes dir usable as the root of a new collection and returns the
// cleaned path the collection writes to. It is the first filesystem decision a
// fresh collection makes, taken before any target or provider is contacted, so a
// destination that cannot be used costs nothing.
//
// A missing destination is created; an existing one must be a real, empty
// directory. Nothing is deleted, renamed, or merged, so a rejected destination is
// left exactly as it was found.
func PrepareFresh(dir string) (string, error) {
	return prepareFresh(dir)
}

// OpenCollection validates that dir holds a collection this build can read - its
// manifest, its canonical event log, and the two configuration snapshots the
// manifest records - and returns the cleaned path together with the manifest.
//
// It is read-only in the strongest sense: it writes nothing, locks nothing, and
// confers no right to add to what it opened. A collection is finished evidence, so
// opening one is something any number of readers may do at once and nothing at all
// may follow with a write.
func OpenCollection(dir string) (string, *Manifest, error) {
	return openCollection(dir)
}

// Sink is the collection-time domain-event writer, and nothing else. It appends
// every event to the canonical, ordered, versioned events/events.jsonl and mirrors
// it into the per-type events/events_<Type>.jsonl splits.
//
// It folds nothing and renders nothing. A collection captures source material;
// deciding what that material means belongs to whatever reads it back, and keeping
// the two apart is what makes a collection directory replayable into the same
// artifacts as many times as an analyst likes. The orchestrator still keeps its own
// in-memory state for live scheduling - that is a collection decision - but none of
// it reaches disk from here.
type Sink struct {
	nextDomainSink events.DomainEventSink

	dir            string
	mu             sync.Mutex
	domainFiles    map[string]*os.File
	domainEncoders map[string]*json.Encoder

	// canonical is the combined, ordered, versioned event log (events.jsonl).
	// It is the source of truth for replay; the per-type files are kept only as
	// a human-friendly convenience.
	canonical *os.File

	// The first failure of each kind, remembered under mu and reported by Close.
	// Writing is not best-effort at the closing boundary: an event the collection
	// could not record is missing evidence, and a manifest that called the collection
	// succeeded would invite exactly the mistake this stream exists to prevent. They
	// are remembered rather than returned per call so the run keeps writing whatever
	// it still can - a broken split does not cost the canonical log its copy.
	typeOpenErr        error
	typeEncodeErr      error
	canonicalEncodeErr error
	canonicalWriteErr  error
}

// firstErr keeps the first error of one kind. Later failures of the same kind are
// almost always the same cause repeating, and the first one is the one that
// explains what happened.
func firstErr(kept, err error) error {
	if kept != nil {
		return kept
	}
	return err
}

// NewSink creates the collection's event sink. It creates the event directory and
// the generated README below dir and opens the canonical log.
//
// dir must already have been accepted by [PrepareFresh]: this constructor prepares
// no destination and deletes nothing, so the emptiness decision stays in one place
// and is taken before anything else runs.
//
// It creates only the directory it writes into. The config snapshots, the tool logs,
// and the packet captures are each created by whatever writes them, so an empty
// bucket in a finished collection means that writer ran and produced nothing rather
// than that the layout was laid out in advance.
func NewSink(dir string, nextDomain events.DomainEventSink) (*Sink, error) {
	dir, err := cleanDestination(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(eventsDirPath(dir), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create event directory %s: %w", eventsDirPath(dir), err)
	}
	if err := writeReadme(dir); err != nil {
		return nil, err
	}
	canonical, err := os.OpenFile(eventsLogPath(dir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open canonical log %s: %w", eventsLogPath(dir), err)
	}
	return &Sink{
		nextDomainSink: nextDomain,
		dir:            dir,
		domainFiles:    make(map[string]*os.File),
		domainEncoders: make(map[string]*json.Encoder),
		canonical:      canonical,
	}, nil
}

// writeReadme describes the collection, and how to project it, for whoever opens
// this directory later. The content is always the embedded copy of the running build
// rather than whatever file happened to be there. A collection that cannot explain
// itself is an incomplete collection, so a failed write fails the sink construction.
func writeReadme(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create collection directory %s: %w", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, readmeName), []byte(collectionReadme), 0o644); err != nil {
		return fmt.Errorf("failed to write README in %s: %w", dir, err)
	}
	return nil
}

// AppendDomain implements events.DomainEventSink. It writes the event to its
// per-type split and to the canonical log, then hands it to the next sink (the
// front-end's progress reporter) unchanged.
func (s *Sink) AppendDomain(ctx context.Context, event events.DomainEvent) error {
	s.mu.Lock()

	// Get event type name
	t := reflect.TypeOf(event)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	name := t.Name()

	enc, ok := s.domainEncoders[name]
	if !ok {
		f, err := os.OpenFile(eventsTypePath(s.dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			s.typeOpenErr = firstErr(s.typeOpenErr, fmt.Errorf("open %s split: %w", name, err))
		} else {
			s.domainFiles[name] = f
			enc = json.NewEncoder(f)
			s.domainEncoders[name] = enc
		}
	}
	if enc != nil {
		if err := enc.Encode(event); err != nil {
			s.typeEncodeErr = firstErr(s.typeEncodeErr, fmt.Errorf("write %s split: %w", name, err))
		}
	}

	// Append to the canonical, ordered, versioned log used for replay. It is
	// attempted whatever the split did: the canonical log is what a replay reads, so
	// it is the copy worth having when only one of the two can be written.
	if s.canonical != nil {
		b, encErr := EncodeEvent(event)
		if encErr != nil {
			s.canonicalEncodeErr = firstErr(s.canonicalEncodeErr,
				fmt.Errorf("encode %s for %s: %w", name, eventsLog, encErr))
		} else if _, err := s.canonical.Write(append(b, '\n')); err != nil {
			s.canonicalWriteErr = firstErr(s.canonicalWriteErr, fmt.Errorf("write %s: %w", eventsLog, err))
		}
	}

	s.mu.Unlock()

	if s.nextDomainSink != nil {
		return s.nextDomainSink.AppendDomain(ctx, event)
	}
	return nil
}

// Close flushes and closes the canonical log and every per-type split, and reports
// every failure this sink remembered while the collection was running. After it
// returns without error, the collected event material is durable and the manifest
// may be moved to a terminal status; after it returns an error, the collection did
// not record everything it observed and must not be called succeeded.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	errs := []error{s.typeOpenErr, s.typeEncodeErr, s.canonicalEncodeErr, s.canonicalWriteErr}
	errs = slices.DeleteFunc(errs, func(err error) bool { return err == nil })

	for name, f := range s.domainFiles {
		if err := f.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close %s.jsonl: %w", name, err))
		}
	}

	if s.canonical != nil {
		if err := s.canonical.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close %s: %w", eventsLog, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("persistence errors: %w", errors.Join(errs...))
	}
	return nil
}
