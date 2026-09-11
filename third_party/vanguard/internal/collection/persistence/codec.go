package persistence

import (
	"encoding/json"
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// envelope is the versioned, self-describing wrapper written for every event in
// the canonical log. The type tag drives decoding; the version lets readers
// migrate older logs. Keeping the payload as RawMessage defers decoding to the
// event registry, so the codec stays agnostic to concrete event types and new
// event types need no change here.
type envelope struct {
	Version int             `json:"version"`
	Type    string          `json:"type"`
	Data    json.RawMessage `json:"data"`
}

// EncodeEvent wraps a domain event in the versioned envelope, tagging it with its
// type so it can be decoded later. The result is a single JSON object, intended
// to be written as one line of the canonical events.jsonl log.
func EncodeEvent(evt events.DomainEvent) ([]byte, error) {
	data, err := json.Marshal(evt)
	if err != nil {
		return nil, fmt.Errorf("marshal event payload: %w", err)
	}
	return json.Marshal(envelope{
		Version: events.SchemaVersion,
		Type:    events.TypeName(evt),
		Data:    data,
	})
}

// DecodeEvent reverses EncodeEvent: it reads the envelope and dispatches to the
// event registry on the type tag, returning the concrete event in its canonical
// form. An unknown type tag is an error, flagging an event that was persisted but
// never registered.
func DecodeEvent(line []byte) (events.DomainEvent, error) {
	var env envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return nil, fmt.Errorf("unmarshal event envelope: %w", err)
	}
	return events.DecodeByType(env.Type, env.Data)
}
