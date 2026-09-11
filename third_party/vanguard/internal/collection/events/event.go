package events

import (
	"context"
	"time"
)

// DomainEvent represents an event that is significant from a business domain perspective.
type DomainEvent interface {
	// At returns the time Vanguard captured the event.
	At() time.Time
	String() string
	Meta() EventMeta
	isDomainEvent() // unexported - seals interface to this package
}

// DomainEventSink receives domain events.
type DomainEventSink interface {
	AppendDomain(ctx context.Context, evt DomainEvent) error
}
