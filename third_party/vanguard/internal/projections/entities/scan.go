package entities

import (
	"fmt"
	"time"
)

// Scan is the aggregate root for a single reconnaissance run. It owns the
// scan identity and the root target, and tracks phase timing.
type Scan struct {
	// ID is the stable scan correlation ID (matches EventMeta.ScanID).
	ID string
	// RootTarget is the domain the scan was launched against.
	RootTarget string
	// StartedAt is when the scan began.
	StartedAt time.Time
	// CompletedAt is when the scan finished; zero while running.
	CompletedAt time.Time
}

// NewScan constructs a Scan, enforcing that ID and RootTarget are non-empty.
func NewScan(id, rootTarget string, startedAt time.Time) (Scan, error) {
	if id == "" {
		return Scan{}, fmt.Errorf("scan ID must not be empty")
	}
	if rootTarget == "" {
		return Scan{}, fmt.Errorf("root target must not be empty")
	}
	return Scan{
		ID:         id,
		RootTarget: rootTarget,
		StartedAt:  startedAt,
	}, nil
}
