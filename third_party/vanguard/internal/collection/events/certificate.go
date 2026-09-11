package events

import (
	"fmt"
	"time"
)

var _ DomainEvent = CertificateDiscovered{}

// CertificateData represents certificate identity and its distinct temporal
// assertions. Zero timestamps mean the producing source did not provide that
// assertion; consumers must not substitute one temporal meaning for another.
type CertificateData struct {
	CommonName     string
	IssuerName     string
	SerialNumber   string
	ValidFrom      time.Time
	ValidUntil     time.Time
	LoggedAt       time.Time
	LiveVerifiedAt time.Time
	Domains        []string
}

// CertificateDiscovered signals that a certificate was found during crawler execution.
type CertificateDiscovered struct {
	EventMeta
	SearchQuery string
	Certificate CertificateData
}

// At returns the capture time recorded in the event envelope.
func (e CertificateDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e CertificateDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e CertificateDiscovered) String() string {
	expiry := ""
	if !e.Certificate.ValidUntil.IsZero() {
		expiry = ", expires " + e.Certificate.ValidUntil.Format("2006-01-02")
	}
	return fmt.Sprintf("certificate found (query %s): %s%s", e.SearchQuery, e.Certificate.CommonName, expiry)
}

func (CertificateDiscovered) isDomainEvent() {}
