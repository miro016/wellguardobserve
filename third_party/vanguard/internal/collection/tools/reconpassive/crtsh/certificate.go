package crtsh

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Certificate holds parsed certificate data from crt.sh.
type Certificate struct {
	// ID is the crt.sh internal certificate identifier.
	ID int64
	// IssuerCAID is the ID of the issuing certificate authority in crt.sh.
	IssuerCAID int64
	// CommonName is the certificate's CN field.
	CommonName string
	// IssuerName is the full DN of the issuing CA.
	IssuerName string
	// SerialNumber is the certificate serial number as a hex string.
	SerialNumber string
	// NotBefore is the start of the certificate's validity period.
	NotBefore time.Time
	// NotAfter is the end of the certificate's validity period.
	NotAfter time.Time
	// EntryTimestamp is when the certificate was logged to CT.
	EntryTimestamp time.Time
	// Domains lists all DNS names found in CN and SANs, deduplicated and lowercased.
	Domains []string
}

// rawCertificate maps the crt.sh JSON response row.
type rawCertificate struct {
	ID             int64  `json:"id"`
	IssuerCAID     int64  `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

func (r *rawCertificate) bytes() []byte {
	b, _ := json.Marshal(r)
	return b
}

func parseCert(raw *rawCertificate) (Certificate, error) {
	entry, err := parseTime(raw.EntryTimestamp)
	if err != nil {
		return Certificate{}, fmt.Errorf("invalid entry_timestamp: %w", err)
	}
	notBefore, err := parseTime(raw.NotBefore)
	if err != nil {
		return Certificate{}, fmt.Errorf("invalid not_before: %w", err)
	}
	notAfter, err := parseTime(raw.NotAfter)
	if err != nil {
		return Certificate{}, fmt.Errorf("invalid not_after: %w", err)
	}
	return Certificate{
		ID:             raw.ID,
		IssuerCAID:     raw.IssuerCAID,
		IssuerName:     raw.IssuerName,
		CommonName:     raw.CommonName,
		Domains:        extractDomains(raw),
		EntryTimestamp: entry,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		SerialNumber:   raw.SerialNumber,
	}, nil
}

func extractDomains(raw *rawCertificate) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, src := range []string{raw.CommonName, raw.NameValue} {
		for _, line := range strings.Split(src, "\n") {
			name := strings.TrimSpace(strings.ToLower(line))
			if name == "" {
				continue
			}
			name = strings.TrimPrefix(name, "*.")
			name = strings.TrimSuffix(name, ".")
			if strings.ContainsAny(name, " \t\r\n/\\") {
				continue
			}
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				out = append(out, name)
			}
		}
	}
	return out
}

var timeFormats = []string{
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, f := range timeFormats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unknown time format: %q", s)
}
