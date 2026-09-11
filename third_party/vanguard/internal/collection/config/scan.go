package config

import (
	"fmt"
	"strings"
)

// Scan pairs the two disjoint audit inputs of a run: the customer [EngagementConfig]
// (who and where) and the reusable [ScanProfile] (how). They are composed, never
// merged: no field exists in both and neither overrides the other. [LoadScan] loads
// each file independently, validates it in isolation, then enforces the cross-file
// constraints that only make sense once both are present.
type Scan struct {
	Engagement EngagementConfig
	Profile    ScanProfile
}

// LoadScan loads and validates an engagement file and a scan-profile file, then
// checks the constraints that span both. Each file is decoded strictly (unknown
// fields rejected) and validated on its own first, so a single-file mistake is
// reported against that file before any cross-file rule runs.
func LoadScan(engagementPath, profilePath string) (Scan, error) {
	eng, err := LoadEngagement(engagementPath)
	if err != nil {
		return Scan{}, err
	}
	profile, err := Load(profilePath)
	if err != nil {
		return Scan{}, err
	}
	return composeScan(eng, profile, engagementPath, profilePath)
}

// The names a byte-oriented caller's two documents are reported under. A caller
// that never had a file still needs its errors to say which of the two documents is
// wrong, and these are the words the engagement and the profile are called
// everywhere else.
const (
	engagementSource = "engagement"
	profileSource    = "scan profile"
)

// ParseScan validates an engagement and a scan profile held as bytes and checks the
// constraints that span both, exactly as [LoadScan] does for the same two documents
// held as files. It is what an embedding application composes a scan with: the
// documents may come from anywhere, and nothing has to be written to a temporary
// file to be validated.
func ParseScan(engagementYAML, profileYAML []byte) (Scan, error) {
	eng, err := ParseEngagement(engagementYAML, engagementSource)
	if err != nil {
		return Scan{}, err
	}
	profile, err := ParseProfile(profileYAML, profileSource)
	if err != nil {
		return Scan{}, err
	}
	return composeScan(eng, profile, engagementSource, profileSource)
}

// composeScan pairs two already validated documents and enforces the cross-file
// rules, naming both sources in the message so the operator knows which pair was
// rejected.
func composeScan(eng EngagementConfig, profile ScanProfile, engagementName, profileName string) (Scan, error) {
	s := Scan{Engagement: eng, Profile: profile}
	if err := s.validateComposition(); err != nil {
		return Scan{}, fmt.Errorf("invalid scan configuration (%s + %s):\n%w", engagementName, profileName, err)
	}
	return s, nil
}

// validateComposition enforces the rules that need both files. It keeps the same
// fail-closed, report-everything discipline as the per-file validators.
func (s *Scan) validateComposition() error {
	var problems []string
	req := func(cond bool, msg string) {
		if !cond {
			problems = append(problems, msg)
		}
	}

	// GoScans reuses host reservations the scheduler already granted, so its bounded
	// target cap must not exceed the engagement's bounded active-host limit.
	g := &s.Profile.Tools.GoScans
	if s.Profile.GoScansEnabled() && g.MaxTargets != nil &&
		s.Engagement.Limits.MaxActiveHosts != nil && *s.Engagement.Limits.MaxActiveHosts > 0 {
		req(*g.MaxTargets <= *s.Engagement.Limits.MaxActiveHosts,
			fmt.Sprintf("tools.goscans.max_targets (%d) must not exceed limits.max_active_hosts (%d)",
				*g.MaxTargets, *s.Engagement.Limits.MaxActiveHosts))
	}

	if len(problems) > 0 {
		return fmt.Errorf("  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}
