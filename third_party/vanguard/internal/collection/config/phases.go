package config

import (
	"sort"
)

// Phase name constants, the canonical identifiers used in the ledger, the logs,
// and the prerequisite rules. They are the string form of the PhaseSet fields.
const (
	PhasePassive = "passive"
	PhaseActive  = "active"
)

// PhaseSet is the set of reconnaissance phases a configuration enables (or that a
// collection executed). It is a small value type, so the rules over two sets -
// whether one covers the other, what a collection cumulatively holds - are pure
// functions, testable without any I/O.
type PhaseSet struct {
	Passive bool
	Active  bool
}

// PhaseSet derives the enabled phases from the configuration, reading the phase
// toggles.
// A nil toggle reads as disabled, so it is safe before Validate, but it is meant
// to be called after Validate has confirmed the required toggles are present.
func (c *ScanProfile) PhaseSet() PhaseSet {
	return PhaseSet{
		Passive: c.Phases.Passive.Enabled != nil && *c.Phases.Passive.Enabled,
		Active:  c.Phases.Active.Enabled != nil && *c.Phases.Active.Enabled,
	}
}

// PhaseSetFromNames rebuilds a PhaseSet from its phase names, the inverse of
// Names. Unknown names are ignored, so it round-trips the ledger's stored set.
func PhaseSetFromNames(names []string) PhaseSet {
	var p PhaseSet
	for _, n := range names {
		switch n {
		case PhasePassive:
			p.Passive = true
		case PhaseActive:
			p.Active = true
		}
	}
	return p
}

// Names returns the enabled phase names in a stable, sorted order, for the ledger
// and the logs.
func (p PhaseSet) Names() []string {
	var names []string
	if p.Passive {
		names = append(names, PhasePassive)
	}
	if p.Active {
		names = append(names, PhaseActive)
	}
	sort.Strings(names)
	return names
}
