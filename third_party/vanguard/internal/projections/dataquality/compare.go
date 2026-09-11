package dataquality

import (
	"sort"

	"github.com/velgard-sk/vanguard/internal/collection/events"
)

// ProviderCoverage is one provider's contribution to a single comparable field.
type ProviderCoverage struct {
	// Provider is the producing tool (events.EventMeta.Source).
	Provider string `json:"provider"`
	// Keys is how many target keys this provider reported a value for.
	Keys int `json:"keys"`
	// Values is the total distinct values this provider reported across all keys.
	Values int `json:"values"`
	// UniqueKeys is how many keys only this provider reported (sole contributor).
	UniqueKeys int `json:"uniqueKeys"`
	// UniqueValues is how many distinct (key, value) pairs only this provider gave.
	UniqueValues int `json:"uniqueValues"`
}

// Conflict is one key where two or more providers reported different value-sets.
type Conflict struct {
	// Key is the target (domain or IP) the providers disagree on.
	Key string `json:"key"`
	// Values maps each provider to the sorted values it reported for the key.
	Values map[string][]string `json:"values"`
}

// FieldReport is the comparison result for one comparable field.
type FieldReport struct {
	// Field is the field label.
	Field string `json:"field"`
	// Unit names what keys count (domains, IPs).
	Unit string `json:"unit"`
	// TotalKeys is the union of keys any provider reported.
	TotalKeys int `json:"totalKeys"`
	// Providers is the per-provider coverage, ordered by provider name.
	Providers []ProviderCoverage `json:"providers"`
	// Agreements is the count of keys where >=2 providers reported and all agree.
	Agreements int `json:"agreements"`
	// CoverageGaps lists the keys where the providers' value-sets are nested (an
	// inclusion chain) rather than contradictory - one provider saw more than
	// another, a scope difference, not a disagreement. Ordered by key.
	CoverageGaps []Conflict `json:"coverageGaps,omitempty"`
	// Conflicts lists the keys where two providers are mutually exclusive (each holds
	// a value the other lacks) - a genuine disagreement to adjudicate. Ordered by key.
	Conflicts []Conflict `json:"conflicts,omitempty"`
}

// buildFieldReport runs one field's extractor and computes coverage, agreement,
// unique contribution, and conflicts. It is a pure function of the event stream.
func buildFieldReport(f Field, evts []events.DomainEvent) FieldReport {
	o := f.Extract(evts)
	fr := FieldReport{Field: f.Name, Unit: f.Unit, TotalKeys: len(o)}

	provKeys := map[string]int{}
	provValues := map[string]int{}
	uniqueKeys := map[string]int{}
	uniqueValues := map[string]int{}
	provSeen := map[string]struct{}{}

	for _, key := range sortedKeys(o) {
		pm := o[key]
		for prov, vs := range pm {
			provKeys[prov]++
			provValues[prov] += len(vs)
			provSeen[prov] = struct{}{}
		}
		if len(pm) == 1 {
			for prov := range pm {
				uniqueKeys[prov]++
			}
		}
		// A value is a unique contribution when exactly one provider reported it.
		valProviders := map[string][]string{}
		for prov, vs := range pm {
			for v := range vs {
				valProviders[v] = append(valProviders[v], prov)
			}
		}
		for _, provs := range valProviders {
			if len(provs) == 1 {
				uniqueValues[provs[0]]++
			}
		}
		// Classification only applies where two or more providers overlap. A presence
		// field cannot conflict (the key is the value), so it is always an agreement;
		// a valued field is agree / coverage-gap / conflict by classifyKey.
		if len(pm) >= 2 {
			switch {
			case f.Presence:
				fr.Agreements++
			default:
				switch classifyKey(pm) {
				case classAgree:
					fr.Agreements++
				case classCoverageGap:
					fr.CoverageGaps = append(fr.CoverageGaps, buildConflict(key, pm))
				case classConflict:
					fr.Conflicts = append(fr.Conflicts, buildConflict(key, pm))
				}
			}
		}
	}

	providers := make([]string, 0, len(provSeen))
	for prov := range provSeen {
		providers = append(providers, prov)
	}
	sort.Strings(providers)
	for _, prov := range providers {
		fr.Providers = append(fr.Providers, ProviderCoverage{
			Provider:     prov,
			Keys:         provKeys[prov],
			Values:       provValues[prov],
			UniqueKeys:   uniqueKeys[prov],
			UniqueValues: uniqueValues[prov],
		})
	}
	sort.Slice(fr.CoverageGaps, func(i, j int) bool { return fr.CoverageGaps[i].Key < fr.CoverageGaps[j].Key })
	sort.Slice(fr.Conflicts, func(i, j int) bool { return fr.Conflicts[i].Key < fr.Conflicts[j].Key })
	return fr
}

// keyClass is how a key's overlapping providers relate: identical sets, a nested
// (inclusion-chain) scope difference, or a mutually-exclusive conflict.
type keyClass int

const (
	classAgree keyClass = iota
	classCoverageGap
	classConflict
)

// classifyKey classifies a key that two or more providers reported. It returns
// classAgree when every provider gave the identical set; classConflict when some
// provider pair is mutually exclusive (each holds a value the other lacks) - a genuine
// disagreement; and classCoverageGap otherwise, when every difference is
// one-directional (the sets form an inclusion chain), meaning one provider simply saw
// more than another rather than contradicting it. Providers per key is tiny (a
// handful), so the O(N^2) pairwise set-difference is cheap.
func classifyKey(pm map[string]map[string]struct{}) keyClass {
	if valueSetsEqual(pm) {
		return classAgree
	}
	provs := make([]string, 0, len(pm))
	for prov := range pm {
		provs = append(provs, prov)
	}
	for i := 0; i < len(provs); i++ {
		for j := i + 1; j < len(provs); j++ {
			a, b := pm[provs[i]], pm[provs[j]]
			if hasExtra(a, b) && hasExtra(b, a) {
				return classConflict
			}
		}
	}
	return classCoverageGap
}

// hasExtra reports whether a holds a value absent from b (the set difference a\b is
// non-empty).
func hasExtra(a, b map[string]struct{}) bool {
	for v := range a {
		if _, ok := b[v]; !ok {
			return true
		}
	}
	return false
}

// valueSetsEqual reports whether every provider on a key reported the identical
// normalised value-set.
func valueSetsEqual(pm map[string]map[string]struct{}) bool {
	var ref map[string]struct{}
	first := true
	for _, vs := range pm {
		if first {
			ref = vs
			first = false
			continue
		}
		if !setEqual(ref, vs) {
			return false
		}
	}
	return true
}

func setEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for v := range a {
		if _, ok := b[v]; !ok {
			return false
		}
	}
	return true
}

// buildConflict snapshots, for a disputed key, the sorted values each provider
// reported, so the analyst can adjudicate the disagreement.
func buildConflict(key string, pm map[string]map[string]struct{}) Conflict {
	c := Conflict{Key: key, Values: make(map[string][]string, len(pm))}
	for prov, vs := range pm {
		c.Values[prov] = sortedValues(vs)
	}
	return c
}
