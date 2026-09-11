package valueobjects

import (
	"net/url"
	"sort"
	"strings"
	"unicode"
)

const cpeAttributeCount = 11

// CPE is a parsed Common Platform Enumeration name. Fields use canonical CPE 2.3
// formatted-string attribute spelling. "*" means ANY and "-" means NA.
type CPE struct {
	// Part classifies application (a), operating system (o), or hardware (h).
	Part string
	// Vendor identifies supplier.
	Vendor string
	// Product identifies product within vendor namespace.
	Product string
	// Version identifies release. "*" means any release.
	Version string
	// Update identifies release update.
	Update string
	// Edition identifies product edition.
	Edition string
	// Language identifies language tag.
	Language string
	// SWEdition identifies software-market edition from CPE 2.3.
	SWEdition string
	// TargetSW identifies target software environment from CPE 2.3.
	TargetSW string
	// TargetHW identifies target hardware environment from CPE 2.3.
	TargetHW string
	// Other carries remaining edition data from CPE 2.3.
	Other string
}

// CPEKind describes what one producer's CPE list means.
type CPEKind uint8

const (
	// CPEKindProduct means every CPE identifies one fingerprinted technology.
	CPEKindProduct CPEKind = iota
	// CPEKindService means one application CPE may be mixed with host platform CPEs.
	CPEKindService
)

// ParseCPE parses CPE 2.3 formatted strings and CPE 2.2 URI bindings. Parsed
// names render as canonical CPE 2.3 formatted strings.
func ParseCPE(s string) (CPE, bool) {
	switch {
	case strings.HasPrefix(s, "cpe:2.3:"):
		return parseCPEFormattedString(s)
	case strings.HasPrefix(s, "cpe:/"):
		return parseCPEURI(s)
	default:
		return CPE{}, false
	}
}

// String renders c as a CPE 2.3 formatted string.
func (c CPE) String() string {
	return "cpe:2.3:" + strings.Join(c.attributes(), ":")
}

// ProductID returns c with only part, vendor, and product constrained.
func (c CPE) ProductID() CPE {
	c.Version = "*"
	c.Update = "*"
	c.Edition = "*"
	c.Language = "*"
	c.SWEdition = "*"
	c.TargetSW = "*"
	c.TargetHW = "*"
	c.Other = "*"
	return c
}

// WithVersion returns c with version set to v. Existing concrete versions win.
// Empty values and values containing whitespace are rejected.
func (c CPE) WithVersion(v string) (CPE, bool) {
	if c.Version != "*" {
		return c, false
	}
	v = strings.TrimSpace(v)
	if v == "" || strings.IndexFunc(v, unicode.IsSpace) >= 0 || !validCPELiteral(v) {
		return c, false
	}
	c.Version = bindCPELiteral(v)
	return c, true
}

// NormalizeCPEs canonicalizes, sorts, and deduplicates CPEs. Invalid input is
// retained unchanged. Product versions are pinned only when list shape proves
// which CPE describes observed product.
func NormalizeCPEs(cpes []string, version string, kind CPEKind) []string {
	if len(cpes) == 0 {
		return nil
	}

	parsed := make([]CPE, len(cpes))
	valid := make([]bool, len(cpes))
	applicationIndexes := make([]int, 0, 1)
	parsedCount := 0
	for i, raw := range cpes {
		parsed[i], valid[i] = ParseCPE(raw)
		if !valid[i] {
			continue
		}
		parsedCount++
		if parsed[i].Part == "a" {
			applicationIndexes = append(applicationIndexes, i)
		}
	}

	switch kind {
	case CPEKindProduct:
		if len(cpes) == 1 && valid[0] {
			parsed[0], _ = parsed[0].WithVersion(version)
		}
	case CPEKindService:
		if parsedCount == len(cpes) && applicationIndexesIdentifyOneProduct(parsed, applicationIndexes) {
			for _, i := range applicationIndexes {
				parsed[i], _ = parsed[i].WithVersion(version)
			}
		}
	}

	out := make([]string, 0, len(cpes))
	for i, raw := range cpes {
		if valid[i] {
			out = append(out, parsed[i].String())
		} else {
			out = append(out, raw)
		}
	}
	sort.Strings(out)
	return compactStrings(out)
}

// applicationIndexesIdentifyOneProduct reports whether every application CPE
// identifies same product. Nmap may emit wildcarded and versioned forms together;
// both can be pinned safely and then deduplicated.
func applicationIndexesIdentifyOneProduct(cpes []CPE, indexes []int) bool {
	if len(indexes) == 0 {
		return false
	}
	want := cpes[indexes[0]].ProductID().String()
	for _, i := range indexes[1:] {
		if cpes[i].ProductID().String() != want {
			return false
		}
	}
	return true
}

func parseCPEFormattedString(s string) (CPE, bool) {
	fields, ok := splitCPEFormattedString(s)
	if !ok || len(fields) != 13 || fields[0] != "cpe" || fields[1] != "2.3" {
		return CPE{}, false
	}
	attrs := fields[2:]
	for i := range attrs {
		attrs[i], ok = canonicalFormattedAttribute(attrs[i])
		if !ok {
			return CPE{}, false
		}
	}
	if !validCPEPart(attrs[0]) {
		return CPE{}, false
	}
	return cpeFromAttributes(attrs), true
}

func parseCPEURI(s string) (CPE, bool) {
	raw := strings.Split(strings.TrimPrefix(s, "cpe:/"), ":")
	if len(raw) < 1 || len(raw) > 7 {
		return CPE{}, false
	}
	attrs := make([]string, cpeAttributeCount)
	for i := range attrs {
		attrs[i] = "*"
	}

	for i, field := range raw {
		value, ok := canonicalURIAttribute(field)
		if !ok {
			return CPE{}, false
		}
		attrs[i] = value
	}
	if !validCPEPart(attrs[0]) {
		return CPE{}, false
	}

	// CPE 2.2 packs five edition-related CPE 2.3 attributes into edition.
	if len(raw) >= 6 && strings.HasPrefix(raw[5], "~") {
		packed := strings.Split(raw[5], "~")
		if len(packed) != 6 || packed[0] != "" {
			return CPE{}, false
		}
		indexes := [...]int{5, 7, 8, 9, 10}
		for i, field := range packed[1:] {
			value, ok := canonicalURIAttribute(field)
			if !ok {
				return CPE{}, false
			}
			attrs[indexes[i]] = value
		}
	}
	return cpeFromAttributes(attrs), true
}

func splitCPEFormattedString(s string) ([]string, bool) {
	fields := make([]string, 0, 13)
	start := 0
	escaped := false
	for i := 0; i < len(s); i++ {
		switch {
		case escaped:
			escaped = false
		case s[i] == '\\':
			escaped = true
		case s[i] == ':':
			fields = append(fields, s[start:i])
			start = i + 1
		}
	}
	if escaped {
		return nil, false
	}
	return append(fields, s[start:]), true
}

func canonicalFormattedAttribute(raw string) (string, bool) {
	if raw == "*" || raw == "-" {
		return raw, true
	}
	if raw == "" {
		return "", false
	}

	var literal strings.Builder
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch == '\\' {
			i++
			if i >= len(raw) {
				return "", false
			}
			if isASCIIAlphaNumeric(raw[i]) {
				return "", false
			}
			literal.WriteByte(raw[i])
			continue
		}
		if !isCPEUnquoted(ch) {
			return "", false
		}
		literal.WriteByte(ch)
	}
	if !validCPELiteral(literal.String()) {
		return "", false
	}
	return bindCPELiteral(literal.String()), true
}

func canonicalURIAttribute(raw string) (string, bool) {
	if raw == "" || raw == "*" {
		return "*", true
	}
	if raw == "-" {
		return "-", true
	}
	literal, err := url.PathUnescape(raw)
	if err != nil || !validCPELiteral(literal) {
		return "", false
	}
	return bindCPELiteral(literal), true
}

func validCPELiteral(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func bindCPELiteral(s string) string {
	var bound strings.Builder
	for i := 0; i < len(s); i++ {
		if !isCPEUnquoted(s[i]) {
			bound.WriteByte('\\')
		}
		bound.WriteByte(s[i])
	}
	return bound.String()
}

func isCPEUnquoted(ch byte) bool {
	return isASCIIAlphaNumeric(ch) || ch == '-' || ch == '.' || ch == '_'
}

func isASCIIAlphaNumeric(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9'
}

func validCPEPart(part string) bool {
	return part == "a" || part == "o" || part == "h"
}

func cpeFromAttributes(a []string) CPE {
	return CPE{Part: a[0], Vendor: a[1], Product: a[2], Version: a[3], Update: a[4],
		Edition: a[5], Language: a[6], SWEdition: a[7], TargetSW: a[8], TargetHW: a[9], Other: a[10]}
}

func (c CPE) attributes() []string {
	return []string{c.Part, c.Vendor, c.Product, c.Version, c.Update, c.Edition,
		c.Language, c.SWEdition, c.TargetSW, c.TargetHW, c.Other}
}

func compactStrings(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}
