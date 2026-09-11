package probes

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Profile names the reviewed probe corpus a scan ran. Only embedded profiles
// exist, so a configuration can name one but can never introduce one.
type Profile string

// EmbeddedSafeDefault is the only profile that exists today: the reviewed,
// read-only exposure probe set compiled into the binary.
const EmbeddedSafeDefault Profile = "embedded-safe-default"

// Max caps the embedded set. It is enforced when the set is materialized, so an
// unreviewed bulk import fails loudly instead of quietly multiplying requests per
// virtual host.
const Max = 100

// FileName is the name the probe set is written under inside the caller's
// temporary directory.
const FileName = "probes.txt"

// set is the reviewed web enumeration probe corpus. It is embedded rather than
// configurable: an operator-supplied probe file would put arbitrary request paths
// into the runtime contract of an active scanner, which is exactly the kind of
// implicit behavior this integration is meant not to have.
//
//go:embed probes.txt
var set []byte

var (
	digestOnce sync.Once
	digest     string
)

// Digest returns the hex SHA-256 of the embedded probe set, so a recorded scan
// says which probes produced its hits without storing the set itself.
func Digest() string {
	digestOnce.Do(func() {
		sum := sha256.Sum256(set)
		digest = hex.EncodeToString(sum[:])
	})
	return digest
}

// Count returns the number of probe definitions in the embedded set, using the
// same "skip blanks and comments" rule the upstream loader applies.
func Count() int {
	n := 0
	for line := range strings.SplitSeq(string(set), "\n") {
		line = strings.Trim(strings.TrimRight(line, "\r"), " |")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
	}
	return n
}

// Write materializes the embedded probe set inside dir and returns its path. The
// upstream enumerator only accepts a real file, so the alternative to this is not
// "keep it in memory" but "let an operator point at a file on disk".
func Write(dir string) (string, error) {
	if n := Count(); n > Max {
		return "", fmt.Errorf("embedded probe set has %d probes, the reviewed maximum is %d", n, Max)
	}
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, set, 0o600); err != nil {
		return "", fmt.Errorf("write probe file: %w", err)
	}
	return path, nil
}
