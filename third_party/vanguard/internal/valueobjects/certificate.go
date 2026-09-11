package valueobjects

import (
	"math/big"
	"strings"
)

// CanonicalCertSerial normalizes a certificate serial to a source-independent form so the
// same certificate seen via CT (crt.sh) and via a live TLS handshake keys identically.
// Producers format the serial differently: upper versus lower case hex, optional ":"
// separators, and a leading zero / DER sign-padding byte that one representation carries
// and the other drops (for example live "1DBEA9A4E7110CFE783EB37" versus CT
// "01dbea9a4e7110cfe783eb37"). Parsing the hex digits as an unsigned big integer collapses
// all of those to one value; the result is lowercase hex with no leading zeros. A serial
// that is not parseable as hex falls back to its lowercased, separator-stripped form so no
// identity is lost.
//
// It lives in this leaf package because both the domain entities (which build the
// canonical certificate asset key) and the collection events (which normalize a serial as
// they translate a tool result) must agree on one implementation.
func CanonicalCertSerial(serial string) string {
	s := strings.ToLower(strings.TrimSpace(serial))
	s = strings.NewReplacer(":", "", " ", "").Replace(s)
	if s == "" {
		return ""
	}
	if n, ok := new(big.Int).SetString(s, 16); ok {
		return n.Text(16)
	}
	return s
}
