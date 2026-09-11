package events

import (
	"fmt"
	"time"
)

var _ DomainEvent = SshPostureDiscovered{}

// SshPostureDiscovered carries the algorithms and protocol an SSH endpoint offers.
// It is structured rather than a banner string on purpose: the security question
// about an SSH service is which key exchanges, host-key types, ciphers, and MACs it
// will accept, and a flattened banner answers none of that.
//
// Every algorithm list is what the server offered during the handshake, not what a
// session negotiated. The distinction matters: a server that offers one weak cipher
// among twenty is exposed by the offer regardless of what a well-configured client
// would pick.
type SshPostureDiscovered struct {
	EventMeta
	// IP and Port identify the endpoint. Together they are the asset key, matching
	// the host/port/protocol key of the service this posture belongs to.
	IP   string
	Port int
	// ProtocolVersion is the SSH protocol version from the identification string,
	// for example "2.0". Empty when the endpoint sent none.
	ProtocolVersion string
	// Banner is the endpoint's identification string, bounded by the producer.
	// Empty when the producer did not retain one. It is kept beside the structured
	// lists as evidence, never instead of them.
	Banner string
	// KeyExchange, HostKey, Encryption, Mac, and Compression are the server's
	// offered algorithm lists. Order is the server's stated preference where the
	// producer preserved it, so consumers must not re-sort them. Each list is
	// capped by the producer.
	KeyExchange []string
	HostKey     []string
	Encryption  []string
	Mac         []string
	Compression []string
	// AuthMechanisms are the authentication methods the endpoint offers. An
	// unexpected mechanism here (for example "none" or a password method on a
	// key-only host) is the point of collecting them.
	AuthMechanisms []string
	// GuessedKeyExchange reports that the server proceeded on a guessed key
	// exchange rather than a negotiated one.
	GuessedKeyExchange bool
	// Truncated marks a posture whose algorithm lists hit a producer cap, so a
	// short list is never read as the server's complete offer.
	Truncated bool
}

// At returns the capture time recorded in the event envelope.
func (e SshPostureDiscovered) At() time.Time { return e.CapturedAt }

// Meta returns the event metadata envelope.
func (e SshPostureDiscovered) Meta() EventMeta { return e.EventMeta }

// String returns a human-readable representation of the event.
func (e SshPostureDiscovered) String() string {
	return fmt.Sprintf("SSH posture on %s:%d (%d key exchange, %d cipher(s))",
		e.IP, e.Port, len(e.KeyExchange), len(e.Encryption))
}

func (SshPostureDiscovered) isDomainEvent() {}
