package crtsh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"time"
)

// isRetryableStatus reports whether an HTTP status from crt.sh warrants a retry.
// 404 is included: on the search route crt.sh returns 200 with an empty array
// when a name has no certificates, so a 404 there is a transient backend fluke
// (overload / routing / table swap), not an authoritative empty result.
func isRetryableStatus(code int) bool {
	switch code {
	case 404, 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}

func isRetryableNetErr(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return true
	}
	// Default: crt.sh transient failures often surface as transport errors.
	return true
}

func nextBackoff(cur, limit time.Duration) time.Duration {
	n := cur * 2
	if n > limit {
		return limit
	}
	return n
}

func addJitter(d time.Duration) time.Duration {
	j := int64(d) / 4 // +/- 25%
	if j <= 0 {
		return d
	}
	delta := rand.Int63n(2*j) - j
	return time.Duration(int64(d) + delta)
}

// errBodyTooLarge marks a response that exceeded the body cap. It is
// deterministic (a retry returns the same oversized body), so callers must not
// retry it - unlike a transient read error.
var errBodyTooLarge = errors.New("crtsh: response exceeds body cap")

func readCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	lr := io.LimitReader(r, maxBytes+1)
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%w (%d bytes)", errBodyTooLarge, maxBytes)
	}
	return b, nil
}

func looksLikeHTML(b []byte) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && b[0] == '<'
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
}

func randomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}
