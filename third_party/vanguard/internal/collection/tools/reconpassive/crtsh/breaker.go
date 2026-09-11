package crtsh

import "sync"

// outageThreshold is how many consecutive searches must each spend their whole
// retry budget without a single successful crt.sh response before the outage
// breaker opens. It is deliberately conservative. crt.sh is the sole certificate
// source and the shipped posture is completeness-first (MaxRetries == -1, retry
// until it succeeds), so the breaker must never trip on ordinary flakiness: any
// successful response resets the streak. It exists only to catch a sustained,
// total outage, where every search would otherwise ride the full MaxQueryTime and
// the crawl would grind one name per time budget for hours while producing no data.
const outageThreshold = 3

// crtshBreaker is a per-Client circuit breaker over crt.sh availability, shared
// across every search in a run. It is the across-search bound that complements the
// per-search MaxQueryTime/MaxRetries budget: those cap one query, this stops the
// whole crawl from repaying that cap against a crt.sh that is answering nothing.
//
// It is closed while crt.sh answers at all. It opens only after outageThreshold
// consecutive searches return without any successful response, and closes again the
// moment any search gets one, so a recovered crt.sh resumes full retries. Methods
// are safe for concurrent use; the crawler is serial today but parallel per-name
// crawling is a known future.
type crtshBreaker struct {
	mu                 sync.Mutex
	consecutiveOutages int
	open               bool
}

// isOpen reports whether the breaker is currently tripped.
func (b *crtshBreaker) isOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open
}

// recordSuccess marks that a search reached crt.sh (any successful HTTP response,
// including a degraded-empty 200). crt.sh is up, so the outage streak resets and
// the breaker closes.
func (b *crtshBreaker) recordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecutiveOutages = 0
	b.open = false
}

// recordOutage marks that a search ended without any successful response for a
// crt.sh-side reason (retryable failures throughout, ended by its own MaxQueryTime
// deadline or an exhausted finite retry budget). It returns the streak length and
// whether this outage is the one that opened the breaker. Once open it is a no-op
// until recordSuccess closes it, so the streak does not grow unbounded during a
// long outage.
func (b *crtshBreaker) recordOutage() (consecutive int, tripped bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return b.consecutiveOutages, false
	}
	b.consecutiveOutages++
	if b.consecutiveOutages >= outageThreshold {
		b.open = true
		return b.consecutiveOutages, true
	}
	return b.consecutiveOutages, false
}
