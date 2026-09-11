package scopecheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// Resolver looks up the IP addresses for a host. *net.Resolver satisfies it, and a
// test can supply a controlled implementation. The network is a lookup network
// ("ip", "ip4", or "ip6").
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// PolicyDialer is a resolver-aware dialer that enforces an Exclusions boundary at
// dial time. Given a hostname destination it resolves the name once, drops every
// excluded answer, and connects to an allowed literal address. Because it hands the
// underlying dialer a literal, a second resolver lookup cannot reintroduce an
// excluded address between the check and the connection. The hostname is otherwise
// untouched, so a caller's HTTP Host header and TLS SNI stay correct.
//
// A destination given as a literal address is checked directly and dialed without a
// lookup. When every resolved answer is excluded, DialContext returns a typed
// *RejectedError before any socket is opened, never a dial timeout. A nil
// Exclusions excludes nothing; a nil Resolver uses net.DefaultResolver; a nil
// Dialer uses a zero-value net.Dialer.
type PolicyDialer struct {
	// Exclusions is the hard traffic boundary. Nil excludes nothing.
	Exclusions *Exclusions
	// Resolver resolves hostnames. Nil uses net.DefaultResolver.
	Resolver Resolver
	// Dialer connects to a chosen literal address. Nil uses a zero net.Dialer.
	Dialer *net.Dialer
}

// DialContext resolves address, filters excluded answers, and connects to an
// allowed literal. It satisfies the net.Dialer.DialContext signature so it can be
// used as an http.Transport.DialContext.
func (d *PolicyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split dial address %q: %w", address, err)
	}
	base := d.Dialer
	if base == nil {
		base = &net.Dialer{}
	}
	allowed, err := d.ResolveAllowed(ctx, network, host)
	if err != nil {
		return nil, err
	}

	var errs []error
	for _, addr := range allowed {
		conn, err := base.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if err == nil {
			return conn, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("dial %s: %w", host, ctxErr)
		}
		errs = append(errs, fmt.Errorf("dial %s: %w", addr, err))
	}
	return nil, fmt.Errorf("dial %s: all %d allowed addresses failed: %w", host, len(allowed), errors.Join(errs...))
}

// ResolveAllowed resolves host once and returns only addresses permitted by the
// exclusion policy, without opening a socket. Literal addresses are checked and
// returned directly. Every rejected literal or DNS answer is reported through the
// context rejection sink with its canonical matched rule.
func (d *PolicyDialer) ResolveAllowed(ctx context.Context, network, host string) ([]netip.Addr, error) {

	// A literal destination needs no lookup; check and return it directly.
	if addr, err := netip.ParseAddr(host); err == nil {
		unmapped := addr.Unmap()
		if excluded, reason := d.Exclusions.AddrExcluded(unmapped); excluded {
			ReportRejection(ctx, Rejection{Host: unmapped.String(), ResolvedIP: unmapped.String(), Reason: reason})
			return nil, &RejectedError{Host: unmapped.String(), Reason: reason}
		}
		return []netip.Addr{unmapped}, nil
	}

	// A name barred by a domain rule is rejected before any resolution.
	if excluded, reason := d.Exclusions.HostExcluded(host); excluded {
		ReportRejection(ctx, Rejection{Host: host, Reason: reason})
		return nil, &RejectedError{Host: host, Reason: reason}
	}

	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	answers, err := resolver.LookupNetIP(ctx, lookupNetwork(network), host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	allowed, excluded := d.allowedAddrs(ctx, host, answers)
	if len(allowed) == 0 {
		if len(answers) == 0 {
			return nil, fmt.Errorf("resolve %s: no addresses returned", host)
		}
		// The denied addresses ride along on the error: the name itself is in scope, so
		// only they identify the rule that fired, and a caller's typed rejection event
		// would otherwise name just the host it was probing.
		return nil, &RejectedError{
			Host:        host,
			Reason:      fmt.Sprintf("every resolved address for %s is excluded", host),
			ResolvedIPs: excluded,
		}
	}

	return allowed, nil
}

// allowedAddrs drops excluded and duplicate answers, unmaps each address, and
// returns them in a deterministic Happy-Eyeballs order that interleaves IPv6 and
// IPv4 candidates, IPv6 first. Ordering is applied only across the allowed set, so
// an excluded address never influences which allowed address is tried first. The
// second return is the denied answers in lookup order, so the caller can name them
// when no answer survives.
func (d *PolicyDialer) allowedAddrs(ctx context.Context, host string, answers []netip.Addr) (allowed []netip.Addr, denied []string) {
	var v6, v4 []netip.Addr
	seen := make(map[netip.Addr]bool, len(answers))
	for _, a := range answers {
		u := a.Unmap()
		if !u.IsValid() || seen[u] {
			continue
		}
		if excluded, reason := d.Exclusions.AddrExcluded(u); excluded {
			ReportRejection(ctx, Rejection{Host: host, ResolvedIP: u.String(), Reason: reason})
			if !slices.Contains(denied, u.String()) {
				denied = append(denied, u.String())
			}
			continue
		}
		seen[u] = true
		if u.Is6() {
			v6 = append(v6, u)
		} else {
			v4 = append(v4, u)
		}
	}
	out := make([]netip.Addr, 0, len(v6)+len(v4))
	for i := 0; i < len(v6) || i < len(v4); i++ {
		if i < len(v6) {
			out = append(out, v6[i])
		}
		if i < len(v4) {
			out = append(out, v4[i])
		}
	}
	return out, denied
}

// lookupNetwork maps a dial network to the matching resolver lookup network.
func lookupNetwork(network string) string {
	switch network {
	case "tcp4", "udp4":
		return "ip4"
	case "tcp6", "udp6":
		return "ip6"
	default:
		return "ip"
	}
}
