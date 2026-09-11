package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

const (
	smtpPort = "25"
	ehloName = "probe.local"
)

// Config holds configuration for the Client.
type Config struct {
	// Timeout is the per-MX-host probe timeout (connect, banner, EHLO, handshake).
	Timeout time.Duration
	// ResolverAddr is the DNS server (host:port) the probe resolves names through -
	// both the MX lookup and the per-MX-host dial - so active resolution matches the
	// passive phase (which uses the configured resolver, not the OS default). Empty
	// means the system resolver.
	ResolverAddr string
	// Allow authorizes the input mail domain before its MX lookup. Nil permits any
	// domain for standalone use; production injects the shared request authorizer.
	Allow scopecheck.Allow
	// Exclusions is the hard traffic boundary for every derived MX destination: an
	// excluded MX hostname is refused before its dial, and each retained MX hostname
	// is resolved once with excluded addresses dropped before an allowed literal is
	// dialed (the hostname is kept for TLS SNI). Nil excludes nothing (standalone);
	// production injects the engagement exclusions.
	Exclusions *scopecheck.Exclusions
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client performs active SMTP STARTTLS reconnaissance against a domain's MX
// hosts: it resolves MX records, connects to each, reads the banner, sends EHLO,
// checks for STARTTLS, upgrades to TLS when offered, and extracts the negotiated
// certificate metadata.
type Client struct {
	cfg Config
	// resolver looks up MX records; an injectable seam for tests. It defaults to the
	// configured DNS resolver's LookupMX (the system resolver when ResolverAddr is
	// empty).
	resolver MXResolver
	// dialResolver resolves MX hostnames for the per-host SMTP dial through the same
	// configured DNS server. nil means the system resolver (valid for net.Dialer).
	dialResolver *net.Resolver
	// dialer resolves each MX hostname once, drops excluded addresses, and dials an
	// allowed literal on port 25. Tests may override its Resolver.
	dialer *scopecheck.PolicyDialer
}

// New validates cfg and returns a Client. Name resolution (the MX lookup and the
// per-host dial) goes through cfg.ResolverAddr, matching the passive phase; an
// empty ResolverAddr uses the system resolver.
func New(cfg Config) (*Client, error) {
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("smtp: Config.Timeout must be positive")
	}
	r := newResolver(cfg.ResolverAddr)
	return &Client{
		cfg: cfg,
		resolver: func(domain string) ([]*net.MX, error) {
			return r.LookupMX(context.Background(), domain)
		},
		dialResolver: r,
		dialer: &scopecheck.PolicyDialer{
			Exclusions: cfg.Exclusions,
			Resolver:   policyResolver(r),
			Dialer:     &net.Dialer{Timeout: cfg.Timeout},
		},
	}, nil
}

// policyResolver adapts the client's *net.Resolver to the scopecheck.Resolver the
// policy dialer expects. A nil resolver stays nil so the dialer falls back to the
// system default rather than wrapping a nil pointer in a non-nil interface.
func policyResolver(r *net.Resolver) scopecheck.Resolver {
	if r == nil {
		return nil
	}
	return r
}

// newResolver returns a *net.Resolver that sends queries to addr (host:port), or
// nil for the system default when addr is empty. A nil *net.Resolver is valid both
// for net.Dialer.Resolver and as a method receiver (it means the default), so
// callers wire it in unconditionally.
func newResolver(addr string) *net.Resolver {
	if strings.TrimSpace(addr) == "" {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

// Probe resolves the MX hosts for domain and probes each for STARTTLS support and
// TLS details. MX-lookup failure and an absent MX set are reported as a
// ProbeFailed event and returned as an error; per-host failures are reported as
// events and do not fail the probe.
func (c *Client) Probe(ctx context.Context, domain string) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
	if domain == "" {
		c.emit(ctx, ProbeFailed{Domain: domain, Err: "domain is empty"})
		return &Result{Error: "domain is empty"}, fmt.Errorf("smtp: domain is empty")
	}
	// Reject a hard-excluded input domain before the MX lookup and before ProbeStarted
	// claims active work, so an excluded mail domain triggers no DNS or SMTP traffic.
	if c.cfg.Allow != nil {
		if allowed, reason := c.cfg.Allow(ctx, domain); !allowed {
			c.emit(ctx, TargetRejected{Domain: domain, Reason: reason})
			return &Result{Domain: domain, Error: reason}, fmt.Errorf("smtp: probe of %s rejected: %s", domain, reason)
		}
	}
	mxRecords, err := c.resolver(domain)
	if err != nil {
		msg := fmt.Sprintf("lookup MX for %s: %v", domain, err)
		c.emit(ctx, ProbeFailed{Domain: domain, Err: msg})
		return &Result{Domain: domain, Error: msg}, fmt.Errorf("smtp: %s", msg)
	}
	if len(mxRecords) == 0 {
		msg := fmt.Sprintf("no MX records found for %s", domain)
		c.emit(ctx, ProbeFailed{Domain: domain, Err: msg})
		return &Result{Domain: domain, Error: msg}, fmt.Errorf("smtp: %s", msg)
	}
	c.emit(ctx, ProbeStarted{Domain: domain, MXServersCount: len(mxRecords)})

	result := &Result{Domain: domain, MXHosts: make([]MXProbeResult, 0, len(mxRecords))}
	starttls := 0
	failed := 0
	succeeded := 0
	for _, mx := range mxRecords {
		host := strings.TrimSuffix(strings.TrimSpace(mx.Host), ".")
		// An explicitly excluded MX hostname (or literal) is refused before any dial.
		// The engagement root/include boundary is not applied here: an allowed domain
		// may delegate mail to an external provider, while a named exclusion is a hard
		// deny. Other allowed MX hosts still get probed.
		if c.cfg.Exclusions != nil {
			if excluded, reason := c.cfg.Exclusions.HostExcluded(host); excluded {
				scopecheck.ReportRejection(ctx, scopecheck.Rejection{Host: host, Reason: reason})
				c.emit(ctx, MXTargetRejected{Domain: domain, Host: host, Reason: reason})
				result.MXHosts = append(result.MXHosts, MXProbeResult{Host: host, Priority: mx.Pref, PolicyRejected: true, Error: reason})
				continue
			}
		}
		mxResult := c.probeMX(ctx, host, mx.Pref)
		switch {
		case mxResult.PolicyRejected:
			c.emit(ctx, MXTargetRejected{Domain: domain, Host: host, ResolvedIP: mxResult.rejectedIP, Reason: mxResult.Error})
		case mxResult.Error != "":
			failed++
			c.emit(ctx, MxProbeFailed{Domain: domain, Host: host, Err: mxResult.Error})
		default:
			succeeded++
			c.emit(ctx, MxProbed{Domain: domain, Host: host, StartTLS: mxResult.STARTTLSSupported})
		}
		if mxResult.STARTTLSSupported {
			starttls++
		}
		result.MXHosts = append(result.MXHosts, mxResult)
	}

	sort.Slice(result.MXHosts, func(i, j int) bool {
		if result.MXHosts[i].Priority == result.MXHosts[j].Priority {
			return result.MXHosts[i].Host < result.MXHosts[j].Host
		}
		return result.MXHosts[i].Priority < result.MXHosts[j].Priority
	})

	c.emit(ctx, ProbeCompleted{
		Domain:            domain,
		MXHosts:           len(result.MXHosts),
		StartTLSHosts:     starttls,
		TotalMxServers:    len(result.MXHosts),
		SuccessfulProbes:  succeeded,
		FailedProbes:      failed,
		StartTLSSupported: starttls,
		Degraded:          failed > 0,
	})
	return result, nil
}

// dialErrorResult classifies a failed MX dial into the probe result. A hard-exclusion
// rejection is a policy decision (no network event, no egress contribution); a real
// dial failure is a timeout or a refusal, each with its own event.
func (c *Client) dialErrorResult(ctx context.Context, result MXProbeResult, host string, err error, dialStart time.Time) MXProbeResult {
	var rejected *scopecheck.RejectedError
	if errors.As(err, &rejected) {
		result.PolicyRejected = true
		if net.ParseIP(rejected.Host) != nil {
			result.rejectedIP = rejected.Host
		}
		result.Error = rejected.Reason
		return result
	}
	result.Error = fmt.Sprintf("dial SMTP: %v", err)
	result.DialTimedOut = isDialTimeout(err)
	switch {
	case result.DialTimedOut:
		c.emit(ctx, ConnectionTimeout{MXHost: host, Port: smtpPort, Timeout: time.Since(dialStart)})
	case strings.Contains(strings.ToLower(err.Error()), "refused"):
		c.emit(ctx, ConnectionRejected{MXHost: host, Port: smtpPort, Code: 0, Message: err.Error()})
	}
	return result
}

//nolint:gocyclo // protocol state machine requires sequential checks and error handling
func (c *Client) probeMX(ctx context.Context, host string, priority uint16) MXProbeResult {
	if ctx == nil {
		ctx = context.Background()
	}

	result := MXProbeResult{
		Host:     strings.TrimSuffix(strings.TrimSpace(host), "."),
		Priority: priority,
	}

	dialStart := time.Now()
	conn, err := c.dialer.DialContext(ctx, "tcp", smtpAddress(host))
	if err != nil {
		return c.dialErrorResult(ctx, result, host, err, dialStart)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(c.connectionDeadline(ctx)); err != nil {
		result.Error = fmt.Sprintf("set deadline: %v", err)
		return result
	}

	reader := bufio.NewReader(conn)
	activeConn := conn
	quitAllowed := true
	defer func() {
		if !quitAllowed {
			return
		}
		_, _ = fmt.Fprintf(activeConn, "QUIT\r\n")
	}()

	banner, err := readLine(reader)
	if err != nil {
		if isTimeoutError(err) {
			c.emit(ctx, ConnectionTimeout{MXHost: host, Port: smtpPort, Timeout: c.cfg.Timeout})
		} else {
			c.emit(ctx, BannerFetchFailed{MXHost: host, Err: err})
		}
		result.Error = fmt.Sprintf("read banner: %v", err)
		return result
	}
	result.Banner = banner
	if !strings.HasPrefix(banner, "220") {
		if len(banner) >= 3 && (banner[0] == '4' || banner[0] == '5') {
			code, _ := strconv.Atoi(banner[:3])
			c.emit(ctx, ConnectionRejected{
				MXHost:  host,
				Port:    smtpPort,
				Code:    code,
				Message: banner,
			})
		} else {
			c.emit(ctx, BannerFetchFailed{MXHost: host, Err: fmt.Errorf("unexpected banner: %s", banner)})
		}
		result.Error = fmt.Sprintf("unexpected banner: %s", banner)
		return result
	}

	if _, err := fmt.Fprintf(conn, "EHLO %s\r\n", ehloName); err != nil {
		if isTimeoutError(err) {
			c.emit(ctx, ConnectionTimeout{MXHost: host, Port: smtpPort, Timeout: c.cfg.Timeout})
		}
		result.Error = fmt.Sprintf("send EHLO: %v", err)
		return result
	}

	ehloLines, err := readMultiLine(reader, "250")
	if err != nil {
		if isTimeoutError(err) {
			c.emit(ctx, ConnectionTimeout{MXHost: host, Port: smtpPort, Timeout: c.cfg.Timeout})
		}
		result.Error = fmt.Sprintf("read EHLO response: %v", err)
		return result
	}

	authMethods, extensions := parseEHLODetails(ehloLines)
	result.EHLOSupport = extensions
	c.emit(ctx, SMTPCapabilitiesDiscovered{
		MXHost:      host,
		AuthMethods: authMethods,
		Extensions:  extensions,
	})
	if i := sort.SearchStrings(result.EHLOSupport, "STARTTLS"); i < len(result.EHLOSupport) && result.EHLOSupport[i] == "STARTTLS" {
		result.STARTTLSSupported = true
	}
	if !result.STARTTLSSupported {
		return result
	}

	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		if isTimeoutError(err) {
			c.emit(ctx, ConnectionTimeout{MXHost: host, Port: smtpPort, Timeout: c.cfg.Timeout})
		} else {
			c.emit(ctx, StartTLSFailed{MXHost: host, Err: err})
		}
		result.Error = fmt.Sprintf("send STARTTLS: %v", err)
		return result
	}

	if _, err := readMultiLine(reader, "220"); err != nil {
		if isTimeoutError(err) {
			c.emit(ctx, ConnectionTimeout{MXHost: host, Port: smtpPort, Timeout: c.cfg.Timeout})
		} else {
			c.emit(ctx, StartTLSFailed{MXHost: host, Err: err})
		}
		result.Error = fmt.Sprintf("read STARTTLS response: %v", err)
		return result
	}

	quitAllowed = false
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         tlsServerName(host),
	})
	if err := tlsConn.SetDeadline(c.connectionDeadline(ctx)); err != nil {
		result.Error = fmt.Sprintf("set TLS deadline: %v", err)
		return result
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		switch {
		case isTimeoutError(err):
			c.emit(ctx, ConnectionTimeout{MXHost: host, Port: smtpPort, Timeout: c.cfg.Timeout})
		case isTLSCertError(err):
			var certErr *x509.CertificateInvalidError
			var authErr x509.UnknownAuthorityError
			issuer := ""
			if errors.As(err, &certErr) && certErr.Cert != nil {
				issuer = formatIssuer(certErr.Cert)
			} else if errors.As(err, &authErr) && authErr.Cert != nil {
				issuer = formatIssuer(authErr.Cert)
			}
			c.emit(ctx, TLSCertificateError{MXHost: host, Issuer: issuer, Err: err})
		default:
			c.emit(ctx, StartTLSFailed{MXHost: host, Err: err})
		}
		result.Error = fmt.Sprintf("TLS handshake: %v", err)
		return result
	}

	state := tlsConn.ConnectionState()
	result.TLSVersion = tlsVersionName(state.Version)
	result.TLSCipher = tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		populateCert(&result, state.PeerCertificates[0])
	}

	activeConn = tlsConn
	quitAllowed = true
	return result
}

// populateCert copies leaf certificate metadata into the MX probe result.
func populateCert(result *MXProbeResult, leaf *x509.Certificate) {
	result.CertSubject = leaf.Subject.CommonName
	result.CertIssuer = formatIssuer(leaf)
	result.CertSerial = strings.ToUpper(leaf.SerialNumber.Text(16))
	result.CertNotBefore = leaf.NotBefore
	result.CertNotAfter = leaf.NotAfter
	if len(leaf.DNSNames) > 0 {
		sans := make(map[string]struct{}, len(leaf.DNSNames))
		for _, dnsName := range leaf.DNSNames {
			dnsName = strings.TrimSpace(dnsName)
			if dnsName == "" {
				continue
			}
			sans[dnsName] = struct{}{}
		}
		result.CertSANs = make([]string, 0, len(sans))
		for dnsName := range sans {
			result.CertSANs = append(result.CertSANs, dnsName)
		}
		sort.Strings(result.CertSANs)
	}
}

func (c *Client) connectionDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(c.cfg.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (%d)", version)
	}
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if err != nil {
		return line, err
	}
	return line, nil
}

func readMultiLine(reader *bufio.Reader, expectedCode string) ([]string, error) {
	line, err := readLine(reader)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, expectedCode) {
		return nil, fmt.Errorf("unexpected SMTP response %q, want %s", line, expectedCode)
	}

	lines := []string{line}
	if len(line) < len(expectedCode)+1 || line[len(expectedCode)] == ' ' {
		return lines, nil
	}
	if line[len(expectedCode)] != '-' {
		return nil, fmt.Errorf("malformed SMTP response %q", line)
	}

	for {
		line, err = readLine(reader)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(line, expectedCode) {
			return nil, fmt.Errorf("unexpected SMTP response %q, want %s", line, expectedCode)
		}
		lines = append(lines, line)
		if len(line) >= len(expectedCode)+1 && line[len(expectedCode)] == ' ' {
			return lines, nil
		}
	}
}

func parseEHLODetails(lines []string) (authMethods, extensions []string) {
	authMap := make(map[string]struct{})
	extMap := make(map[string]struct{})
	for _, line := range lines {
		if len(line) < 4 {
			continue
		}
		text := strings.TrimSpace(line[4:])
		if text == "" {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		keyword := strings.ToUpper(fields[0])
		if strings.ContainsAny(keyword, ".[]:") {
			continue
		}
		extMap[keyword] = struct{}{}
		if keyword == "AUTH" {
			for _, m := range fields[1:] {
				if strings.ContainsAny(m, ".[]:= ") {
					continue
				}
				authMap[strings.ToUpper(m)] = struct{}{}
			}
		}
	}
	for m := range authMap {
		authMethods = append(authMethods, m)
	}
	sort.Strings(authMethods)
	for ext := range extMap {
		extensions = append(extensions, ext)
	}
	sort.Strings(extensions)
	return authMethods, extensions
}

func formatIssuer(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	org := strings.Join(cert.Issuer.Organization, ", ")
	cn := strings.TrimSpace(cert.Issuer.CommonName)
	if org == "" {
		return cn
	}
	if cn == "" {
		return org
	}
	return org + " (" + cn + ")"
}

// isDialTimeout reports whether err is a connect timeout (the dial got no answer
// before the deadline), as opposed to a refused connection or a non-network
// error. A firewall blocking outbound port 25 drops the SYN, so the dial times
// out; distinguishing that from a refusal (host up, port closed) is what lets the
// caller read an all-timeout result as a probable egress block.
func isDialTimeout(err error) bool {
	return isTimeoutError(err)
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

func isTLSCertError(err error) bool {
	if err == nil {
		return false
	}
	var certErr *x509.CertificateInvalidError
	var authErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	return errors.As(err, &certErr) || errors.As(err, &authErr) || errors.As(err, &hostnameErr) || strings.Contains(strings.ToLower(err.Error()), "certificate")
}

func smtpAddress(host string) string {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, smtpPort)
}

func tlsServerName(host string) string {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return parsedHost
	}
	return host
}
