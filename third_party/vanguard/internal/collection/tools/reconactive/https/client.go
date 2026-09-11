package https

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
	"github.com/velgard-sk/vanguard/internal/collection/tools/scopecheck"
)

const (
	defaultPort         = "443"
	defaultMaxRedirects = 10
)

var errRedirectLimit = errors.New("redirect limit reached")

// Config holds configuration for the Client.
type Config struct {
	// Timeout bounds each TLS dial/handshake and the HTTPS GET for headers.
	Timeout time.Duration
	// MaxRedirects caps redirect hops followed by the security-header GET. Zero uses 10.
	MaxRedirects int
	// ResolverAddr is the DNS server (host:port) the probe resolves names through,
	// so active resolution matches the passive phase (which uses the configured
	// resolver, not the OS default). Empty means the system resolver. Sharing the
	// passive resolver removes the divergence where the passive phase resolves a
	// name the active phase then fails to look up.
	ResolverAddr string
	// Allow authorizes every normalized security-header HTTP request host before
	// traffic is sent. Nil permits valid HTTP(S) targets for standalone use.
	Allow scopecheck.Allow
	// Exclusions is the hard traffic boundary enforced at dial time on every TLS
	// handshake, the header request, and the provider certificate preflight: a
	// hostname is resolved once, excluded answers are dropped, and only an allowed
	// literal is dialed, with the original name kept as TLS SNI. Nil excludes nothing
	// (standalone use); production injects the engagement exclusions.
	Exclusions *scopecheck.Exclusions
	// Sink receives a typed event for every notable outcome. May be nil.
	Sink tooleventlog.EventSink
}

// Client performs active HTTPS reconnaissance against a domain on port 443: it
// opens live TLS connections to capture the leaf certificate and full peer
// chain, enumerates supported TLS protocol versions (marking old-protocol risk
// and negotiated ciphers), and fetches the HSTS policy and security headers from
// the HTTPS endpoint.
type Client struct {
	cfg      Config
	resolver *net.Resolver
	// dialer is the shared resolver-aware policy dialer every TLS handshake and the
	// header transport dial through: it resolves once, drops excluded answers, and
	// dials an allowed literal. Tests may override its Resolver.
	dialer *scopecheck.PolicyDialer
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("https: Config.Timeout must be positive")
	}
	if cfg.MaxRedirects < 0 {
		return nil, fmt.Errorf("https: Config.MaxRedirects must not be negative")
	}
	if cfg.MaxRedirects == 0 {
		cfg.MaxRedirects = defaultMaxRedirects
	}
	resolver := newResolver(cfg.ResolverAddr)
	dialer := &scopecheck.PolicyDialer{
		Exclusions: cfg.Exclusions,
		Resolver:   policyResolver(resolver),
		Dialer:     &net.Dialer{Timeout: cfg.Timeout},
	}
	return &Client{cfg: cfg, resolver: resolver, dialer: dialer}, nil
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
// nil for the system default when addr is empty. nil is a valid value for
// net.Dialer.Resolver, so callers wire it in unconditionally.
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

// Probe runs full HTTPS reconnaissance against domain on port 443.
func (c *Client) Probe(ctx context.Context, domain string) (*Result, error) {
	return c.probe(ctx, domain, defaultPort)
}

// ProbeCertificate performs one TLS handshake against address using serverName as
// SNI and returns only the leaf certificate's DNS SANs. address may include a port
// for controlled tests; production provider corroboration uses port 443. Both the
// literal address and SNI name are checked against configured exclusions. It does
// not enumerate protocol versions or send an HTTP request.
func (c *Client) ProbeCertificate(ctx context.Context, address, serverName string) (*CertificateEvidence, error) {
	address = strings.TrimSpace(address)
	serverName = strings.TrimSpace(serverName)
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	host, port := address, defaultPort
	if splitHost, splitPort, err := net.SplitHostPort(address); err == nil {
		host, port = splitHost, splitPort
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		err = fmt.Errorf("https: certificate preflight address %q is not an IP: %w", address, err)
		c.emit(ctx, ProbeFailed{Target: address, Err: err})
		return nil, err
	}
	// Defense in depth: orchestration already refuses an excluded provider candidate
	// before the preflight, but the tool rechecks the literal at its own boundary so a
	// direct caller cannot make the preflight dial an excluded address.
	if c.cfg.Exclusions != nil {
		if excluded, reason := c.cfg.Exclusions.AddrExcluded(addr); excluded {
			scopecheck.ReportRejection(ctx, scopecheck.Rejection{Host: addr.Unmap().String(), ResolvedIP: addr.Unmap().String(), Reason: reason})
			c.emit(ctx, TargetRejected{Target: address, ResolvedIP: addr.Unmap().String(), Reason: reason})
			return nil, &scopecheck.RejectedError{Host: addr.Unmap().String(), Reason: reason}
		}
	}
	if serverName == "" {
		err := fmt.Errorf("https: certificate preflight server name is empty")
		c.emit(ctx, ProbeFailed{Target: address, Err: err})
		return nil, err
	}
	// The provider admission path already checks its associated name, but a direct
	// tool caller must not attach an excluded identity as SNI to an otherwise allowed
	// address.
	if c.cfg.Exclusions != nil {
		if excluded, reason := c.cfg.Exclusions.HostExcluded(serverName); excluded {
			scopecheck.ReportRejection(ctx, scopecheck.Rejection{Host: serverName, Reason: reason})
			c.emit(ctx, TargetRejected{Target: serverName, Reason: reason})
			return nil, &scopecheck.RejectedError{Host: serverName, Reason: reason}
		}
	}

	c.emit(ctx, CertificatePreflightStarted{Address: address, ServerName: serverName})
	conn, err := c.dialTLS(ctx, host, port, &tls.Config{InsecureSkipVerify: true, ServerName: serverName})
	if err != nil {
		c.emitTLSErr(ctx, address, port, err, "")
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		err := fmt.Errorf("https: certificate preflight returned no peer certificates")
		c.emit(ctx, TLSInfoFailed{Target: address, Err: err})
		return nil, err
	}

	names := append([]string(nil), state.PeerCertificates[0].DNSNames...)
	sort.Strings(names)
	evidence := &CertificateEvidence{RemoteAddr: conn.RemoteAddr().String(), DNSNames: names}
	c.emit(ctx, CertificatePreflightCompleted{Address: address, ServerName: serverName, DNSNames: append([]string(nil), names...)})
	return evidence, nil
}

// ProbeEndpoints performs concurrent HTTPS recon against a batch of domains on port 443,
// summarizing execution metrics in a final ProbeCompleted event.
func (c *Client) ProbeEndpoints(ctx context.Context, domains []string, concurrency int) ([]*Result, error) {
	if len(domains) == 0 {
		return nil, nil
	}
	if concurrency <= 0 {
		concurrency = 5
	}
	c.emit(ctx, ProbeStarted{Target: strings.Join(domains, ","), Port: 443})

	var (
		totalEndpoints   = len(domains)
		handshakeSuccess int
		handshakeFailed  int
	)

	results := make([]*Result, len(domains))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, d := range domains {
		wg.Add(1)
		go func(idx int, domain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res, _ := c.doProbe(ctx, domain, defaultPort)
			mu.Lock()
			defer mu.Unlock()
			if res != nil && res.Reachable {
				handshakeSuccess++
				results[idx] = res
			} else {
				handshakeFailed++
			}
		}(i, d)
	}
	wg.Wait()

	degraded := handshakeFailed > 0 && handshakeSuccess > 0
	c.emit(ctx, ProbeCompleted{
		Target:           strings.Join(domains, ","),
		TotalEndpoints:   totalEndpoints,
		HandshakeSuccess: handshakeSuccess,
		HandshakeFailed:  handshakeFailed,
		Degraded:         degraded,
	})

	validResults := make([]*Result, 0, handshakeSuccess)
	for _, r := range results {
		if r != nil && r.Reachable {
			validResults = append(validResults, r)
		}
	}
	return validResults, nil
}

// probe runs HTTPS recon against domain on the given port. Tests call this
// directly with a local listener port.
func (c *Client) probe(ctx context.Context, domain, port string) (*Result, error) {
	if h, p, err := net.SplitHostPort(domain); err == nil {
		domain = h
		port = p
	}
	portInt, _ := strconv.Atoi(port)
	if portInt == 0 {
		portInt = 443
	}
	c.emit(ctx, ProbeStarted{Target: domain, Port: portInt})

	result, err := c.doProbe(ctx, domain, port)
	if result == nil {
		return nil, err
	}

	succeeded := 0
	failed := 0
	if result.Reachable {
		succeeded = 1
	} else {
		failed = 1
	}

	c.emit(ctx, ProbeCompleted{
		Target:           domain,
		TotalEndpoints:   1,
		HandshakeSuccess: succeeded,
		HandshakeFailed:  failed,
		Degraded:         false,
	})
	return result, err
}

func (c *Client) doProbe(ctx context.Context, domain, port string) (*Result, error) {
	if h, p, err := net.SplitHostPort(domain); err == nil {
		domain = h
		port = p
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	domain = strings.TrimSpace(domain)
	if domain == "" {
		err := fmt.Errorf("https: domain is empty")
		c.emit(ctx, ProbeFailed{Target: domain, Err: err})
		return nil, err
	}

	result := &Result{TLSVersions: make([]TLSVersionResult, 0, 4)}

	// Authorize the initial target before the first TLS handshake opens a connection.
	// The request authorizer previously guarded only the later header GET, leaving the
	// certificate handshake and version sweep unchecked; a rejection here is terminal
	// and dials nothing.
	if c.cfg.Allow != nil {
		if allowed, reason := c.cfg.Allow(ctx, domain); !allowed {
			c.emit(ctx, TargetRejected{Target: domain, Reason: reason})
			return result, fmt.Errorf("https: probe of %s rejected: %s", domain, reason)
		}
	}

	tlsErr := c.populateTLSInfo(ctx, domain, port, result)
	if tlsErr != nil {
		// A hard-exclusion rejection on the first handshake is terminal and must not
		// look like a TLS/connection failure or an unreachable host: skip the version
		// sweep and the header GET so no false unsupported-version or unreachable
		// evidence is produced, and report it as a policy rejection.
		if rejected := asRejected(tlsErr); rejected != nil {
			c.emit(ctx, TargetRejected{Target: domain, ResolvedIPs: rejected.ResolvedIPs, Reason: rejected.Reason})
			return result, fmt.Errorf("https: probe of %s rejected: %w", domain, tlsErr)
		}
		appendError(&result.Error, fmt.Sprintf("tls probe failed: %v", tlsErr))
		c.emitTLSErr(ctx, domain, port, tlsErr, "")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Short-circuit an unreachable host: when the first dial failed at the connection
	// level (refused, timeout, no route), the four version dials and the headers GET
	// would each wait the full timeout to fail identically - 6 x timeout of dead wait
	// for no data. Skip them so an unreachable host costs ~1 timeout. A host that
	// answered at the TLS layer (a handshake/record error, or an empty peer chain)
	// still gets the full sweep, since those probes are meaningful there.
	headersOK := false
	var terminalErr error
	if tlsErr == nil || !isHostUnreachable(tlsErr) {
		headersOK, terminalErr = c.collectHTTPPosture(ctx, domain, port, result)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	// The endpoint was reached when any TLS handshake or the HTTPS GET completed.
	// When all dials failed, the all-unsupported versions below are a non-result,
	// not a clean posture - Reachable lets the caller tell the two apart.
	result.Reachable = result.TLS != nil || countSupported(result.TLSVersions) > 0 || headersOK

	if result.Reachable {
		var bestVer, bestCipher string
		for i := len(result.TLSVersions) - 1; i >= 0; i-- {
			if result.TLSVersions[i].Supported {
				bestVer = result.TLSVersions[i].Version
				bestCipher = result.TLSVersions[i].Cipher
				break
			}
		}
		sanCount := 0
		if result.TLS != nil {
			sanCount = len(result.TLS.SANs)
		}
		c.emit(ctx, TLSPostureDiscovered{
			Target:     domain,
			TLSVersion: bestVer,
			Cipher:     bestCipher,
			HasHSTS:    result.HSTS != nil,
			SANCount:   sanCount,
		})
	}

	return result, terminalErr
}

// collectHTTPPosture enumerates protocol support and performs the one policy-aware
// HTTP request. Only a policy rejection is terminal; ordinary header failures stay
// in Result.Error as the package's existing best-effort behavior.
func (c *Client) collectHTTPPosture(ctx context.Context, domain, port string, result *Result) (bool, error) {
	result.TLSVersions = c.enumerateTLSVersions(ctx, domain, port)
	if err := ctx.Err(); err != nil {
		return false, err
	}

	headers, hstsRaw, trail, err := c.fetchSecurityHeaders(ctx, domain, port)
	result.RedirectTrail = trail
	if err != nil {
		appendError(&result.Error, fmt.Sprintf("http probe failed: %v", err))
		c.emitHTTPErr(ctx, domain, port, err)
		if isPolicyRejection(err) {
			return false, fmt.Errorf("https: security-header request rejected: %w", err)
		}
		return false, nil
	}

	result.HeadersComplete = true
	result.SecurityHeaders = headers
	result.HSTS = parseHSTS(hstsRaw)
	result.SecurityHeaders.MissingHeaders = criticalMissingHeaders(&result.SecurityHeaders, result.HSTS)
	return true, nil
}

func countSupported(versions []TLSVersionResult) int {
	n := 0
	for _, v := range versions {
		if v.Supported {
			n++
		}
	}
	return n
}

// criticalMissingHeaders returns names of absent critical security headers.
func criticalMissingHeaders(h *SecurityHeaders, hsts *HSTSResult) []string {
	var missing []string
	if h.CSP == "" {
		missing = append(missing, "Content-Security-Policy")
	}
	if h.XFrameOptions == "" {
		missing = append(missing, "X-Frame-Options")
	}
	if h.XContentTypeOpts == "" {
		missing = append(missing, "X-Content-Type-Options")
	}
	if h.ReferrerPolicy == "" {
		missing = append(missing, "Referrer-Policy")
	}
	if hsts == nil {
		missing = append(missing, "Strict-Transport-Security")
	}
	if h.PermissionsPolicy == "" {
		missing = append(missing, "Permissions-Policy")
	}
	if missing == nil {
		return []string{}
	}
	return missing
}

// populateTLSInfo fills leaf certificate data and the full peer chain.
func (c *Client) populateTLSInfo(ctx context.Context, domain, port string, result *Result) error {
	conn, err := c.dialTLS(ctx, domain, port, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	result.RemoteAddr = conn.RemoteAddr().String()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificates returned")
	}

	leaf := state.PeerCertificates[0]
	leafSubject := strings.TrimSpace(leaf.Subject.CommonName)
	if leafSubject == "" {
		leafSubject = leaf.Subject.String()
	}

	now := time.Now()
	result.TLS = &TLSInfo{
		Subject:   leafSubject,
		Issuer:    issuerName(leaf),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		SANs:      certificateSANs(leaf),
		Serial:    strings.ToUpper(leaf.SerialNumber.Text(16)),
		SigAlgo:   leaf.SignatureAlgorithm.String(),
		KeyUsage:  certificateKeyUsage(leaf.ExtKeyUsage),
		IsExpired: now.After(leaf.NotAfter),
		DaysLeft:  int(leaf.NotAfter.Sub(now).Hours() / 24),
	}

	if result.TLS.IsExpired {
		c.emit(ctx, CertificateExpired{Target: domain, NotAfter: leaf.NotAfter, Subject: leafSubject})
	}
	verifyErr := verifyServedChain(state.PeerCertificates, domain, now, nil)
	result.ChainValidation = &ChainValidation{Trusted: verifyErr == nil}
	if verifyErr != nil {
		result.ChainValidation.Error = verifyErr.Error()
		c.emit(ctx, CertificateChainInvalid{Target: domain, Issuer: issuerName(leaf), Err: verifyErr})
	}

	result.CertChain = make([]ChainCert, 0, len(state.PeerCertificates))
	for index, cert := range state.PeerCertificates {
		subject := strings.TrimSpace(cert.Subject.CommonName)
		if subject == "" {
			subject = cert.Subject.String()
		}

		result.CertChain = append(result.CertChain, ChainCert{
			Subject:   subject,
			Issuer:    issuerName(cert),
			NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
			SANs:      certificateSANs(cert),
			Serial:    strings.ToUpper(cert.SerialNumber.Text(16)),
			SigAlgo:   cert.SignatureAlgorithm.String(),
			IsCA:      cert.IsCA,
			Position:  index,
		})
	}

	return nil
}

// enumerateTLSVersions probes fixed TLS versions one by one.
func (c *Client) enumerateTLSVersions(ctx context.Context, domain, port string) []TLSVersionResult {
	versions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}
	results := make([]TLSVersionResult, 0, len(versions))

	for _, version := range versions {
		item := TLSVersionResult{Version: tlsVersionName(version)}

		conn, err := c.dialTLS(ctx, domain, port, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
			MinVersion:         version,
			MaxVersion:         version,
		})
		if err == nil {
			state := conn.ConnectionState()
			item.Supported = true
			item.Cipher = tls.CipherSuiteName(state.CipherSuite)
			item.Risk = tlsVersionRisk(version)
			_ = conn.Close()
		} else {
			item.Error = err.Error()
		}

		results = append(results, item)
	}

	return results
}

// fetchSecurityHeaders performs one HTTPS GET and extracts security headers.
func (c *Client) fetchSecurityHeaders(ctx context.Context, domain, port string) (SecurityHeaders, string, []scopecheck.RedirectObservation, error) {
	trail := make([]scopecheck.RedirectObservation, 0, c.cfg.MaxRedirects)
	transport := &http.Transport{
		Proxy:       nil,
		DialContext: c.dialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout: c.cfg.Timeout, Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > c.cfg.MaxRedirects {
				c.emit(req.Context(), RedirectLimitReached{Target: domain, URL: req.URL.String(), Limit: c.cfg.MaxRedirects})
				return fmt.Errorf("stopped after %d redirects: %w", c.cfg.MaxRedirects, errRedirectLimit)
			}
			last := via[len(via)-1]
			status := 0
			if req.Response != nil {
				status = req.Response.StatusCode
			}
			hop := len(via)
			observation := scopecheck.RedirectObservation{
				FromURL: last.URL.String(), ToURL: req.URL.String(), Status: status, Hop: hop,
			}
			if err := scopecheck.Check(req.Context(), c.cfg.Allow, req.URL); err != nil {
				var rejected *scopecheck.RejectedError
				if errors.As(err, &rejected) {
					observation.Disposition = scopecheck.DispositionRejected
					observation.Reason = rejected.Reason
					trail = append(trail, observation)
					c.emit(req.Context(), RedirectRejected{
						Target: domain, FromURL: observation.FromURL, ToURL: observation.ToURL,
						Status: status, Hop: hop, Reason: rejected.Reason,
					})
				}
				return fmt.Errorf("authorize redirect to %s: %w", req.URL, err)
			}
			observation.Disposition = scopecheck.DispositionFollowed
			trail = append(trail, observation)
			c.emit(req.Context(), RedirectFollowed{
				Target: domain, FromURL: observation.FromURL, ToURL: observation.ToURL,
				Status: status, Hop: hop,
			})
			return nil
		},
	}

	targetURL := "https://" + net.JoinHostPort(domain, port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		return SecurityHeaders{}, "", trail, err
	}
	if err := scopecheck.Check(ctx, c.cfg.Allow, req.URL); err != nil {
		return SecurityHeaders{}, "", trail, fmt.Errorf("authorize request %s: %w", targetURL, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return SecurityHeaders{}, "", trail, err
	}
	defer func() { _ = resp.Body.Close() }()

	rawHSTS := resp.Header.Get("Strict-Transport-Security")
	return extractSecurityHeaders(resp.Header), rawHSTS, trail, nil
}

func isPolicyRejection(err error) bool {
	return asRejected(err) != nil
}

// asRejected returns the wrapped policy rejection, or nil when err is not one.
func asRejected(err error) *scopecheck.RejectedError {
	var rejected *scopecheck.RejectedError
	if errors.As(err, &rejected) {
		return rejected
	}
	return nil
}

// dialTLS opens one TLS connection with the configured timeout. The raw TCP dial
// goes through the shared policy dialer, so the destination hostname is resolved
// once, excluded addresses are dropped, and only an allowed literal is connected -
// while config.ServerName keeps the original hostname as SNI. An all-excluded
// destination returns a *scopecheck.RejectedError before the handshake.
func (c *Client) dialTLS(ctx context.Context, domain, port string, config *tls.Config) (*tls.Conn, error) {
	rawConn, err := c.dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, port))
	if err != nil {
		return nil, err
	}

	hsCtx := ctx
	if c.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		hsCtx, cancel = context.WithTimeout(ctx, c.cfg.Timeout)
		defer cancel()
	}
	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func (c *Client) emit(ctx context.Context, e tooleventlog.Event) {
	if c.cfg.Sink != nil {
		c.cfg.Sink.Emit(ctx, e)
	}
}

func (c *Client) emitCommonNetErr(ctx context.Context, domain string, port int, err error, errStr string) bool {
	if isTimeoutErr(err) {
		c.emit(ctx, TLSHandshakeTimeout{Target: domain, Timeout: c.cfg.Timeout})
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) || strings.Contains(errStr, "no such host") || strings.Contains(errStr, "server misbehaving") || strings.Contains(errStr, "lookup ") {
		c.emit(ctx, DNSResolutionFailed{Target: domain, Err: err})
		return true
	}
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(errStr, "refused") {
		c.emit(ctx, ConnectionRefused{Target: domain, Port: port})
		return true
	}
	return false
}

func (c *Client) emitTLSErr(ctx context.Context, domain, portStr string, err error, offeredVer string) {
	if err == nil {
		return
	}
	errStr := strings.ToLower(err.Error())
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}
	if c.emitCommonNetErr(ctx, domain, port, err, errStr) {
		return
	}

	var certErr *x509.CertificateInvalidError
	if errors.As(err, &certErr) || strings.Contains(errStr, "expired") {
		notAfter := time.Time{}
		if certErr != nil && certErr.Cert != nil {
			notAfter = certErr.Cert.NotAfter
		}
		c.emit(ctx, CertificateExpired{Target: domain, NotAfter: notAfter, Subject: domain})
		return
	}
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) || strings.Contains(errStr, "unknown authority") || strings.Contains(errStr, "self-signed") {
		issuer := ""
		if authErr.Cert != nil {
			issuer = issuerName(authErr.Cert)
		}
		c.emit(ctx, CertificateChainInvalid{Target: domain, Issuer: issuer, Err: err})
		return
	}
	if strings.Contains(errStr, "protocol") || strings.Contains(errStr, "version") || strings.Contains(errStr, "cipher") || strings.Contains(errStr, "handshake failure") || strings.Contains(errStr, "remote error: tls:") {
		c.emit(ctx, ProtocolNegotiationFailed{Target: domain, OfferedVer: offeredVer, Err: err})
		return
	}
	c.emit(ctx, TLSInfoFailed{Target: domain, Err: err})
}

func (c *Client) emitHTTPErr(ctx context.Context, domain, portStr string, err error) {
	if err == nil {
		return
	}
	errStr := strings.ToLower(err.Error())
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}
	if c.emitCommonNetErr(ctx, domain, port, err, errStr) {
		return
	}
	c.emit(ctx, HeadersFetchFailed{Target: domain, Err: err})
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	var urlErr *url.Error
	errStr := strings.ToLower(err.Error())
	return errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &netErr) && netErr.Timeout()) ||
		(errors.As(err, &urlErr) && urlErr.Timeout()) ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded")
}

// isHostUnreachable reports whether err from the first TLS dial (populateTLSInfo) is a
// connection-level failure - the host never answered - as opposed to a TLS-level error
// where the host did answer. It gates the version-sweep short-circuit, so it classifies
// conservatively: only explicit connect failures (refused, host/network unreachable) and
// dial timeouts count; a TLS record/handshake error, or the empty-peer-chain case (the
// host completed a TLS connection), return false so the caller runs the full sweep.
func isHostUnreachable(err error) bool {
	if err == nil {
		return false
	}

	// A TLS-level failure means the host answered; never short-circuit on it. A
	// RecordHeaderError is a non-TLS service on the port, and this exact error is
	// returned by populateTLSInfo after a completed handshake with an empty peer chain.
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return false
	}
	if strings.Contains(err.Error(), "no peer certificates returned") {
		return false
	}

	// A dial/handshake that never completed in time: the host is unreachable for probe
	// purposes (a host that cannot complete one handshake within the timeout is dead to
	// the sweep, which would only repeat the wait four more times).
	if isTimeoutErr(err) {
		return true
	}

	// Explicit connect-level failures.
	for _, errno := range []syscall.Errno{syscall.ECONNREFUSED, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.ETIMEDOUT} {
		if errors.Is(err, errno) {
			return true
		}
	}

	// Any other failure in the TCP dial phase (for example a DNS lookup failure, which
	// every later dial would repeat) is host-level. A TLS-layer error happens after the
	// dial op, so it is never Op == "dial".
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}

	return false
}

// appendError joins probe errors into one string.
func appendError(dst *string, message string) {
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	if *dst == "" {
		*dst = message
		return
	}
	*dst += "; " + message
}

// issuerName formats issuer organization and common name.
// verifyServedChain validates the leaf of a served chain for domain, building the
// path only from the certificates the server itself sent. roots nil means the host
// trust store; tests pass their own.
//
// Passing the served certificates as intermediates is what makes the verdict mean
// what it says. Without them any deployment whose chain needs an intermediate fails
// with "signed by unknown authority" even when the server did send that
// intermediate and the root is trusted - which blames the target for the prober's
// empty pool. With them, a failure is a real deployment fault: an intermediate the
// server never sent, an issuer no trust store holds, or a name the certificate does
// not cover.
func verifyServedChain(served []*x509.Certificate, domain string, now time.Time, roots *x509.CertPool) error {
	if len(served) == 0 {
		return fmt.Errorf("no peer certificates returned")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range served[1:] {
		intermediates.AddCert(cert)
	}
	_, err := served[0].Verify(x509.VerifyOptions{
		DNSName:       domain,
		CurrentTime:   now,
		Roots:         roots,
		Intermediates: intermediates,
	})
	return err
}

func issuerName(cert *x509.Certificate) string {
	org := strings.TrimSpace(strings.Join(cert.Issuer.Organization, " "))
	cn := strings.TrimSpace(cert.Issuer.CommonName)

	switch {
	case org != "" && cn != "":
		return org + " " + cn
	case org != "":
		return org
	case cn != "":
		return cn
	default:
		return cert.Issuer.String()
	}
}

// certificateSANs collects, deduplicates, and sorts SAN entries.
func certificateSANs(cert *x509.Certificate) []string {
	seen := make(map[string]struct{})
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		seen[value] = struct{}{}
	}

	for _, name := range cert.DNSNames {
		add(name)
	}
	for _, ip := range cert.IPAddresses {
		add(ip.String())
	}
	for _, email := range cert.EmailAddresses {
		add(email)
	}
	for _, uri := range cert.URIs {
		add(uri.String())
	}

	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// certificateKeyUsage maps ext key usages to readable names.
func certificateKeyUsage(usages []x509.ExtKeyUsage) []string {
	seen := make(map[string]struct{})
	for _, usage := range usages {
		name := ""
		switch usage {
		case x509.ExtKeyUsageAny:
			name = "Any"
		case x509.ExtKeyUsageServerAuth:
			name = "Server Auth"
		case x509.ExtKeyUsageClientAuth:
			name = "Client Auth"
		case x509.ExtKeyUsageCodeSigning:
			name = "Code Signing"
		case x509.ExtKeyUsageEmailProtection:
			name = "Email Protection"
		case x509.ExtKeyUsageIPSECEndSystem:
			name = "IPSEC End System"
		case x509.ExtKeyUsageIPSECTunnel:
			name = "IPSEC Tunnel"
		case x509.ExtKeyUsageIPSECUser:
			name = "IPSEC User"
		case x509.ExtKeyUsageTimeStamping:
			name = "Time Stamping"
		case x509.ExtKeyUsageOCSPSigning:
			name = "OCSP Signing"
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			name = "Microsoft Server Gated Crypto"
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			name = "Netscape Server Gated Crypto"
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			name = "Microsoft Commercial Code Signing"
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			name = "Microsoft Kernel Code Signing"
		}
		if name == "" {
			continue
		}
		seen[name] = struct{}{}
	}

	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// tlsVersionRisk marks old TLS versions.
func tlsVersionRisk(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "critical"
	case tls.VersionTLS11:
		return "warning"
	default:
		return ""
	}
}

// tlsVersionName maps TLS version constants to friendly names.
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
		return "Unknown"
	}
}

// parseHSTS parses Strict-Transport-Security directives.
func parseHSTS(raw string) *HSTSResult {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	result := &HSTSResult{Raw: raw}
	parts := strings.Split(raw, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		key := part
		value := ""
		if eq := strings.Index(part, "="); eq >= 0 {
			key = strings.TrimSpace(part[:eq])
			value = strings.TrimSpace(part[eq+1:])
		}

		switch strings.ToLower(key) {
		case "max-age":
			if parsed, err := strconv.Atoi(value); err == nil {
				result.MaxAge = parsed
			}
		case "includesubdomains":
			result.IncludeSubDomains = true
		case "preload":
			result.Preload = true
		}
	}

	return result
}

// extractSecurityHeaders copies recognized headers from an HTTP response.
func extractSecurityHeaders(headers http.Header) SecurityHeaders {
	return SecurityHeaders{
		CSP:               headers.Get("Content-Security-Policy"),
		XFrameOptions:     headers.Get("X-Frame-Options"),
		XContentTypeOpts:  headers.Get("X-Content-Type-Options"),
		ReferrerPolicy:    headers.Get("Referrer-Policy"),
		PermissionsPolicy: headers.Get("Permissions-Policy"),
		COOP:              headers.Get("Cross-Origin-Opener-Policy"),
		CORP:              headers.Get("Cross-Origin-Resource-Policy"),
		COEP:              headers.Get("Cross-Origin-Embedder-Policy"),
		XXSSProtection:    headers.Get("X-XSS-Protection"),
	}
}
