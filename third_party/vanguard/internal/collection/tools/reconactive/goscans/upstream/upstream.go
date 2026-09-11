package upstream

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/siemens/GoScans/banner"
	"github.com/siemens/GoScans/discovery"
	"github.com/siemens/GoScans/ssh"
	"github.com/siemens/GoScans/ssl"
	"github.com/siemens/GoScans/utils"
	"github.com/siemens/GoScans/webcrawler"
	"github.com/siemens/GoScans/webenum"
)

// Logger is the upstream logger interface. Every GoScans constructor takes one,
// so the actor passes an adapter that turns upstream log lines into bounded tool
// events instead of letting GoScans write anywhere on its own.
type Logger = utils.Logger

type (
	// DiscoveryResult is the upstream discovery output for one scan.
	DiscoveryResult = discovery.Result
	// DiscoveryHost is the unit subordinate modules are selected from.
	DiscoveryHost = discovery.Host
	// DiscoveryService carries the transport in Protocol, which is what module
	// selection keys on, and the TLS hint in Tunnel.
	DiscoveryService = discovery.Service
	// DiscoveryScript carries raw NSE output per host or port.
	DiscoveryScript = discovery.Script
)

// Every upstream module result carries a Status string and an Exception flag
// meaning the payload must be discarded, alongside the module's own data shape.
type (
	// BannerResult is the upstream banner scan output.
	BannerResult = banner.Result
	// BannerData holds the raw bytes each banner probe returned.
	BannerData = banner.ResultData
	// SSLResult is the upstream TLS scan output, one entry per virtual host.
	SSLResult = ssl.Result
	// SSLData is one virtual host's TLS assessment.
	SSLData = ssl.Data
	// SSLIssues is the flat set of TLS vulnerability flags SSLyze reported.
	SSLIssues = ssl.Issues
	// SSLCipher is one accepted cipher suite with its full algorithm breakdown.
	SSLCipher = ssl.Cipher
	// SSLChain is one presented certificate deployment and its validation result.
	SSLChain = ssl.Chain
	// SSLCertificate is one parsed X.509 certificate of a chain.
	SSLCertificate = ssl.Certificate
	// SSLSettings are the server's protocol-level configuration choices.
	SSLSettings = ssl.Settings
	// SSLCurves are the elliptic curves the server accepted and rejected.
	SSLCurves = ssl.Curves
	// SSLEllipticCurve is one named curve.
	SSLEllipticCurve = ssl.EllipticCurve
)

// Upstream models each TLS algorithm slot as a small integer enum with a generated
// String method, not as a string. The distinction matters at every use: converting
// one of these to a string directly yields a control character rather than an
// algorithm name, so a reader must go through String. They are aliased here so a
// caller can name the type it is filling in without importing the library.
type (
	// SSLProtocol is an SSL/TLS version.
	SSLProtocol = ssl.Protocol
	// SSLKeyExchange is a key exchange algorithm.
	SSLKeyExchange = ssl.KeyExchange
	// SSLAuthentication is an authentication algorithm.
	SSLAuthentication = ssl.Authentication
	// SSLEncryption is a symmetric encryption algorithm.
	SSLEncryption = ssl.Encryption
	// SSLMac is a message authentication code algorithm.
	SSLMac = ssl.Mac
	// SSLPublicKey is a public key algorithm.
	SSLPublicKey = ssl.PublicKey
	// SSLSignatureAlgorithm is a certificate signature algorithm.
	SSLSignatureAlgorithm = ssl.SignatureAlgorithm
	// SSLSignatureHash is a certificate signature hash algorithm.
	SSLSignatureHash = ssl.SignatureHash
)

// A representative slice of the upstream algorithm enums, re-exported so a caller
// can build a fixture without importing the library itself. Only the values the
// reduction is exercised against are aliased: the door exists to keep the import in
// one file, not to mirror every constant upstream defines.
const (
	// SSLProtocolTLS10, SSLProtocolTLS12, and SSLProtocolTLS13 are TLS versions.
	SSLProtocolTLS10 = ssl.Tlsv1_0
	SSLProtocolTLS12 = ssl.Tlsv1_2
	SSLProtocolTLS13 = ssl.Tlsv1_3
	// Key exchange algorithms. Both the ephemeral and the static elliptic-curve
	// values are aliased because the reduction has to be exercised against a suite
	// the upstream table types as static when its name says ephemeral, which is the
	// case that makes reading the name rather than the table necessary.
	SSLKeyExchangeRSA   = ssl.KEX_RSA
	SSLKeyExchangeDHE   = ssl.KEX_DHE
	SSLKeyExchangeECDH  = ssl.KEX_ECDH
	SSLKeyExchangeECDHE = ssl.KEX_ECDHE
	// SSLKeyExchangeTLS13 is the placeholder upstream reports for a TLS 1.3 suite,
	// whose key exchange is negotiated outside the suite.
	SSLKeyExchangeTLS13 = ssl.KEX_TLSv1_3
	// SSLAuthenticationRSA is an authentication algorithm.
	SSLAuthenticationRSA = ssl.AUTH_RSA
	// SSLEncryptionRC4 is a symmetric encryption algorithm.
	SSLEncryptionRC4 = ssl.ENC_RC4
	// SSLMacSHA is a message authentication code algorithm.
	SSLMacSHA = ssl.MAC_SHA1
	// SSLPublicKeyRSA is a public key algorithm.
	SSLPublicKeyRSA = ssl.PUB_K_RSA
	// SSLSignatureAlgorithmRSA is a certificate signature algorithm.
	SSLSignatureAlgorithmRSA = ssl.SIG_A_RSA
	// SSLSignatureHashSHA256 is a certificate signature hash algorithm.
	SSLSignatureHashSHA256 = ssl.SIG_H_SHA256
)

type (
	// SSHResult is the upstream SSH scan output.
	SSHResult = ssh.Result
	// SSHData holds the SSH algorithm and protocol choices.
	SSHData = ssh.ResultData
	// WebCrawlerResult is the upstream crawl output, one entry per virtual host.
	WebCrawlerResult = webcrawler.Result
	// WebCrawlerCrawl is one virtual host's crawl.
	WebCrawlerCrawl = webcrawler.CrawlResult
	// WebCrawlerPage is one crawled page.
	WebCrawlerPage = webcrawler.Page
	// WebEnumResult is the upstream enumeration output.
	WebEnumResult = webenum.Result
	// WebEnumItem is one enumeration probe that matched.
	WebEnumItem = webenum.EnumItem
)

// Runner interfaces are the whole upstream surface the actor drives. They exist so
// tests can substitute fakes without a network, a Python interpreter, or an nmap
// binary, and so the cancellation difference between modules is visible in the
// type rather than buried in upstream documentation: only the four runners with
// SetContext can be interrupted.
type (
	// DiscoveryRunner wraps the nmap-backed discovery scanner. It has no context
	// setter: the only lever is the Run timeout, and the actor must wait it out.
	DiscoveryRunner interface {
		Run(timeout time.Duration) *DiscoveryResult
	}
	// BannerRunner wraps the banner scanner. It has neither a context nor a Run
	// timeout; its bound is the dial and receive timeout given at construction.
	BannerRunner interface {
		Run() *BannerResult
	}
	// SSLRunner wraps the SSLyze-backed TLS scanner. Cancelling the context kills
	// the SSLyze child process.
	SSLRunner interface {
		SetContext(ctx context.Context)
		Run(timeout time.Duration) *SSLResult
	}
	// SSHRunner wraps the SSH scanner.
	SSHRunner interface {
		SetContext(ctx context.Context)
		Run(timeout time.Duration) *SSHResult
	}
	// WebCrawlerRunner wraps the web crawler.
	WebCrawlerRunner interface {
		SetContext(ctx context.Context)
		Run(timeout time.Duration) *WebCrawlerResult
	}
	// WebEnumRunner wraps the web enumerator.
	WebEnumRunner interface {
		SetContext(ctx context.Context)
		Run(timeout time.Duration) *WebEnumResult
	}
)

// DiscoveryRequest is the complete input to one discovery scan. Everything the
// upstream constructor accepts and this integration deliberately does not use
// (LDAP credentials, blacklists, OT scanning) is absent here by construction
// rather than passed empty at each call site.
type DiscoveryRequest struct {
	// Targets are the addresses handed to nmap, already scope approved.
	Targets []string
	// NmapPath is the nmap executable to run.
	NmapPath string
	// NmapArgs are the raw nmap arguments, prepended to the upstream mandatory set.
	NmapArgs []string
	// DomainOrder ranks candidate domains by plausibility so discovery can pick the
	// most likely DNS name for a host. Order is significant.
	DomainOrder []string
	// DialTimeout bounds the post-processing connections discovery makes to read
	// subject alternative names.
	DialTimeout time.Duration
}

// BannerRequest is the complete input to one banner collection.
type BannerRequest struct {
	// Target is the address to connect to.
	Target string
	// Port is the service port.
	Port int
	// Protocol is the transport, "tcp" or "udp". Only "tcp" is scheduled today.
	Protocol string
	// DialTimeout bounds connection establishment.
	DialTimeout time.Duration
	// ReceiveTimeout bounds waiting for the banner bytes.
	ReceiveTimeout time.Duration
}

// SSLRequest is the complete input to one TLS assessment.
type SSLRequest struct {
	// PythonPath is the interpreter that runs "python -m sslyze" on Linux, or the
	// SSLyze executable on Windows. The upstream constructor probes its version,
	// which costs two process spawns per request.
	PythonPath string
	// Target is the address to assess.
	Target string
	// Port is the TLS port.
	Port int
	// Vhosts are the server names to assess in addition to the target itself.
	Vhosts []string
	// AdditionalTruststore is an optional extra CA bundle file. Upstream always
	// applies the SSLyze default CA set as well; this only adds to it. Empty means
	// the default set alone decides trust.
	AdditionalTruststore string
}

// SSHRequest is the complete input to one SSH assessment.
type SSHRequest struct {
	// Target is the address to connect to.
	Target string
	// Port is the SSH port.
	Port int
	// DialTimeout bounds connection establishment.
	DialTimeout time.Duration
}

// WebCrawlerRequest is the complete input to one crawl. OutputFolder is mandatory
// even though downloads are disabled: the upstream constructor creates a download
// URL list inside it and fails if it cannot.
type WebCrawlerRequest struct {
	// Target is the address to crawl.
	Target string
	// Port is the web port.
	Port int
	// Vhosts are the server names to crawl in addition to the target itself.
	Vhosts []string
	// HTTPS selects the scheme.
	HTTPS bool
	// Depth is the maximum link depth followed from the entry page.
	Depth int
	// MaxThreads is the crawler's own request parallelism for this one job.
	MaxThreads int
	// OutputFolder is the actor-owned temporary directory for this job.
	OutputFolder string
	// UserAgent is the request user agent.
	UserAgent string
	// RequestTimeout bounds a single HTTP request.
	RequestTimeout time.Duration
}

// WebEnumRequest is the complete input to one enumeration. ProbesFile must be a
// regular file; the upstream constructor rejects anything else.
type WebEnumRequest struct {
	// Target is the address to enumerate.
	Target string
	// Port is the web port.
	Port int
	// Vhosts are the server names to enumerate in addition to the target itself.
	Vhosts []string
	// HTTPS selects the scheme.
	HTTPS bool
	// ProbesFile is the materialized probe set for this run.
	ProbesFile string
	// ProbeRobots additionally derives probes from the target robots.txt.
	ProbeRobots bool
	// UserAgent is the request user agent.
	UserAgent string
	// RequestTimeout bounds a single HTTP request.
	RequestTimeout time.Duration
}

// Upstream constructs the GoScans scanners. The live implementation is the only
// place upstream constructors are called; everything else in this package works
// against the runner interfaces.
type Upstream interface {
	// Discovery builds the nmap-backed discovery scanner for one target set.
	Discovery(log Logger, req DiscoveryRequest) (DiscoveryRunner, error)
	// Banner builds a banner scanner for one service.
	Banner(log Logger, req BannerRequest) (BannerRunner, error)
	// SSL builds a TLS scanner for one service.
	SSL(log Logger, req SSLRequest) (SSLRunner, error)
	// SSH builds an SSH scanner for one service.
	SSH(log Logger, req SSHRequest) (SSHRunner, error)
	// WebCrawler builds a crawler for one web service.
	WebCrawler(log Logger, req WebCrawlerRequest) (WebCrawlerRunner, error)
	// WebEnum builds an enumerator for one web service.
	WebEnum(log Logger, req WebEnumRequest) (WebEnumRunner, error)
}

// New returns the Upstream that calls the pinned GoScans constructors. It is the
// only path from Vanguard into upstream code; tests substitute their own Upstream.
func New() Upstream { return liveUpstream{} }

// liveUpstream calls the pinned GoScans constructors.
type liveUpstream struct{}

// loadCiphersOnce guards the upstream TLS cipher table, which is process-global
// and lazily initialized. Without it the TLS parser cannot name a cipher and logs
// a warning per lookup, so it is primed before the first SSL scanner is built.
var loadCiphersOnce sync.Once

// Discovery builds a discovery scanner with no LDAP credentials, no blacklist, and
// GSSAPI disabled, which is what keeps upstream Active Directory enrichment from
// ever running. The scanner is returned without an OT scanner attached, and this
// package never calls EnableOtScanner.
func (liveUpstream) Discovery(log Logger, req DiscoveryRequest) (DiscoveryRunner, error) {
	s, err := discovery.NewScanner(
		log,
		req.Targets,
		req.NmapPath,
		req.NmapArgs,
		false, // nmapVersionAll: exhaustive version detection is far too slow for an external estate
		nil,   // nmapBlacklist: scope is enforced before a target ever reaches this actor
		"",    // nmapBlacklistFile
		req.DomainOrder,
		"",   // ldapServer
		"",   // ldapDomain
		"",   // ldapUser
		"",   // ldapPassword
		true, // disableGssapi
		nil,  // excludeDomains
		req.DialTimeout,
	)
	if err != nil {
		return nil, fmt.Errorf("discovery scanner: %w", err)
	}
	return s, nil
}

// Banner builds a banner scanner.
func (liveUpstream) Banner(log Logger, req BannerRequest) (BannerRunner, error) {
	s, err := banner.NewScanner(log, req.Target, req.Port, req.Protocol, req.DialTimeout, req.ReceiveTimeout)
	if err != nil {
		return nil, fmt.Errorf("banner scanner: %w", err)
	}
	return s, nil
}

// SSL builds a TLS scanner. The upstream constructor probes the interpreter and
// the SSLyze version here, so a missing or too-old runtime surfaces as a
// construction error rather than as an empty result.
func (liveUpstream) SSL(log Logger, req SSLRequest) (SSLRunner, error) {
	loadCiphersOnce.Do(func() { ssl.LoadCiphers(log) })
	s, err := ssl.NewScanner(
		log,
		req.PythonPath,
		req.AdditionalTruststore,
		req.Target,
		req.Port,
		req.Vhosts,
	)
	if err != nil {
		return nil, fmt.Errorf("ssl scanner: %w", err)
	}
	return s, nil
}

// SSH builds an SSH scanner.
func (liveUpstream) SSH(log Logger, req SSHRequest) (SSHRunner, error) {
	s, err := ssh.NewScanner(log, req.Target, req.Port, req.DialTimeout)
	if err != nil {
		return nil, fmt.Errorf("ssh scanner: %w", err)
	}
	return s, nil
}

// WebCrawler builds a crawler with downloads disabled, no credentials, and no
// proxy. storeRoot is on so the entry page is always part of the result; query
// string following is off, because it is what turns a parameterized site into an
// unbounded crawl.
func (liveUpstream) WebCrawler(log Logger, req WebCrawlerRequest) (WebCrawlerRunner, error) {
	s, err := webcrawler.NewScanner(
		log,
		req.Target,
		req.Port,
		req.Vhosts,
		req.HTTPS,
		req.Depth,
		req.MaxThreads,
		false, // followQS
		true,  // storeRoot
		false, // download
		req.OutputFolder,
		"", // ntlmDomain
		"", // ntlmUser
		"", // ntlmPassword
		req.UserAgent,
		"", // proxy
		req.RequestTimeout,
	)
	if err != nil {
		return nil, fmt.Errorf("webcrawler scanner: %w", err)
	}
	return s, nil
}

// WebEnum builds an enumerator with no credentials and no proxy.
func (liveUpstream) WebEnum(log Logger, req WebEnumRequest) (WebEnumRunner, error) {
	s, err := webenum.NewScanner(
		log,
		req.Target,
		req.Port,
		req.Vhosts,
		req.HTTPS,
		"", // ntlmDomain
		"", // ntlmUser
		"", // ntlmPassword
		req.ProbesFile,
		req.ProbeRobots,
		req.UserAgent,
		"", // proxy
		req.RequestTimeout,
	)
	if err != nil {
		return nil, fmt.Errorf("webenum scanner: %w", err)
	}
	return s, nil
}
