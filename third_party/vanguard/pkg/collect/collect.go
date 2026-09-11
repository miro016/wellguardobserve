package collect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"

	"github.com/velgard-sk/vanguard/internal/buildid"
)

// Credentials are the provider API credentials a collection may use. Every field
// is optional here and checked against the scan profile when a run starts: a
// profile that enables a provider requires that provider's credential, and a
// credential for a disabled provider is simply unused.
//
// They are passed as data rather than read from the process environment, so an
// embedding application can hold them wherever it already holds its secrets. Use
// [CredentialsFromEnv] to opt into the command-line convention instead.
type Credentials struct {
	// Breach is the Have I Been Pwned API key.
	Breach string
	// Censys is the Censys API key.
	Censys string
	// CensysOrgID is the Censys organization ID that key belongs to.
	CensysOrgID string
	// VirusTotal is the VirusTotal API key.
	VirusTotal string
	// WebSearch is the SerpAPI key used for search-engine enumeration.
	WebSearch string
	// Shodan is the Shodan API key.
	Shodan string
	// Netlas is the Netlas API key.
	Netlas string
	// Certspotter is the SSLMate Cert Spotter API key.
	Certspotter string
}

// Environment variable names [CredentialsFromEnv] reads. They are the same names
// the vanguard-collect command uses, so a process configured for the command can
// be moved to the library without renaming anything.
const (
	EnvBreach      = "HIBP_API_KEY"
	EnvCensys      = "CENSYS_API_KEY"
	EnvCensysOrgID = "CENSYS_ORG_ID"
	EnvVirusTotal  = "VIRUSTOTAL_API_KEY"
	EnvWebSearch   = "SERPAPI_API_KEY"
	EnvShodan      = "SHODAN_API_KEY"
	EnvNetlas      = "NETLAS_API_KEY"
	EnvCertspotter = "CERTSPOTTER_API_KEY"
)

// CredentialsFromEnv reads the credentials from the process environment, using the
// same variable names the vanguard-collect command uses. It is the one place in
// this package that looks at the environment, and it does so only because a caller
// asked: a library that read secrets implicitly would make an embedding
// application's behavior depend on how it happened to be launched.
func CredentialsFromEnv() Credentials {
	return Credentials{
		Breach:      os.Getenv(EnvBreach),
		Censys:      os.Getenv(EnvCensys),
		CensysOrgID: os.Getenv(EnvCensysOrgID),
		VirusTotal:  os.Getenv(EnvVirusTotal),
		WebSearch:   os.Getenv(EnvWebSearch),
		Shodan:      os.Getenv(EnvShodan),
		Netlas:      os.Getenv(EnvNetlas),
		Certspotter: os.Getenv(EnvCertspotter),
	}
}

// Options is everything one collection needs. Every input is a value: no path is
// resolved from the environment, no default is read from a configuration file
// outside the capture, and nothing is inferred from the process.
type Options struct {
	// EngagementYAML is the exact engagement document: the customer, the authorized
	// scope, and the scan root. It is required, is validated as given, and is
	// snapshotted verbatim into the capture, so the capture states what was actually
	// authorized rather than what a file happened to contain later.
	EngagementYAML []byte
	// ProfileYAML is the exact scan profile document: which phases and tools run and
	// how they are tuned. It is required, and is snapshotted into the capture beside
	// the engagement.
	ProfileYAML []byte
	// Credentials are the provider API credentials the profile's enabled providers
	// need. A profile that enables none needs none.
	Credentials Credentials
	// DestinationDir is the exact collection directory to write. It is required, and
	// it is the root of the collection: Vanguard adds no enclosing directory of its
	// own, so what is written is what this path names.
	//
	// It must be missing or empty. Nothing there is ever deleted, renamed, or merged:
	// a caller that wants to replace disposable output empties or chooses the
	// destination itself, because only the caller knows whether those bytes matter.
	// A collection directory records one collection, so collecting again means
	// naming another destination rather than reopening this one.
	//
	// A directory must be used by one collection at a time. Vanguard checks the
	// destination but takes no lock, so exclusive ownership stays the caller's.
	DestinationDir string
	// ApplicationName is the name recorded as the collector in the capture's
	// provenance, for example the embedding program's command name. It is required
	// and is a name the caller chooses rather than os.Args[0], so a renamed or
	// symlinked executable still reports the program it implements.
	ApplicationName string
	// Version is the identifier recorded beside ApplicationName: the caller's answer
	// to "which build produced this capture". It is required, because a capture whose
	// producer cannot be named is evidence nobody can reproduce or re-judge.
	//
	// It is opaque. Vanguard stores it verbatim and never parses it, so a caller
	// chooses what it means: its own release, a Vanguard release, a commit, or a
	// composite such as "host=v9.8.7;vanguard=v0.5.0" naming both. Only the caller
	// knows which of those describes the build it shipped.
	Version string
	// Progress is an optional writer for human-readable progress. A nil writer makes
	// the run silent, which is the default for an embedded library. The text is for
	// operators and its wording is not stable; the capture's event streams are the
	// machine-readable result. The writer stays the caller's and is never closed
	// here.
	Progress io.Writer
}

// Collector runs one collection. It is created by [New], holds its own copy of
// every input, and runs exactly once.
type Collector struct {
	// engagementYAML and profileYAML are this collector's own copies of the caller's
	// documents, so a caller reusing its buffers cannot change a run in flight or the
	// snapshots it writes.
	engagementYAML []byte
	profileYAML    []byte
	credentials    Credentials
	destinationDir string
	progress       io.Writer
	// collector is the identity recorded for this execution, fixed in New, before
	// anything is contacted, because a capture nobody can attribute is worth less
	// than no capture. The manifest and the environment event are both written from
	// this one value, so they cannot disagree.
	collector buildid.Identity
	// started guards the single-run rule. One instance owns one collection directory
	// for the length of one run, and a second run against it would write into a
	// collection whose state the first run is still deciding.
	started atomic.Bool
}

// New validates the options and prepares one collection. It performs no target or
// provider traffic, executes no external tool, and writes no file: everything it
// rejects, it rejects before the run could have had an effect.
//
// It fails when the caller named no version, which is the same rule the
// vanguard-collect command applies before it opens a sink: an unattributable
// capture is worth less than no capture.
func New(options Options) (*Collector, error) {
	if len(options.EngagementYAML) == 0 {
		return nil, errors.New("collect: EngagementYAML is required")
	}
	if len(options.ProfileYAML) == 0 {
		return nil, errors.New("collect: ProfileYAML is required")
	}
	if strings.TrimSpace(options.DestinationDir) == "" {
		return nil, errors.New("collect: DestinationDir is required")
	}
	if strings.TrimSpace(options.ApplicationName) == "" {
		return nil, errors.New("collect: ApplicationName is required; it names the collector in the capture's provenance")
	}
	collector, err := buildid.Current(options.ApplicationName, options.Version)
	if err != nil {
		return nil, fmt.Errorf("collect: %w; supply Options.Version with the identifier your release process uses", err)
	}
	return &Collector{
		engagementYAML: append([]byte(nil), options.EngagementYAML...),
		profileYAML:    append([]byte(nil), options.ProfileYAML...),
		credentials:    options.Credentials,
		destinationDir: options.DestinationDir,
		progress:       options.Progress,
		collector:      collector,
	}, nil
}

// Run executes the collection and returns when the capture is complete or the
// error that stopped it. Cancelling ctx stops the run: the capture keeps whatever
// it had already durably written, and the interrupted execution is recorded as
// interrupted, which is what marks the collection as one nobody should read as
// complete.
//
// One collector runs once. A second call, or a concurrent one, is refused rather
// than allowed to write into a capture whose state the first run still owns.
func (c *Collector) Run(ctx context.Context) error {
	if !c.started.CompareAndSwap(false, true) {
		return errors.New("collect: this collector has already been run; create another for another capture")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.run(ctx)
}

// RuntimeInfo is the external runtime a scan profile needs, as resolved on this
// machine: the absolute paths and versions actually found, which differ from what
// a configuration named more often than is comfortable.
type RuntimeInfo struct {
	// Required reports whether the profile enables any tool that needs an external
	// runtime at all. A passive profile needs none, and empty fields below are then a
	// pass rather than a gap.
	Required bool
	// NmapPath is the nmap executable that was found.
	NmapPath string
	// NmapVersion is the version that executable reported.
	NmapVersion string
	// PythonPath is the interpreter used to run SSLyze, empty when TLS scanning is
	// disabled.
	PythonPath string
	// PythonVersion is the version that interpreter reported.
	PythonVersion string
	// SslyzeVersion is the pinned SSLyze version that interpreter resolved.
	SslyzeVersion string
	// Truststore is the CA bundle the TLS checks resolved.
	Truststore string
	// UDPVerified reports that the profile asked for a UDP port-scan pass and that
	// the resolved nmap was proven able to open the raw socket it needs, as the
	// user this check ran as. It is false when the profile enabled no UDP pass; an
	// enabled pass that could not be proven fails preflight instead of reporting.
	UDPVerified bool
	// UDPPrivilegedFlag reports whether that nmap needed the --privileged flag to
	// accept a UDP scan here, which is what a file capability rather than root
	// ownership produces. It is what the scan builds its arguments from.
	UDPPrivilegedFlag bool
}

// PreflightReport is what a collection-runtime preflight resolved: who would
// collect, and whether this machine can. It is the read-only form of the checks a
// run performs at startup, so a deployment can prove a machine is ready before a
// scan is started on it.
type PreflightReport struct {
	// Collector is the identity a collection started with these options would
	// record: the caller's application name and the caller's version, checked by the
	// same rule [New] applies. It is echoed rather than resolved, so a deployment can
	// see exactly what its captures will say.
	Collector CollectorInfo
	// Runtime is the external runtime the given profile needs, as found here.
	Runtime RuntimeInfo
}

// CollectorInfo is the identity a collection would record: the name and version its
// caller supplied. Both are the caller's values; this package constructs neither.
type CollectorInfo struct {
	// Name is the application name the caller chose, as it would appear in the
	// capture's provenance.
	Name string
	// Version is the caller's opaque identifier for the build, recorded verbatim.
	Version string
}

// PreflightOptions is what a preflight check needs: the profile that selects the
// external runtime, and the identity a collection with the same options would
// record.
type PreflightOptions struct {
	// ProfileYAML is the exact scan profile document. It is required, because it is
	// the profile that decides which external runtime has to be present.
	ProfileYAML []byte
	// ApplicationName is the name a collection would record as its collector. It is
	// required and checked here for the same reason [Options.ApplicationName] is.
	ApplicationName string
	// Version is the identifier a collection would record beside ApplicationName. It
	// is required, and an empty one fails here exactly as it would fail a run, so a
	// deployment that would produce unattributable captures learns it at deploy time.
	Version string
}

// String renders the report as the operator-facing block a deployment log wants.
// Its wording is not a machine protocol; read the fields for that.
func (r PreflightReport) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "collector:  %s\n", orNone(r.Collector.Name))
	fmt.Fprintf(&b, "version:    %s\n", orNone(r.Collector.Version))
	if !r.Runtime.Required {
		b.WriteString("runtime:    none required by this profile\n")
		return b.String()
	}
	fmt.Fprintf(&b, "nmap:       %s (%s)\n", orNone(r.Runtime.NmapVersion), orNone(r.Runtime.NmapPath))
	fmt.Fprintf(&b, "python:     %s (%s)\n", orNone(r.Runtime.PythonVersion), orNone(r.Runtime.PythonPath))
	fmt.Fprintf(&b, "sslyze:     %s\n", orNone(r.Runtime.SslyzeVersion))
	fmt.Fprintf(&b, "cabundle:   %s\n", orNone(r.Runtime.Truststore))
	if r.Runtime.UDPVerified {
		fmt.Fprintf(&b, "udp scan:   raw socket verified (--privileged required: %s)\n", yesNo(r.Runtime.UDPPrivilegedFlag))
	} else {
		b.WriteString("udp scan:   not enabled by this profile\n")
	}
	return b.String()
}

// yesNo renders a report line's boolean as the word an operator reads.
func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// orNone keeps a report line from ending in a blank where an unresolved value
// would go.
func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// Preflight runs the startup checks a collection performs and reports what they
// resolved. It writes nothing, installs nothing, and never contacts an engagement
// target. Profiles without UDP enabled send no probe traffic; an enabled UDP pass
// adds one bounded nmap capability probe against 127.0.0.1:53.
//
// It takes the profile because the external runtime is selected by the profile's
// tools rather than by the engagement, and it takes no credentials: a machine is
// proven ready without being handed any secret. A profile that enables a paid
// provider is checked for its credential when a collection starts, not here.
//
// It applies the same identity rule [New] does, against the same options, so a
// deployment whose collector could not name itself fails at deploy time rather
// than after a scan has already spent an hour contacting targets.
func Preflight(ctx context.Context, options PreflightOptions) (PreflightReport, error) {
	if len(options.ProfileYAML) == 0 {
		return PreflightReport{}, errors.New("collect: a scan profile is required for preflight")
	}
	collector, err := buildid.Current(options.ApplicationName, options.Version)
	if err != nil {
		return PreflightReport{}, fmt.Errorf("collect: %w; supply the identifier your release process uses", err)
	}
	if err := ctx.Err(); err != nil {
		return PreflightReport{}, err
	}
	report, err := preflight(ctx, options.ProfileYAML)
	if err != nil {
		return PreflightReport{}, fmt.Errorf("collect: %w", err)
	}
	report.Collector = CollectorInfo{Name: collector.Name, Version: collector.Version}
	return report, nil
}
