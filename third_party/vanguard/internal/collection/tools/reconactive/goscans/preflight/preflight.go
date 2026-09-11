package preflight

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DiscoveryScripts are the NSE scripts upstream GoScans discovery forces onto
// every nmap invocation. Upstream prunes unavailable ones only inside its own
// setup path, which this integration never calls because that path also runs
// setcap and needs elevation. Nothing prunes them at scan time, so nmap fails the
// whole scan if one is missing, and checking them here is the only thing standing
// between a stripped nmap package and a scan that dies on its first target.
var DiscoveryScripts = []string{
	"smb-os-discovery",
	"ssl-cert",
	"http-ntlm-info",
	"rdp-ntlm-info",
	"telnet-ntlm-info",
	"smtp-ntlm-info",
	"pop3-ntlm-info",
	"imap-ntlm-info",
	"ms-sql-ntlm-info",
	"rdp-enum-encryption",
}

// MinPythonVersion is the lowest interpreter SSLyze 6.x supports.
var MinPythonVersion = Version{Major: 3, Minor: 10}

// GoScansVersion is the vendored upstream GoScans release this integration is
// built against. It lives here because this package already encodes what that
// release requires of a machine - the forced script list above is its list - and
// because a scan's record has to name the library that decided what to run, not
// only the binaries it ran. A test asserts it still matches the module the build
// actually uses, so it cannot drift into a comfortable lie.
const GoScansVersion = "v1.2.0"

// Options are the read-only checks to perform. Nothing here installs, upgrades,
// or grants anything: every command is a version or capability query against a
// binary deployment already placed on the machine.
type Options struct {
	// NmapPath is the configured nmap executable, resolved through PATH when it is
	// a bare name.
	NmapPath string
	// CheckTLS additionally verifies the Python interpreter and SSLyze. It is off
	// when the TLS module is disabled, so a scan that never runs SSLyze does not
	// require it to exist.
	CheckTLS bool
	// PythonPath is the interpreter that must be able to run "python -m sslyze".
	PythonPath string
	// SslyzeVersion is the exact version deployment pinned, for example "6.3.1". An
	// empty value accepts any version that satisfies the upstream minimum.
	SslyzeVersion string
	// Truststore is an optional additional CA bundle. Empty skips the check.
	Truststore string
	// CommandTimeout bounds each individual preflight command.
	CommandTimeout time.Duration
	// MaxOutputBytes caps what is read from one command, so a runaway binary cannot
	// grow the scan process.
	MaxOutputBytes int

	// run executes one command and returns its combined output. Nil uses the real
	// process runner; tests substitute a fake so no binary has to exist.
	run runner
	// lookPath resolves an executable. Nil uses exec.LookPath.
	lookPath func(string) (string, error)
}

// runner executes one preflight command.
type runner func(ctx context.Context, name string, args ...string) (string, error)

// Result records what preflight resolved, so a scan can report the exact runtime
// it used rather than the one it was configured with.
type Result struct {
	// NmapPath is the resolved absolute nmap executable.
	NmapPath string
	// NmapVersion is the detected nmap version.
	NmapVersion string
	// PythonPath is the resolved interpreter, empty when TLS is not checked.
	PythonPath string
	// PythonVersion is the detected interpreter version.
	PythonVersion string
	// SslyzeVersion is the detected SSLyze version.
	SslyzeVersion string
	// Truststore is the verified additional CA bundle, empty when none.
	Truststore string
}

// Run performs every enabled check and reports all problems at once, so an
// operator fixes the deployment in one pass instead of one failure per run.
//
// It never installs a package, invokes pip or a package manager, changes
// capabilities, escalates privileges, or downloads anything. A dependency that is
// missing or the wrong version is reported with its path, what was found, what is
// required, and what to do about it.
func Run(ctx context.Context, o Options) (Result, error) {
	o = o.withDefaults()

	var result Result
	var problems []string

	result.NmapPath, result.NmapVersion, problems = o.checkNmap(ctx, problems)
	if result.NmapPath != "" {
		problems = o.checkScripts(ctx, result.NmapPath, problems)
	}
	if o.CheckTLS {
		result.PythonPath, result.PythonVersion, result.SslyzeVersion, problems = o.checkSslyze(ctx, problems)
	}
	result.Truststore, problems = o.checkTruststore(problems)

	if len(problems) > 0 {
		return result, fmt.Errorf("goscans preflight failed:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return result, nil
}

// ResolveNmap resolves an nmap executable and records its version without
// applying GoScans-specific NSE script requirements. It is used when portscan is
// enabled but GoScans is not.
func ResolveNmap(ctx context.Context, path string, timeout time.Duration, maxOutputBytes int) (Result, error) {
	o := Options{NmapPath: path, CommandTimeout: timeout, MaxOutputBytes: maxOutputBytes}.withDefaults()
	resolved, version, problems := o.checkNmap(ctx, nil)
	result := Result{NmapPath: resolved, NmapVersion: version}
	if len(problems) > 0 {
		return result, fmt.Errorf("nmap preflight failed:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return result, nil
}

// withDefaults fills the injectable hooks and the bounds.
func (o Options) withDefaults() Options {
	if o.run == nil {
		o.run = execRunner(o.CommandTimeout, o.MaxOutputBytes)
	}
	if o.lookPath == nil {
		o.lookPath = exec.LookPath
	}
	return o
}

// checkNmap resolves the executable and reads its version.
func (o Options) checkNmap(ctx context.Context, problems []string) (path, version string, out []string) {
	resolved, err := o.lookPath(o.NmapPath)
	if err != nil {
		return "", "", append(problems, fmt.Sprintf(
			"nmap %q was not found (install nmap or set tools.goscans.nmap.path; do not rely on the scan to install it): %v",
			o.NmapPath, err))
	}

	stdout, err := o.run(ctx, resolved, "--version")
	if err != nil {
		return resolved, "", append(problems, fmt.Sprintf("nmap %q could not be executed: %v", resolved, err))
	}
	version = parseNmapVersion(stdout)
	if version == "" {
		return resolved, "", append(problems, fmt.Sprintf(
			"nmap %q did not report a parsable version (got %q)", resolved, firstLine(stdout)))
	}
	return resolved, version, problems
}

// checkScripts verifies that every NSE script upstream discovery forces is
// installed. The whole list is asked for once; only when that fails does it fall
// back to naming the individual offenders, so the common case costs one process.
func (o Options) checkScripts(ctx context.Context, nmapPath string, problems []string) []string {
	if _, err := o.run(ctx, nmapPath, "--script-help="+strings.Join(DiscoveryScripts, ",")); err == nil {
		return problems
	}

	var missing []string
	for _, script := range DiscoveryScripts {
		if _, err := o.run(ctx, nmapPath, "--script-help="+script); err != nil {
			missing = append(missing, script)
		}
	}
	if len(missing) == 0 {
		// The combined query failed for a reason other than a missing script, which
		// is still a problem worth naming rather than passing over.
		return append(problems, fmt.Sprintf(
			"nmap %q rejected the required NSE script list although every script resolves individually", nmapPath))
	}
	return append(problems, fmt.Sprintf(
		"nmap %q is missing NSE scripts required by goscans discovery: %s (install the full nmap scripts package; every scan requests all of them and nmap aborts when one is absent)",
		nmapPath, strings.Join(missing, ", ")))
}

// checkSslyze resolves the interpreter and verifies both it and the SSLyze module.
func (o Options) checkSslyze(ctx context.Context, problems []string) (path, python, sslyze string, out []string) {
	resolved, err := o.lookPath(o.PythonPath)
	if err != nil {
		return "", "", "", append(problems, fmt.Sprintf(
			"python %q was not found (deploy the pinned goscans SSLyze environment or disable tools.goscans.ssl): %v",
			o.PythonPath, err))
	}

	stdout, err := o.run(ctx, resolved, "--version")
	if err != nil {
		return resolved, "", "", append(problems, fmt.Sprintf("python %q could not be executed: %v", resolved, err))
	}
	python = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(firstLine(stdout)), "Python "))
	pv, perr := ParseVersion(python)
	switch {
	case perr != nil:
		problems = append(problems, fmt.Sprintf("python %q did not report a parsable version (got %q)", resolved, python))
	case pv.Less(MinPythonVersion):
		problems = append(problems, fmt.Sprintf(
			"python %q is version %s but SSLyze needs at least %s (deploy a newer interpreter)",
			resolved, python, MinPythonVersion))
	}

	help, err := o.run(ctx, resolved, "-m", "sslyze", "--help")
	if err != nil {
		return resolved, python, "", append(problems, fmt.Sprintf(
			"%q could not run \"-m sslyze\" (install SSLyze into that environment; the scan never installs it): %v",
			resolved, err))
	}
	sslyze = parseSslyzeVersion(help)
	if sslyze == "" {
		return resolved, python, "", append(problems, fmt.Sprintf(
			"%q ran SSLyze but its help output carried no version", resolved))
	}
	if o.SslyzeVersion != "" && sslyze != o.SslyzeVersion {
		problems = append(problems, fmt.Sprintf(
			"SSLyze at %q is version %s but deployment pinned %s (align the environment with the pinned version)",
			resolved, sslyze, o.SslyzeVersion))
	}
	return resolved, python, sslyze, problems
}

// checkTruststore verifies the optional additional CA bundle is a readable file.
func (o Options) checkTruststore(problems []string) (path string, out []string) {
	path = strings.TrimSpace(o.Truststore)
	if path == "" {
		return "", problems
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", append(problems, fmt.Sprintf("sslyze trust store %q is not readable: %v", path, err))
	}
	if !info.Mode().IsRegular() {
		return "", append(problems, fmt.Sprintf("sslyze trust store %q is not a regular file", path))
	}
	f, err := os.Open(path)
	if err != nil {
		return "", append(problems, fmt.Sprintf("sslyze trust store %q cannot be opened by the scan user: %v", path, err))
	}
	_ = f.Close()
	return path, problems
}

// execRunner returns a runner that executes a real command with a deadline and a
// bounded output buffer, and never goes through a shell.
func execRunner(timeout time.Duration, maxBytes int) runner {
	return func(ctx context.Context, name string, args ...string) (string, error) {
		if timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		cmd := exec.CommandContext(ctx, name, args...)
		buf := &capped{limit: maxBytes}
		cmd.Stdout = buf
		cmd.Stderr = buf
		err := cmd.Run()
		return buf.String(), err
	}
}

// capped is a writer that keeps at most limit bytes and silently discards the
// rest, so an unexpectedly chatty binary cannot grow the scan process.
type capped struct {
	limit int
	buf   bytes.Buffer
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		c.buf.Write(p[:room])
	}
	return len(p), nil
}

func (c *capped) String() string { return c.buf.String() }

// parseNmapVersion pulls the version out of "Nmap version 7.94 ( https://nmap.org )".
func parseNmapVersion(out string) string {
	const marker = "Nmap version "
	i := strings.Index(out, marker)
	if i < 0 {
		return ""
	}
	rest := out[i+len(marker):]
	if j := strings.IndexAny(rest, " \t\r\n"); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// parseSslyzeVersion pulls the version out of the SSLyze help banner. It reads the
// same "SSLyze version X" marker the upstream scanner reads, so preflight and the
// scanner never disagree about which version is installed.
func parseSslyzeVersion(help string) string {
	const marker = "SSLyze version "
	i := strings.Index(help, marker)
	if i < 0 {
		return ""
	}
	rest := help[i+len(marker):]
	if j := strings.IndexAny(rest, " \t\r\n"); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// firstLine returns the first line of out, for error messages.
func firstLine(out string) string {
	if i := strings.IndexAny(out, "\r\n"); i >= 0 {
		return out[:i]
	}
	return out
}

// Version is a dotted numeric version, enough to compare interpreter and tool
// versions without a dependency.
type Version struct {
	Major int
	Minor int
	Patch int
}

// String renders the version as "major.minor.patch".
func (v Version) String() string {
	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
}

// Less reports whether v is older than other.
func (v Version) Less(other Version) bool {
	if v.Major != other.Major {
		return v.Major < other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor < other.Minor
	}
	return v.Patch < other.Patch
}

// ParseVersion reads a leading dotted numeric version, ignoring any suffix such as
// "rc1" that release candidates carry.
func ParseVersion(s string) (Version, error) {
	fields := strings.SplitN(strings.TrimSpace(s), ".", 4)
	if len(fields) == 0 || fields[0] == "" {
		return Version{}, fmt.Errorf("empty version")
	}
	var v Version
	targets := []*int{&v.Major, &v.Minor, &v.Patch}
	for i, target := range targets {
		if i >= len(fields) {
			break
		}
		n, err := strconv.Atoi(numericPrefix(fields[i]))
		if err != nil {
			if i == 0 {
				return Version{}, fmt.Errorf("version %q is not numeric", s)
			}
			break
		}
		*target = n
	}
	return v, nil
}

// numericPrefix returns the leading digits of s.
func numericPrefix(s string) string {
	for i, r := range s {
		if r < '0' || r > '9' {
			return s[:i]
		}
	}
	return s
}
