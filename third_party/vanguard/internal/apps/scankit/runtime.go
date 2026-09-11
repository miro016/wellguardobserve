package scankit

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// udpProbeTarget is the only address the UDP capability probe ever contacts. It is
// the loopback interface, so the probe stays inside the machine's own network
// stack; nothing a scan is authorized against is touched by a startup check.
const udpProbeTarget = "127.0.0.1"

// udpProbePort is the single port the capability probe asks for. Its choice is
// irrelevant to the answer: the probe is checking whether the kernel lets nmap open
// a raw socket at all, not what is listening.
const udpProbePort = "53"

// udpProbeHostTimeout bounds nmap's own view of the probe, so a probe cannot outlive
// the startup check even if the process ignores its parent's deadline.
const udpProbeHostTimeout = "5s"

// UDPRuntime is what the UDP preflight resolved: the nmap that would run the UDP
// pass, and the one argv decision that cannot be made from a document because it
// depends on how privilege was granted on this machine.
//
// It is only populated when the profile enabled the UDP pass. A profile that did
// not ask for UDP resolves a zero value and starts no process.
type UDPRuntime struct {
	// NmapPath is the absolute executable the UDP pass will invoke. It is the same
	// binary the external-runtime check resolved and recorded, so what was proven
	// capable and what runs cannot drift apart.
	NmapPath string
	// NmapVersion is the version that executable reported.
	NmapVersion string
	// PrivilegedFlag records whether nmap needed --privileged to accept a UDP scan
	// on this machine. nmap decides it is unprivileged by looking at its effective
	// UID, so a binary that holds cap_net_raw as a file capability can refuse a scan
	// it is perfectly able to run. Rather than guessing, the probe tries the plain
	// invocation first and only then the flagged one, and the answer is recorded
	// here for the scan to build its argument list from.
	PrivilegedFlag bool
}

// udpRunner executes one preflight command and returns its combined output. It is
// the seam tests replace, so the capability decision can be exercised without nmap,
// without privileges, and on an operating system that has neither.
type udpRunner func(ctx context.Context, name string, args ...string) (string, error)

// resolveUDPRuntime verifies that the resolved nmap can actually perform the
// raw-socket UDP scan the profile asked for, and reports how it must be invoked.
//
// It is the one preflight check that sends a packet, and the exception is bounded
// on every axis: loopback only, one port, one host, its own host timeout, and its
// own command deadline. There is no way to answer the question without it. nmap
// reports insufficient privilege by refusing the scan type, not by any flag or
// version, so a static check would either trust the deployment or guess.
//
// An enabled UDP pass that cannot be performed is a hard failure here. There is no
// downgrade to a connect scan and no silent skip: a capture that quietly dropped
// the transport it was configured for would read as a clean UDP result.
func resolveUDPRuntime(ctx context.Context, nmapPath, nmapVersion string, run udpRunner) (UDPRuntime, error) {
	if nmapPath == "" {
		return UDPRuntime{}, fmt.Errorf("udp preflight failed:\n" +
			"  - tools.portscan.udp.enabled is true but no nmap executable was resolved (install nmap or disable the UDP pass)")
	}
	if run == nil {
		run = udpExecRunner(goScansPreflightCommandTimeout, goScansPreflightOutputCap)
	}

	var denials []string
	// Plain first, then --privileged: the flag tells nmap to stop consulting its
	// effective UID, which is what a file capability makes it get wrong. Trying it
	// first would hide a deployment that is actually running the scanner as root.
	for _, privileged := range []bool{false, true} {
		out, err := run(ctx, nmapPath, udpProbeArgs(privileged)...)
		switch {
		case err == nil && !udpPrivilegeDenied(out):
			return UDPRuntime{NmapPath: nmapPath, NmapVersion: nmapVersion, PrivilegedFlag: privileged}, nil
		case udpPrivilegeDenied(out):
			denials = append(denials, fmt.Sprintf("%s: %s", strings.Join(udpProbeArgs(privileged), " "), firstUDPProbeLine(out)))
		default:
			// A failure that is not about privilege is a broken deployment rather
			// than a missing capability, and saying so beats recommending setcap.
			return UDPRuntime{}, fmt.Errorf("udp preflight failed:\n"+
				"  - %s could not run a UDP scan: %v\n    output: %s", nmapPath, err, firstUDPProbeLine(out))
		}
	}
	return UDPRuntime{}, fmt.Errorf("udp preflight failed:\n"+
		"  - %s may not open a raw socket as this user, so tools.portscan.udp cannot run\n"+
		"    grant it with: setcap 'cap_net_raw,cap_net_admin+eip' %s\n"+
		"    (a package upgrade replaces the binary and drops the capability; re-run deployment)\n"+
		"    attempts: %s",
		nmapPath, nmapPath, strings.Join(denials, "; "))
}

// udpProbeArgs is the exact probe invocation. It is built here, once, from typed
// decisions rather than assembled from configuration, because a startup check that
// took its arguments from a file would be a way to make the scanner send whatever
// the file asked for.
func udpProbeArgs(privileged bool) []string {
	args := []string{"-sU", "-Pn", "-n", "--host-timeout", udpProbeHostTimeout, "-p", udpProbePort}
	if privileged {
		args = append(args, "--privileged")
	}
	return append(args, udpProbeTarget)
}

// udpPrivilegeDenied reports whether nmap refused the scan for lack of privilege
// rather than failing for another reason. nmap says so in prose on the way out, and
// the wording has been stable across releases; matching several phrasings keeps one
// reworded message from turning a clear denial into an unexplained failure.
func udpPrivilegeDenied(out string) bool {
	lower := strings.ToLower(out)
	for _, phrase := range []string{
		"requires root privileges",
		"requires raw socket access",
		"operation not permitted",
		"you requested a scan type which requires",
		"socket troubles in init_socket",
	} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// firstUDPProbeLine reduces a probe's output to one bounded line for an error
// message. The full output is not interesting: what an operator needs is the
// sentence nmap refused with.
func firstUDPProbeLine(out string) string {
	const maxLen = 200
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Starting Nmap") {
			continue
		}
		if len(line) > maxLen {
			return line[:maxLen] + "..."
		}
		return line
	}
	return "(no output)"
}

// udpExecRunner is the real command runner: no shell, its own deadline, and a
// bounded read, so a hung or chatty nmap cannot outlive or grow the startup check.
func udpExecRunner(timeout time.Duration, maxBytes int) udpRunner {
	return func(ctx context.Context, name string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if len(out) > maxBytes {
			out = out[:maxBytes]
		}
		return string(out), err
	}
}
