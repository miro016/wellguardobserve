package portscan

import (
	"log/slog"

	"github.com/velgard-sk/vanguard/internal/collection/tooleventlog"
)

const toolName = "portscan"

// healthCodeRuntimeFailed is the one health code this tool reports: a local
// scanner failure that prevented configured work. Which work was lost is said by
// the component, not by a second code, so a rollup groups every portscan failure
// together and still separates the transports.
const healthCodeRuntimeFailed = "portscan.runtime_failed"

// ScanStarted is emitted when a port scan of a host begins.
type ScanStarted struct {
	IP    string
	Ports int
}

// ToolName returns the tool identifier.
func (ScanStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ScanStarted) EventName() string { return "portscan: scan started" }

// EventLevel returns the log severity.
func (ScanStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ScanStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("ip", e.IP), slog.Int("ports", e.Ports)}
}

// PortOpen is emitted for each open port naabu reports, enriched with nmap
// service detection when it ran.
type PortOpen struct {
	IP      string
	Port    int
	Service string
	Product string
	Version string
}

// ToolName returns the tool identifier.
func (PortOpen) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (PortOpen) EventName() string { return "portscan: port open" }

// EventLevel returns the log severity.
func (PortOpen) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e PortOpen) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("service", e.Service),
		slog.String("product", e.Product),
		slog.String("version", e.Version),
	}
}

// ScanCompleted is emitted when a host scan finishes, summarising the scan metrics.
type ScanCompleted struct {
	IP         string
	TotalPorts int
	Open       int
	Closed     int
	Filtered   int
	Timeouts   int
	Degraded   bool
}

// ToolName returns the tool identifier.
func (ScanCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ScanCompleted) EventName() string { return "portscan: scan completed" }

// EventLevel returns the log severity.
func (ScanCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ScanCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("total_ports", e.TotalPorts),
		slog.Int("open", e.Open),
		slog.Int("closed", e.Closed),
		slog.Int("filtered", e.Filtered),
		slog.Int("timeouts", e.Timeouts),
		slog.Bool("degraded", e.Degraded),
	}
}

// ScanError is emitted when a scan cannot be performed (invalid input, runner
// construction failure, or an enumeration error).
type ScanError struct {
	IP  string
	Err error
}

// ToolName returns the tool identifier.
func (ScanError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ScanError) EventName() string { return "portscan: scan error" }

// EventLevel returns the log severity.
func (ScanError) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ScanError) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("ip", e.IP), slog.Any("error", e.Err)}
}

// CollectionHealth reports a local scanner failure that prevented the scan.
func (e ScanError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: healthCodeRuntimeFailed, Target: e.IP}, true
}

// PermissionDenied is emitted when socket creation fails due to missing privileges.
type PermissionDenied struct {
	ScanType string
	Err      error
}

// ToolName returns the tool identifier.
func (PermissionDenied) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (PermissionDenied) EventName() string { return "portscan: permission denied" }

// EventLevel returns the log severity.
func (PermissionDenied) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e PermissionDenied) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("scan_type", e.ScanType), slog.Any("error", e.Err)}
}

// CollectionHealth reports a local privilege failure that prevented scanning.
func (e PermissionDenied) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: healthCodeRuntimeFailed, Component: e.ScanType}, true
}

// NetworkUnreachable is emitted for routing errors when destination network is unreachable.
type NetworkUnreachable struct {
	IP  string
	Err error
}

// ToolName returns the tool identifier.
func (NetworkUnreachable) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (NetworkUnreachable) EventName() string { return "portscan: network unreachable" }

// EventLevel returns the log severity.
func (NetworkUnreachable) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e NetworkUnreachable) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("ip", e.IP), slog.Any("error", e.Err)}
}

// ScanThrottled is emitted when consecutive timeouts indicate stateful firewall rate limiting or SYN cookies.
type ScanThrottled struct {
	IP                  string
	ConsecutiveTimeouts int
}

// ToolName returns the tool identifier.
func (ScanThrottled) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ScanThrottled) EventName() string { return "portscan: scan throttled" }

// EventLevel returns the log severity.
func (ScanThrottled) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ScanThrottled) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("ip", e.IP), slog.Int("consecutive_timeouts", e.ConsecutiveTimeouts)}
}

// ServiceBannerDiscovered is emitted when an open port returns an initial greeting banner or protocol signature.
type ServiceBannerDiscovered struct {
	IP            string
	Port          int
	Protocol      string
	BannerSnippet string
}

// ToolName returns the tool identifier.
func (ServiceBannerDiscovered) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (ServiceBannerDiscovered) EventName() string { return "portscan: service banner discovered" }

// EventLevel returns the log severity.
func (ServiceBannerDiscovered) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e ServiceBannerDiscovered) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.Int("port", e.Port),
		slog.String("protocol", e.Protocol),
		slog.String("banner_snippet", e.BannerSnippet),
	}
}

// TargetRejected is emitted when the injected IP authorizer denies a scan target
// before any engine runs. It is the tool-boundary defense-in-depth check: the outer
// scheduler is the primary boundary, but a programmatic or future batched call is
// still refused here before a naabu runner, an nmap process, or a reachability dial
// is created. It is a policy decision, not an unreachable or clean-negative result,
// so a reader must not read it as coverage.
type TargetRejected struct {
	IP     string
	Reason string
}

// ToolName returns the tool identifier.
func (TargetRejected) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (TargetRejected) EventName() string { return "portscan: target rejected" }

// EventLevel returns the log severity.
func (TargetRejected) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e TargetRejected) EventAttrs() []slog.Attr {
	return []slog.Attr{slog.String("ip", e.IP), slog.String("reason", e.Reason)}
}

var (
	_ tooleventlog.HealthEvent = ScanError{}
	_ tooleventlog.HealthEvent = PermissionDenied{}
)

// The UDP pass has its own event set rather than a protocol field on the TCP
// events. Two transports sharing one event shape make a tool log where a reader
// has to know which field to trust, and a capture written before UDP existed
// would have to be migrated to gain the field. Separate types also keep the TCP
// stream byte-identical when UDP is disabled.
//
// udpComponent is the health component every UDP failure carries, so a rollup can
// tell a lost UDP pass from a lost TCP one without parsing a message.
const udpComponent = "udp-nmap"

// UDPScanStarted is emitted when a host's UDP pass begins, after the target has
// been authorized and the port list validated. It opens the pass's correlated
// span; the caller stamps the correlation id on the context.
type UDPScanStarted struct {
	IP    string
	Ports int
}

// ToolName returns the tool identifier.
func (UDPScanStarted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (UDPScanStarted) EventName() string { return "portscan: udp scan started" }

// EventLevel returns the log severity.
func (UDPScanStarted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e UDPScanStarted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("protocol", "udp"),
		slog.Int("ports", e.Ports),
	}
}

// UDPPortOpen is emitted for a confirmed UDP service: the port answered. It is
// the only UDP port event that becomes a discovered service; silence never does.
type UDPPortOpen struct {
	IP      string
	Port    int
	Service string
	Product string
	Version string
}

// ToolName returns the tool identifier.
func (UDPPortOpen) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (UDPPortOpen) EventName() string { return "portscan: udp port open" }

// EventLevel returns the log severity.
func (UDPPortOpen) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e UDPPortOpen) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("protocol", "udp"),
		slog.Int("port", e.Port),
		slog.String("service", e.Service),
		slog.String("product", e.Product),
		slog.String("version", e.Version),
	}
}

// UDPPortNotOpen records a port that was probed and did not answer as an open
// service, with the reason nmap gave. It is coverage, not a failure: a silent
// port is open|filtered and proves nothing, while a port-unreachable reply proves
// the host is up. Keeping the reason in the tool stream is what lets those two be
// told apart after the fact.
type UDPPortNotOpen struct {
	IP     string
	Port   int
	State  string
	Reason string
}

// ToolName returns the tool identifier.
func (UDPPortNotOpen) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (UDPPortNotOpen) EventName() string { return "portscan: udp port not open" }

// EventLevel returns the log severity.
func (UDPPortNotOpen) EventLevel() slog.Level { return slog.LevelDebug }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e UDPPortNotOpen) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("protocol", "udp"),
		slog.Int("port", e.Port),
		slog.String("state", e.State),
		slog.String("reason", e.Reason),
	}
}

// UDPScanCompleted is the terminal accounting event: what was requested, what
// each state accounted for, and whether the result is complete. A pass that
// finished with zero open ports is healthy, and an ambiguous one is coverage, so
// this event carries no health problem however few services it found.
type UDPScanCompleted struct {
	IP           string
	TotalPorts   int
	Open         int
	OpenFiltered int
	Closed       int
	Filtered     int
	// Accounted is how many of the requested ports came back with a verdict. Fewer
	// than TotalPorts means the pass did not cover what it was asked to.
	Accounted int
	// DurationMS is the wall-clock time the pass took.
	DurationMS int64
	// Partial marks a result that carries real evidence from a pass that then
	// failed. The loss itself is reported by the accompanying error event.
	Partial bool
}

// ToolName returns the tool identifier.
func (UDPScanCompleted) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (UDPScanCompleted) EventName() string { return "portscan: udp scan completed" }

// EventLevel returns the log severity.
func (UDPScanCompleted) EventLevel() slog.Level { return slog.LevelInfo }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e UDPScanCompleted) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("protocol", "udp"),
		slog.Int("total_ports", e.TotalPorts),
		slog.Int("open", e.Open),
		slog.Int("open_filtered", e.OpenFiltered),
		slog.Int("closed", e.Closed),
		slog.Int("filtered", e.Filtered),
		slog.Int("accounted", e.Accounted),
		slog.Int64("duration_ms", e.DurationMS),
		slog.Bool("partial", e.Partial),
	}
}

// UDPScanCancelled is the terminal event of a pass the collection stopped. It is
// not a health problem: an interrupted run is the capture manifest's to describe,
// and counting it as a scanner failure would make every cancelled collection look
// broken.
type UDPScanCancelled struct {
	IP  string
	Err error
}

// ToolName returns the tool identifier.
func (UDPScanCancelled) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (UDPScanCancelled) EventName() string { return "portscan: udp scan cancelled" }

// EventLevel returns the log severity.
func (UDPScanCancelled) EventLevel() slog.Level { return slog.LevelWarn }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e UDPScanCancelled) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("protocol", "udp"),
		slog.Any("error", e.Err),
	}
}

// UDPScanError is emitted when a UDP pass could not be performed or did not
// finish the work it was asked to do. It is a local scanner failure, not a target
// outcome, so it is health-bearing: the requested UDP coverage was lost.
type UDPScanError struct {
	IP  string
	Err error
}

// ToolName returns the tool identifier.
func (UDPScanError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (UDPScanError) EventName() string { return "portscan: udp scan error" }

// EventLevel returns the log severity.
func (UDPScanError) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e UDPScanError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("protocol", "udp"),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports the lost UDP work under the udp-nmap component, so a
// rollup can separate a failed UDP pass from a failed TCP one.
func (e UDPScanError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{Code: healthCodeRuntimeFailed, Component: udpComponent, Target: e.IP}, true
}

// UDPPermissionDenied is emitted when the UDP pass was refused the raw socket it
// needs. It keeps its own event because it is the one failure an operator repairs
// at deployment - the nmap binary lost its capability, typically to a package
// upgrade - rather than by retrying the scan.
type UDPPermissionDenied struct {
	IP  string
	Err error
}

// ToolName returns the tool identifier.
func (UDPPermissionDenied) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (UDPPermissionDenied) EventName() string { return "portscan: udp permission denied" }

// EventLevel returns the log severity.
func (UDPPermissionDenied) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e UDPPermissionDenied) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("protocol", "udp"),
		slog.Any("error", e.Err),
	}
}

// CollectionHealth reports the privilege failure that prevented the UDP pass.
func (e UDPPermissionDenied) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{
		Code: healthCodeRuntimeFailed, Component: udpComponent, Target: e.IP,
		SafeDetail: "nmap could not open a raw socket for the UDP pass",
	}, true
}

// UDPParsingError is emitted when nmap reported a port state this code has not
// been reviewed against. It carries bounded raw context so the change can be
// diagnosed from the tool log alone. It is health-bearing because the pass is
// abandoned: reading an unknown state as closed would turn an upstream output
// change into a confident false statement about a customer's attack surface.
type UDPParsingError struct {
	IP    string
	Port  int
	State string
	// Raw is bounded context from the same element, for diagnosis.
	Raw string
}

// ToolName returns the tool identifier.
func (UDPParsingError) ToolName() string { return toolName }

// EventName returns a short human-readable label.
func (UDPParsingError) EventName() string { return "portscan: udp parsing error" }

// EventLevel returns the log severity.
func (UDPParsingError) EventLevel() slog.Level { return slog.LevelError }

// EventAttrs returns the structured key-value pairs for logging and display.
func (e UDPParsingError) EventAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("ip", e.IP),
		slog.String("protocol", "udp"),
		slog.Int("port", e.Port),
		slog.String("state", e.State),
		slog.String("raw", e.Raw),
	}
}

// CollectionHealth reports the abandoned pass under the udp-nmap component.
func (e UDPParsingError) CollectionHealth() (tooleventlog.HealthProblem, bool) {
	return tooleventlog.HealthProblem{
		Code: healthCodeRuntimeFailed, Component: udpComponent, Target: e.IP,
		SafeDetail: "unrecognised nmap port state",
	}, true
}

var (
	_ tooleventlog.HealthEvent = UDPScanError{}
	_ tooleventlog.HealthEvent = UDPPermissionDenied{}
	_ tooleventlog.HealthEvent = UDPParsingError{}
)
