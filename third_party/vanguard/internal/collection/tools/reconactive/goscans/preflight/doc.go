// Package preflight verifies, read-only, that the external runtime the goscans
// tool needs is already present and correct.
//
// The division of labour is deliberate: deployment installs nmap and the pinned
// SSLyze environment, and a scan only looks. Nothing here installs a package,
// invokes pip or a system package manager, runs setcap, escalates privileges, or
// downloads anything. A scan that repairs its own environment would make two runs
// on the same machine mean different things, and would need privileges a scanner
// has no business holding.
//
// Every check is a version or capability query with a deadline and a bounded
// output buffer, executed without a shell. All problems are collected and reported
// together, each naming the path that was checked, what was found, what is
// required, and what an operator should do, because fixing a deployment one
// failure per scan run is the slowest possible loop.
//
// # What is checked and why
//
// nmap is resolved and its version read. Then the NSE scripts in DiscoveryScripts
// are verified, which matters more than it looks: upstream GoScans discovery forces
// that script list onto every invocation and prunes unavailable entries only inside
// its own setup routine, which this integration never calls because that routine
// also runs setcap and requires elevation. Nothing prunes them at scan time, so a
// stripped nmap package turns into a scan that aborts on its first target. This
// check is what turns that into a startup error.
// [ResolveNmap] performs only the resolution/version half for portscan-only runs,
// where GoScans' forced NSE script set is irrelevant.
//
// When the TLS module is enabled, the configured interpreter is resolved, its
// version compared against MinPythonVersion, and SSLyze run with "-m sslyze
// --help". The version is read from the same help banner the upstream scanner
// parses, so preflight and the scanner can never disagree about what is installed.
// When the TLS module is disabled none of that runs, and a passive or
// TLS-free scan needs no Python at all.
//
// An optional additional trust store is checked for existence, regular-file shape,
// and readability by the scan user.
//
// # What is reported
//
// [Result] carries what was actually resolved rather than what was configured: the
// absolute paths and the versions the binaries reported. A run records that, so a
// finding is attributable to the runtime that produced it, which matters because a
// configured path resolves through PATH to whatever is there on the day.
//
// [GoScansVersion] belongs to the same record from the other side. It is the
// vendored upstream release this binary was built against - compiled in, not found
// on the machine - and it is what decides which scripts are forced and how each
// module's results are read. It lives here because this package already encodes
// what that release demands of a machine, and a test holds it to the module the
// build actually uses.
package preflight
