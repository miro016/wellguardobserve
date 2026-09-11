// Package probes holds the reviewed web enumeration probe corpus for the goscans
// tool.
//
// The corpus is embedded in the binary and named by profile. There is no way to
// point the scanner at a file on disk, because an operator-supplied probe list
// would put arbitrary request paths into the runtime contract of an active scanner:
// what the tool sends would then depend on a file nobody reviewed. Adding a probe
// means editing probes.txt and passing review, which is the point.
//
// Every probe is a plain GET of a path that indicates exposure, never one that
// exploits it, with no parameters, no request body, and no large downloads. The
// set is deliberately small: this tool corroborates other tools rather than
// replacing a dedicated content-discovery run.
//
// Digest reports the SHA-256 of the corpus so a scan records which probes produced
// its hits, and a later comparison can tell a real change on the target from a
// change in what was asked. Write materializes the corpus into a caller-owned
// temporary directory, which the upstream enumerator requires: it reads its probe
// list from a path and rejects anything that is not a regular file.
package probes
