package main

import (
	"os"

	"github.com/velgard-sk/vanguard/internal/apps/collect"
)

// version is this command's release identifier, set at link time by a release or
// deploy script with -ldflags "-X main.version=v0.1.0". It is empty for an
// ordinary developer build, which is then identified by the build information the
// toolchain stamped in instead.
//
// It lives here, in the command that produces provenance, rather than in a shared
// package: a version is a property of one binary, and a package-global would let
// one stamp claim to describe every program that ever links Vanguard.
var version string

func main() {
	os.Exit(collect.Run(os.Args[1:], version))
}
