package buildversion

import (
	"runtime/debug"
	"strings"
)

// devVersion is the module version the Go toolchain reports for a main package
// built from a repository rather than resolved as a published module. It names no
// release, so it does not identify a build.
const devVersion = "(devel)"

// dirtySuffix marks a revision built from a working tree that had uncommitted
// changes. It is appended rather than substituted so the revision stays readable,
// and it is fixed text so two builds of the same dirty revision produce the same
// identifier.
const dirtySuffix = "+dirty"

// Resolve returns the version identifier for a first-party Vanguard command.
//
// release is the command's own link-time value, empty for an ordinary developer
// build. When it is empty the running executable's Go build information is used
// instead: a meaningful main-module version, otherwise the VCS revision with a
// dirty marker when applicable. The result is empty when the build carries none of
// these, which is the honest answer for a binary nothing can name.
func Resolve(release string) string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		info = nil
	}
	return resolve(release, info)
}

// resolve is the whole policy, separated from reading the running build so every
// case a real binary can present - stamped release, published module, developer
// build, dirty tree, no build information - is testable without building five
// binaries.
func resolve(release string, info *debug.BuildInfo) string {
	if strings.TrimSpace(release) != "" {
		return release
	}
	if info == nil {
		return ""
	}
	if v := info.Main.Version; v != "" && v != devVersion {
		return v
	}
	return revision(info.Settings)
}

// revision reads the VCS stamp the toolchain recorded. An unstamped build (built
// with -buildvcs=false, or from an export with no repository) has no settings to
// read and yields the empty string.
func revision(settings []debug.BuildSetting) string {
	var rev string
	var modified bool
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if rev == "" {
		return ""
	}
	if modified {
		return rev + dirtySuffix
	}
	return rev
}
