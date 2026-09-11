// Command vanguard-projections rebuilds derived views from downloaded collections on
// the analyst's host: it reads an explicit collection directory and writes an
// independently named projection directory, contacting no target, provider, or VM. Application wiring
// lives in internal/apps/projections; this package only provides the executable
// entry point and the one piece of state that genuinely belongs to a binary rather
// than to a library: the release identifier a build script stamps into it with
//
//	go build -ldflags "-X main.version=v0.1.0" ./cmd/vanguard-projections
//
// It is passed to the app layer as ordinary data. internal/apps/buildversion turns
// it, or the Go build information when it is empty, into the identifier a build
// records as its projector. An empty result is recorded rather than refused: a
// rebuild invents no evidence.
package main
