// Command vanguard-collect runs a Vanguard collection on a scan VM: it contacts
// targets and providers and writes the captured streams and collection metadata,
// and it renders no derived artifact. Application wiring lives in
// internal/apps/collect; this package only provides the executable entry point and
// the one piece of state that genuinely belongs to a binary rather than to a
// library: the release identifier a build script stamps into it with
//
//	go build -ldflags "-X main.version=v0.1.0" ./cmd/vanguard-collect
//
// It is passed to the app layer as ordinary data. internal/apps/buildversion turns
// it, or the Go build information when it is empty, into the single identifier the
// collection stage records; nothing below that layer knows a linker was involved.
package main
