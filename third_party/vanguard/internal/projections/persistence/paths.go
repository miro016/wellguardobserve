package persistence

import (
	collection "github.com/velgard-sk/vanguard/internal/collection/persistence"
)

// The packet-capture sidecar names this package reads. The collection layout itself
// is owned by internal/collection/persistence, which this package asks rather than
// rebuilding: a reader that joined its own paths would become a second, silent
// authority on where the collector put the bytes.
const (
	// captureMeta is the wrapper-written key=value sidecar recording the capture
	// backend and its UTC start/stop time, beside the packet file it describes.
	captureMeta = "capture.meta.txt"
	// captureLog is the capture backend's stdout/stderr, retained so a broken or
	// empty capture can still be explained from its own diagnostics.
	captureLog = "capture.log"
)

// captureFileNames are the packet files the capture directory may hold, in
// preference order: the gzipped forms the capture wrapper collects, then the
// uncompressed forms a backend run outside the wrapper leaves. pcapng comes before
// pcap in each pair because it carries process attribution and the classic format
// does not, so when both somehow exist the higher-confidence evidence wins.
//
// Discovery and validation share this one list. Two copies would let a newly
// supported name become readable but unvalidated, or validated but never read.
var captureFileNames = []string{
	"capture.pcapng.gz", "capture.pcap.gz",
	"capture.pcapng", "capture.pcap",
}

// netauditDirPath returns the directory holding the collection's packet capture:
// one immutable set, written directly below it.
func netauditDirPath(dir string) string {
	return collection.NetAuditDir(dir)
}
