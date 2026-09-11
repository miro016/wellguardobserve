package persistence

import (
	"fmt"
	"os"
)

// OpenToolLogs creates the tools/ bucket and opens the canonical tool-event log
// ready to be written. This package owns that bucket, so it creates the directory
// rather than expecting its caller to lay the shape out.
//
// The log is created rather than appended to, which is what the collection
// directory allows: it was empty when the run claimed it, so there is no other tool
// output anywhere below it and nothing to preserve.
func OpenToolLogs(dir string) (*os.File, error) {
	tools := ToolLogDir(dir)
	if err := os.MkdirAll(tools, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create tool log dir %s: %w", tools, err)
	}
	f, err := os.Create(ToolLogPath(dir))
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", ToolLogPath(dir), err)
	}
	return f, nil
}

// OpenToolTextLog creates one tool's human-readable text log for writing.
// [OpenToolLogs] must have run first: it is what creates the bucket both streams
// live in.
func OpenToolTextLog(dir, tool string) (*os.File, error) {
	f, err := os.Create(ToolTextLogPath(dir, tool))
	if err != nil {
		return nil, fmt.Errorf("failed to open %s log: %w", tool, err)
	}
	return f, nil
}

// ReadToolLog opens the canonical tool-event log for reading. The log is optional -
// a collection whose tools wrote nothing has none - so a missing file is reported as
// (nil, false, nil) and the caller degrades instead of failing. A path that exists
// but is not a regular file is an error: that is the signature of a broken copy, not
// of a quiet run.
func ReadToolLog(dir string) (*os.File, bool, error) {
	path := ToolLogPath(dir)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("tool-event log %s is not readable: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("tool-event log %s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, fmt.Errorf("open tool-event log %s: %w", path, err)
	}
	return f, true, nil
}
