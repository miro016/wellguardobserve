package goscans

import (
	"context"
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/plan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/redact"
)

// Upstream log levels, as they appear on an UpstreamLog event.
const (
	levelInfo    = "info"
	levelWarning = "warning"
	levelError   = "error"
)

// upstreamLogger adapts the GoScans logger interface to bounded tool events. It is
// created per job so the module, target, and port are known without upstream
// having to say them, and it is the reason this integration never installs a
// global logger: every upstream line lands in this actor's event stream or is
// dropped.
//
// Debug lines are dropped. Upstream logs per request and per certificate at debug
// level, which would swamp the tool log with detail that the result events already
// carry in structured form.
type upstreamLogger struct {
	actor  *Actor
	ctx    context.Context
	module plan.Module
	ip     string
	port   int
}

// Debugf drops the line: upstream debug output is per request and adds nothing the
// result events do not already carry.
func (upstreamLogger) Debugf(string, ...interface{}) {}

// Infof forwards an upstream informational line.
func (l upstreamLogger) Infof(format string, v ...interface{}) {
	l.emit(levelInfo, format, v...)
}

// Warningf forwards an upstream warning.
func (l upstreamLogger) Warningf(format string, v ...interface{}) {
	l.emit(levelWarning, format, v...)
}

// Errorf forwards an upstream error line. It is a log record, not a failure: the
// module still reports its own outcome through its result.
func (l upstreamLogger) Errorf(format string, v ...interface{}) {
	l.emit(levelError, format, v...)
}

// emit redacts, caps, and forwards one upstream line.
func (l upstreamLogger) emit(level, format string, v ...interface{}) {
	msg := redact.Snippet(fmt.Sprintf(format, v...), l.actor.cfg.Limits.MaxUpstreamLogBytes)
	l.actor.emit(l.ctx, UpstreamLog{
		Module:  l.module.String(),
		IP:      l.ip,
		Port:    l.port,
		Level:   level,
		Message: msg,
	})
}
