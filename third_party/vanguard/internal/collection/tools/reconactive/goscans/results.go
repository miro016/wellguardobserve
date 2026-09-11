package goscans

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/plan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/goscans/upstream"
	"github.com/velgard-sk/vanguard/internal/collection/tools/redact"
)

// emitScripts reports NSE script output, redacted and capped, and returns how many
// scripts it emitted.
func (a *Actor) emitScripts(ctx context.Context, ip string, scripts []upstream.DiscoveryScript) int {
	for _, s := range scripts {
		text, truncated := a.excerptString(s.Result, a.cfg.Limits.MaxScriptOutputBytes)
		a.emit(ctx, ScriptCollected{
			IP:        ip,
			Port:      s.Port,
			Protocol:  s.Protocol,
			Name:      s.Name,
			Scope:     s.Type,
			Output:    text,
			RawBytes:  len(s.Result),
			Truncated: truncated,
		})
	}
	return len(scripts)
}

// runBanner collects the banners of one service. Upstream banner has neither a
// context nor a run timeout, so it is run inline and bounded only by the dial and
// receive timeouts it was constructed with. That is deliberate: a wrapper
// goroutine would have to be abandoned on cancellation, and an abandoned goroutine
// holding an open socket is worse than waiting out a short read.
func (a *Actor) runBanner(ctx context.Context, j plan.Job) bool {
	log := upstreamLogger{actor: a, ctx: ctx, module: plan.Banner, ip: j.IP, port: j.Port}
	runner, err := a.up.Banner(log, upstream.BannerRequest{
		Target:         j.IP,
		Port:           j.Port,
		Protocol:       j.Protocol,
		DialTimeout:    a.cfg.BannerDialTimeout,
		ReceiveTimeout: a.cfg.BannerReceiveTimeout,
	})
	if err != nil {
		a.emit(ctx, ModuleSetupFailed{Module: plan.Banner.String(), IP: j.IP, Port: j.Port, Err: err})
		return false
	}

	result := runner.Run()
	if result == nil {
		return a.failMissing(ctx, plan.Banner, j.IP, j.Port)
	}
	if result.Exception {
		return a.failException(ctx, plan.Banner, j.IP, j.Port, result.Status)
	}
	if result.Data == nil {
		return true
	}

	for _, probe := range []struct {
		name string
		raw  []byte
	}{
		{"plain", result.Data.Plain},
		{"ssl", result.Data.Ssl},
		{"telnet", result.Data.Telnet},
		{"http", result.Data.Http},
		{"https", result.Data.Https},
	} {
		if len(probe.raw) == 0 {
			continue
		}
		text, digest, truncated := a.excerpt(probe.raw)
		a.emit(ctx, BannerCollected{
			IP:        j.IP,
			Port:      j.Port,
			Protocol:  j.Protocol,
			Probe:     probe.name,
			Excerpt:   text,
			RawBytes:  len(probe.raw),
			Digest:    digest,
			Truncated: truncated,
		})
	}
	return true
}

// runTLS assesses one TLS service with SSLyze. Cancelling the module context kills
// the SSLyze child process, so this is one of the modules that stops promptly.
func (a *Actor) runTLS(ctx context.Context, j plan.Job) bool {
	mctx, cancel, timeout, ok := a.moduleContext(ctx, plan.TLS, j, a.cfg.TLSTimeout)
	if !ok {
		return false
	}
	defer cancel()

	log := upstreamLogger{actor: a, ctx: ctx, module: plan.TLS, ip: j.IP, port: j.Port}
	runner, err := a.up.SSL(log, upstream.SSLRequest{
		PythonPath:           a.cfg.PythonPath,
		AdditionalTruststore: a.cfg.SslyzeAdditionalTruststore,
		Target:               j.IP,
		Port:                 j.Port,
		Vhosts:               j.Vhosts,
	})
	if err != nil {
		// The upstream constructor probes the interpreter and the SSLyze version
		// here, so a missing or too-old runtime arrives as a construction error.
		a.emit(ctx, ModuleSetupFailed{Module: plan.TLS.String(), IP: j.IP, Port: j.Port, Err: err})
		return false
	}
	runner.SetContext(mctx)

	result := runner.Run(timeout)
	a.reportTimeout(ctx, mctx, plan.TLS, j, timeout)
	if result == nil {
		return a.failMissing(ctx, plan.TLS, j.IP, j.Port)
	}
	if result.Exception {
		return a.failException(ctx, plan.TLS, j.IP, j.Port, result.Status)
	}

	entries := make([]*upstream.SSLData, 0, len(result.Data))
	for _, data := range result.Data {
		if data != nil {
			entries = append(entries, data)
		}
	}
	// Emission order follows the requested names, not upstream's: it iterates its
	// scanners out of a map, so the order it returns results in changes between
	// runs of the same scan.
	sort.Slice(entries, func(i, k int) bool { return entries[i].Vhost < entries[k].Vhost })

	// Reconcile what came back against what was asked for. A result may be
	// attributed to a name only when every requested name came back, because
	// upstream removes a result for either of two reasons and reports neither:
	// it drops one that duplicates a result it already holds, and it drops one
	// that came back empty. Only the first would mean the missing names measured
	// like the survivor; the second means they were not measured at all.
	//
	// Nothing distinguishes the two from outside, and the difference is not
	// academic: upstream compares the trust-store list as part of equality, so a
	// certificate covering the virtual hosts but not the address can never
	// deduplicate its address result against a name result. On such a service a
	// short count is always loss, and the result that survives is the address
	// measurement - whose failure to validate would then be charged to names that
	// validate perfectly well.
	//
	// So the name a surviving result is labelled with is kept only when the count
	// matches, and every short count is reported instead of guessed at.
	requested := tlsRequestedNames(j)
	attributable := len(entries) == len(requested)
	for _, data := range entries {
		assessment := a.tlsAssessment(j.IP, j.Port, data)
		if attributable {
			assessment.AssessedNames = []string{assessment.Vhost}
		} else {
			assessment.Vhost = ""
			assessment.AssessedNames = nil
		}
		a.emit(ctx, assessment)
	}
	if !attributable {
		a.emit(ctx, TLSNamesUnreported{IP: j.IP, Port: j.Port, Requested: requested, Reported: len(entries)})
	}
	return true
}

// tlsRequestedNames lists the server names the TLS scanner actually probes, sorted:
// the address itself, which it always probes without SNI, plus the job's usable
// virtual hosts.
//
// It has to match what upstream probes exactly, not approximately, because its
// length is what decides whether a result can be attributed to a name. Upstream
// discards invalid names, removes the target from the virtual hosts, and then
// deduplicates what is left before building one scanner per surviving name, keyed
// by the name in a map. So a name counted here that upstream never built a scanner
// for makes a complete set of results look short, which clears the server name off
// every result for that socket and reports a coverage gap that does not exist.
//
// Deduplication is by exact string, because that is what keying a map by the name
// does: upstream builds two scanners for two spellings of one host that differ in
// case, and so two results come back.
func tlsRequestedNames(j plan.Job) []string {
	out := make([]string, 0, len(j.Vhosts)+1)
	out = append(out, j.IP)
	seen := map[string]bool{j.IP: true}
	for _, v := range j.Vhosts {
		if seen[v] || !usableServerName(v) {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// usableServerName reports whether upstream will probe a name as an SNI value. It
// mirrors the constraints upstream applies to a virtual-host list: a name must
// start and end alphanumeric, must not be an address, and must not contain a
// character that has no place in a hostname.
func usableServerName(name string) bool {
	if name == "" || net.ParseIP(name) != nil {
		return false
	}
	if !isAlphanumeric(rune(name[0])) || !isAlphanumeric(rune(name[len(name)-1])) {
		return false
	}
	return !strings.ContainsAny(name, " =:?!\\/\x00")
}

// isAlphanumeric reports whether r is an ASCII letter or digit.
func isAlphanumeric(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}

// runSSH assesses the algorithm and protocol choices of one SSH service.
func (a *Actor) runSSH(ctx context.Context, j plan.Job) bool {
	mctx, cancel, timeout, ok := a.moduleContext(ctx, plan.SSH, j, a.cfg.SSHTimeout)
	if !ok {
		return false
	}
	defer cancel()

	log := upstreamLogger{actor: a, ctx: ctx, module: plan.SSH, ip: j.IP, port: j.Port}
	runner, err := a.up.SSH(log, upstream.SSHRequest{Target: j.IP, Port: j.Port, DialTimeout: a.cfg.BannerDialTimeout})
	if err != nil {
		a.emit(ctx, ModuleSetupFailed{Module: plan.SSH.String(), IP: j.IP, Port: j.Port, Err: err})
		return false
	}
	runner.SetContext(mctx)

	result := runner.Run(timeout)
	a.reportTimeout(ctx, mctx, plan.SSH, j, timeout)
	if result == nil {
		return a.failMissing(ctx, plan.SSH, j.IP, j.Port)
	}
	if result.Exception {
		return a.failException(ctx, plan.SSH, j.IP, j.Port, result.Status)
	}
	if result.Data == nil {
		return true
	}

	limit := a.cfg.Limits.MaxSSHAlgorithms
	kex, t1 := capStrings(result.Data.KeyExchangeAlgorithms, limit)
	key, t2 := capStrings(result.Data.ServerKeyAlgorithms, limit)
	enc, t3 := capStrings(result.Data.ServerEncryptionAlgorithms, limit)
	mac, t4 := capStrings(result.Data.ServerMacAlgorithms, limit)
	comp, t5 := capStrings(result.Data.ServerCompressAlgorithms, limit)
	auth, t6 := capStrings(result.Data.AuthenticationMechanisms, limit)

	a.emit(ctx, SSHAssessed{
		IP:                 j.IP,
		Port:               j.Port,
		ProtocolVersion:    result.Data.ProtocolVersion,
		KeyExchange:        kex,
		ServerKey:          key,
		Encryption:         enc,
		Mac:                mac,
		Compression:        comp,
		AuthMechanisms:     auth,
		GuessedKeyExchange: result.Data.UsesGuessedKeyExchange,
		Truncated:          t1 || t2 || t3 || t4 || t5 || t6,
	})
	return true
}

// runCrawl crawls one web service. The crawler needs a writable directory even
// with downloads disabled, because it records discovered file URLs to a CSV there;
// the directory is inside the actor-owned temporary root and is removed with it.
func (a *Actor) runCrawl(ctx context.Context, j plan.Job) bool {
	mctx, cancel, timeout, ok := a.moduleContext(ctx, plan.Crawl, j, a.cfg.CrawlTimeout)
	if !ok {
		return false
	}
	defer cancel()

	dir, err := a.jobDir(j)
	if err != nil {
		a.emit(ctx, FilesystemError{Op: "create crawl directory", Path: a.tempRoot, Err: err})
		return false
	}

	log := upstreamLogger{actor: a, ctx: ctx, module: plan.Crawl, ip: j.IP, port: j.Port}
	runner, err := a.up.WebCrawler(log, upstream.WebCrawlerRequest{
		Target:         j.IP,
		Port:           j.Port,
		Vhosts:         j.Vhosts,
		HTTPS:          j.HTTPS,
		Depth:          a.cfg.CrawlDepth,
		MaxThreads:     a.cfg.CrawlThreads,
		OutputFolder:   dir,
		UserAgent:      a.cfg.UserAgent,
		RequestTimeout: a.cfg.CrawlRequestTimeout,
	})
	if err != nil {
		a.emit(ctx, ModuleSetupFailed{Module: plan.Crawl.String(), IP: j.IP, Port: j.Port, Err: err})
		return false
	}
	runner.SetContext(mctx)

	result := runner.Run(timeout)
	a.reportTimeout(ctx, mctx, plan.Crawl, j, timeout)
	if result == nil {
		return a.failMissing(ctx, plan.Crawl, j.IP, j.Port)
	}
	if result.Exception {
		return a.failException(ctx, plan.Crawl, j.IP, j.Port, result.Status)
	}

	for _, crawl := range result.Data {
		if crawl == nil {
			continue
		}
		emitted := a.emitPages(ctx, j, crawl)
		vhosts := append([]string(nil), crawl.DiscoveredVhosts...)
		for i := range vhosts {
			vhosts[i] = strings.ToLower(strings.TrimSpace(vhosts[i]))
		}
		sort.Strings(vhosts)
		vhosts, vhostTrunc := capStrings(dedupSorted(vhosts), a.cfg.Limits.MaxVhosts)
		a.emit(ctx, CrawlCompleted{
			IP:               j.IP,
			Port:             j.Port,
			Vhost:            crawl.Vhost,
			Pages:            len(crawl.Pages),
			Requests:         crawl.RequestsTotal,
			DiscoveredVhosts: vhosts,
			FaviconHash:      crawl.FaviconHash,
			AuthMethod:       crawl.AuthMethod,
			AuthSuccess:      crawl.AuthSuccess,
			Status:           a.capStatus(crawl.Status),
			Truncated:        emitted < len(crawl.Pages) || vhostTrunc,
		})
	}
	return true
}

// emitPages reports crawled pages up to the configured cap and returns how many it
// emitted, so the caller can mark a capped crawl as truncated.
func (a *Actor) emitPages(ctx context.Context, j plan.Job, crawl *upstream.WebCrawlerCrawl) int {
	emitted := 0
	for _, page := range crawl.Pages {
		if page == nil {
			continue
		}
		if emitted >= a.cfg.Limits.MaxCrawlPages {
			break
		}
		text, digest, truncated := a.excerpt(page.HtmlContent)
		url := ""
		if page.Url != nil {
			url = page.Url.String()
		}
		a.emit(ctx, CrawlPage{
			IP:            j.IP,
			Port:          j.Port,
			Vhost:         crawl.Vhost,
			URL:           url,
			RedirectURL:   page.RedirectUrl,
			RedirectCount: page.RedirectCount,
			Depth:         page.Depth,
			ResponseCode:  page.ResponseCode,
			ContentType:   page.ResponseContentType,
			Server:        serverHeader(page.ResponseHeaders),
			AuthMethod:    page.AuthMethod,
			Title:         redact.Snippet(page.HtmlTitle, a.cfg.Limits.MaxExcerptBytes),
			Excerpt:       text,
			RawBytes:      len(page.HtmlContent),
			Digest:        digest,
			Truncated:     truncated,
		})
		emitted++
	}
	return emitted
}

// runEnum probes one web service with the embedded probe set.
func (a *Actor) runEnum(ctx context.Context, j plan.Job) bool {
	mctx, cancel, timeout, ok := a.moduleContext(ctx, plan.Enum, j, a.cfg.EnumTimeout)
	if !ok {
		return false
	}
	defer cancel()

	log := upstreamLogger{actor: a, ctx: ctx, module: plan.Enum, ip: j.IP, port: j.Port}
	runner, err := a.up.WebEnum(log, upstream.WebEnumRequest{
		Target:         j.IP,
		Port:           j.Port,
		Vhosts:         j.Vhosts,
		HTTPS:          j.HTTPS,
		ProbesFile:     a.probesFile,
		ProbeRobots:    a.cfg.ProbeRobots,
		UserAgent:      a.cfg.UserAgent,
		RequestTimeout: a.cfg.EnumRequestTimeout,
	})
	if err != nil {
		a.emit(ctx, ModuleSetupFailed{Module: plan.Enum.String(), IP: j.IP, Port: j.Port, Err: err})
		return false
	}
	runner.SetContext(mctx)

	result := runner.Run(timeout)
	a.reportTimeout(ctx, mctx, plan.Enum, j, timeout)
	if result == nil {
		return a.failMissing(ctx, plan.Enum, j.IP, j.Port)
	}
	if result.Exception {
		return a.failException(ctx, plan.Enum, j.IP, j.Port, result.Status)
	}

	emitted := 0
	for _, item := range result.Data {
		if item == nil {
			continue
		}
		if emitted >= a.cfg.Limits.MaxEnumItems {
			break
		}
		text, digest, truncated := a.excerpt(item.HtmlContent)
		a.emit(ctx, EnumItemFound{
			IP:            j.IP,
			Port:          j.Port,
			Vhost:         item.Vhost,
			Name:          item.Name,
			URL:           item.Url,
			RedirectURL:   item.RedirectUrl,
			RedirectCount: item.RedirectCount,
			RedirectOut:   item.RedirectOut,
			ResponseCode:  item.ResponseCode,
			ContentType:   item.ResponseContentType,
			Server:        serverHeader(item.ResponseHeaders),
			AuthMethod:    item.AuthMethod,
			Title:         redact.Snippet(item.HtmlTitle, a.cfg.Limits.MaxExcerptBytes),
			Excerpt:       text,
			RawBytes:      len(item.HtmlContent),
			Digest:        digest,
			Truncated:     truncated,
		})
		emitted++
	}

	a.emit(ctx, EnumCompleted{
		IP:        j.IP,
		Port:      j.Port,
		Items:     len(result.Data),
		Status:    a.capStatus(result.Status),
		Truncated: emitted < len(result.Data),
	})
	return true
}

// -----------------------------------------------------------------------------
// Shared module plumbing
// -----------------------------------------------------------------------------

// moduleContext derives the deadline for one module from the shorter of its
// configured timeout and the time left on the run. It reports false, having
// emitted a timeout event, when there is no time left to start at all.
func (a *Actor) moduleContext(ctx context.Context, m plan.Module, j plan.Job, want time.Duration) (context.Context, context.CancelFunc, time.Duration, bool) {
	timeout := remaining(ctx, want)
	if timeout <= 0 {
		a.emit(ctx, ModuleTimeout{Module: m.String(), IP: j.IP, Port: j.Port, Timeout: want})
		return nil, nil, 0, false
	}
	mctx, cancel := context.WithTimeout(ctx, timeout)
	return mctx, cancel, timeout, true
}

// reportTimeout emits a timeout event when the module deadline elapsed. It is
// reported even when the module still returned partial data, so a short result is
// never mistaken for a complete one.
func (a *Actor) reportTimeout(ctx, mctx context.Context, m plan.Module, j plan.Job, timeout time.Duration) {
	if errors.Is(mctx.Err(), context.DeadlineExceeded) {
		a.emit(ctx, ModuleTimeout{Module: m.String(), IP: j.IP, Port: j.Port, Timeout: timeout})
	}
}

// failMissing records a module that returned no result at all and reports the job
// as failed. Every upstream module is documented to always return a result, so a
// nil one means the upstream contract broke rather than that the target was quiet.
func (a *Actor) failMissing(ctx context.Context, m plan.Module, ip string, port int) bool {
	a.emit(ctx, ModuleFailed{Module: m.String(), IP: ip, Port: port, Status: statusNoResult})
	return false
}

// failException records an upstream exception and reports the job as failed. An
// exception is also how an upstream parsing failure arrives: upstream turns a
// malformed nmap or SSLyze payload into an exception rather than a typed parse
// error, and it documents the payload as unusable when the flag is set.
func (a *Actor) failException(ctx context.Context, m plan.Module, ip string, port int, status string) bool {
	a.emit(ctx, ModuleFailed{Module: m.String(), IP: ip, Port: port, Status: a.capStatus(status), Exception: true})
	return false
}

// capStatus bounds an upstream status string before it reaches an event.
func (a *Actor) capStatus(status string) string {
	return redact.Snippet(status, a.cfg.Limits.MaxExcerptBytes)
}

// excerpt redacts and caps a raw payload and returns the safe text, a digest of
// the raw bytes, and whether the payload was longer than the cap.
func (a *Actor) excerpt(raw []byte) (text, digest string, truncated bool) {
	if len(raw) == 0 {
		return "", "", false
	}
	limit := a.cfg.Limits.MaxExcerptBytes
	return redact.Snippet(string(raw), limit), redact.Hash(raw), len(raw) > limit
}

// excerptString is excerpt for text that upstream already decoded. It reports no
// digest: the caller records the raw length, and the text is already the payload.
func (a *Actor) excerptString(raw string, limit int) (text string, truncated bool) {
	if raw == "" {
		return "", false
	}
	return redact.Snippet(raw, limit), len(raw) > limit
}

// serverHeader pulls the Server header value out of the raw header block upstream
// hands back as one string. Only that one header is extracted: the rest of the
// block is unbounded, request-specific, and already summarised by the status and
// content type, so carrying it whole would put an arbitrary payload into the
// stream for no consumer. The value is capped, because a header is attacker
// controlled like any other response field.
func serverHeader(headers string) string {
	for line := range strings.Lines(headers) {
		name, value, found := strings.Cut(line, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "server") {
			continue
		}
		return redact.Snippet(strings.TrimSpace(value), maxServerHeaderBytes)
	}
	return ""
}

// maxServerHeaderBytes bounds the retained Server header. A real one is a product
// and version; anything longer is padding or an attempt to bloat the stream.
const maxServerHeaderBytes = 128

// capStrings truncates a list to the limit and reports whether it had to.
func capStrings(in []string, limit int) ([]string, bool) {
	if len(in) <= limit {
		return in, false
	}
	return in[:limit], true
}

// issueNames lists the upstream TLS issue flags that were set, sorted by name.
// Reflection is deliberate here: the upstream Issues type is a flat block of about
// thirty booleans that upstream extends over time, and enumerating them by hand
// would silently miss every new one on a version bump.
func issueNames(issues *upstream.SSLIssues) []string {
	if issues == nil {
		return nil
	}
	v := reflect.ValueOf(*issues)
	t := v.Type()
	var out []string
	for i := range t.NumField() {
		field := t.Field(i)
		if field.Type.Kind() != reflect.Bool || !field.IsExported() {
			continue
		}
		if v.Field(i).Bool() {
			out = append(out, field.Name)
		}
	}
	sort.Strings(out)
	return out
}

// sanitizePathPart makes one path segment safe to build a temporary directory name
// from, so an address can never introduce a separator or a traversal.
func sanitizePathPart(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, s)
}
