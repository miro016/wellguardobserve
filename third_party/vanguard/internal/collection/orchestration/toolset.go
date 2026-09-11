package orchestration

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/httpprobe"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/https"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/portscan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/smtp"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/wappalyzer"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconactive/webinfo"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/asn"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/breach"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/censys"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/certspotter"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/crtsh"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/dnsinfo"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/mailsec"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/netlas"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/shodan"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/subfinder"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/virustotal"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/websearch"
	"github.com/velgard-sk/vanguard/internal/collection/tools/reconpassive/whois"
)

// toolset groups the tool client instances used by the orchestrator.
type toolset struct {
	dns         *dnsinfo.Client
	asn         *asn.Client
	crtsh       *crtsh.Client
	certspotter *certspotter.Client
	subfinder   *subfinder.Client
	whois       *whois.Client
	mailsec     *mailsec.Client
	breach      *breach.Client
	censys      *censys.Client
	virustotal  *virustotal.Client
	websearch   *websearch.Client
	shodan      *shodan.Client
	netlas      *netlas.Client
	portscan    portScanner
	httpprobe   *httpprobe.Client
	https       *https.Client
	providerTLS certificateProber
	smtp        smtpProber
	webinfo     *webinfo.Client
	wappalyzer  wappalyzerProber
}

// newToolset constructs all enabled tool clients from cfg. A client is created only
// for an enabled tool, so a disabled tool is inert.
//
// An enabled tool whose constructor fails is a configuration error, not a runtime
// degradation: the operator asked for that tool, and a silently nil client would run
// the whole scan and report a clean result for work that never happened. The error is
// returned, named with the tool it came from, and the orchestrator refuses to start
// on it - before any traffic leaves the machine.
func newToolset(cfg *Config) (toolset, error) {
	var ts toolset
	if err := ts.initDiscovery(cfg); err != nil {
		return ts, err
	}
	if err := ts.initIntel(cfg); err != nil {
		return ts, err
	}
	if err := ts.initActive(cfg); err != nil {
		return ts, err
	}
	return ts, nil
}

// initErr names the tool an enabled client's constructor failed for, so an operator
// reading the message knows which config block to fix.
func initErr(tool string, err error) error {
	return fmt.Errorf("init %s: %w", tool, err)
}

// initDiscovery builds the passive DNS/infrastructure discovery clients.
func (ts *toolset) initDiscovery(cfg *Config) error {
	var err error
	if cfg.Crtsh.Mode.Enabled() {
		if ts.crtsh, err = crtsh.New(&cfg.Crtsh); err != nil {
			return initErr(sourceCrtsh, err)
		}
	}
	if cfg.EnableCertspotter {
		if ts.certspotter, err = certspotter.New(&cfg.Certspotter); err != nil {
			return initErr(sourceCertspotter, err)
		}
	}
	if cfg.EnableSubfinder {
		if ts.subfinder, err = subfinder.New(cfg.Subfinder); err != nil {
			return initErr(sourceSubfinder, err)
		}
	}
	if cfg.EnableDnsInfo {
		if ts.dns, err = dnsinfo.New(cfg.DnsInfo); err != nil {
			return initErr(sourceDnsinfo, err)
		}
	}
	if cfg.EnableAsnInfo {
		if ts.asn, err = asn.New(cfg.AsnInfo); err != nil {
			return initErr(sourceAsn, err)
		}
	}
	if cfg.EnableWhois {
		if ts.whois, err = whois.New(cfg.Whois); err != nil {
			return initErr(sourceWhois, err)
		}
	}
	return nil
}

// initIntel builds the passive external-intelligence clients (mail security,
// breach, and the paid search/intel APIs).
func (ts *toolset) initIntel(cfg *Config) error {
	var err error
	if cfg.EnableMailSec {
		if ts.mailsec, err = mailsec.New(cfg.MailSec); err != nil {
			return initErr(sourceMailsec, err)
		}
	}
	if cfg.EnableBreach {
		if ts.breach, err = breach.New(cfg.Breach); err != nil {
			return initErr(sourceBreach, err)
		}
	}
	if cfg.Censys.Mode.Enabled() {
		if ts.censys, err = censys.New(cfg.Censys); err != nil {
			return initErr(sourceCensys, err)
		}
	}
	if cfg.EnableVirusTotal {
		if ts.virustotal, err = virustotal.New(cfg.Virustotal); err != nil {
			return initErr(sourceVirustotal, err)
		}
	}
	if cfg.EnableWebSearch {
		if ts.websearch, err = websearch.New(cfg.WebSearch); err != nil {
			return initErr(sourceWebsearch, err)
		}
	}
	if cfg.EnableShodan {
		if ts.shodan, err = shodan.New(cfg.Shodan); err != nil {
			return initErr(sourceShodan, err)
		}
	}
	if cfg.EnableNetlas {
		if ts.netlas, err = netlas.New(cfg.Netlas); err != nil {
			return initErr(sourceNetlas, err)
		}
	}
	return nil
}

// initActive constructs the enabled active-phase tool clients, under the same
// enabled-tool-must-construct rule as the passive clients.
func (ts *toolset) initActive(cfg *Config) error {
	if cfg.EnablePortScan {
		client, err := portscan.New(cfg.PortScan)
		if err != nil {
			return initErr(sourcePortscan, err)
		}
		ts.portscan = client
	}
	if cfg.EnableHttpProbe {
		client, err := httpprobe.New(cfg.HttpProbe)
		if err != nil {
			return initErr(sourceHTTP, err)
		}
		ts.httpprobe = client
	}
	if cfg.EnableHttps {
		client, err := https.New(cfg.Https)
		if err != nil {
			return initErr(sourceHTTPS, err)
		}
		ts.https = client
	}
	if cfg.ProviderHostProbePolicy == ProviderHostProbeCorroborated &&
		cfg.EnableActive && (cfg.EnablePortScan || cfg.EnableGoScans) {
		if ts.https != nil {
			ts.providerTLS = ts.https
		} else {
			client, err := https.New(cfg.Https)
			if err != nil {
				return initErr(sourceProviderProbe, err)
			}
			ts.providerTLS = client
		}
	}
	if cfg.EnableSmtp {
		client, err := smtp.New(cfg.Smtp)
		if err != nil {
			return initErr(sourceSMTP, err)
		}
		ts.smtp = client
	}
	if cfg.EnableWebInfo {
		client, err := webinfo.New(cfg.WebInfo)
		if err != nil {
			return initErr(sourceWebinfo, err)
		}
		ts.webinfo = client
	}
	// Wappalyzer is gated on its own flag alone. No other HTTP tool's state is read
	// here, and none reads this one: the tool runs standalone or beside them.
	if cfg.EnableWappalyzer {
		client, err := wappalyzer.New(cfg.Wappalyzer)
		if err != nil {
			return initErr(sourceWappalyzer, err)
		}
		ts.wappalyzer = client
	}
	return nil
}
