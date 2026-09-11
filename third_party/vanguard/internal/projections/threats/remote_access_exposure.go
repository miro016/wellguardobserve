package threats

import (
	"fmt"

	"github.com/velgard-sk/vanguard/internal/collection/events"
	"github.com/velgard-sk/vanguard/internal/projections/assetgraph"
	"github.com/velgard-sk/vanguard/internal/projections/entities"
)

// remoteAccessPorts are interactive remote-access services whose exposure to the
// internet is a direct initial-access vector: an attacker with valid or leaked
// credentials logs straight in, with no application layer in between.
var remoteAccessPorts = map[int]string{
	23:   "Telnet",
	3389: "RDP",
	5900: "VNC",
}

// RemoteAccessExposure fires when a risky-open-port finding exposes an interactive
// remote-access service (Telnet/RDP/VNC) to the internet. It is the service-layer
// companion to the web-centric credential-stuffing scenario.
func RemoteAccessExposure(g assetgraph.Graph) []ThreatScenario {
	var out []ThreatScenario
	for _, asset := range g.FindingAssets("service") {
		id := asset.ID
		f := g.Findings(asset)["risky-open-port"]
		if f == nil {
			continue
		}
		if asset.Proto() != entities.ProtocolTCP {
			// Telnet, RDP and VNC are interactive TCP sessions. The narrative below
			// describes logging in over one, so a service on any other transport is
			// not this scenario's subject.
			continue
		}
		label, ok := remoteAccessPorts[asset.Port()]
		if !ok {
			continue
		}
		out = append(out, ThreatScenario{
			Name:       "External remote-access exposure",
			Severity:   int(events.SeverityHigh),
			Narrative:  fmt.Sprintf("%s exposes %s to the internet; an attacker with valid or leaked credentials can log in for a direct interactive foothold.", id, label),
			Summary:    fmt.Sprintf("%s is exposed to the internet; an attacker with valid or leaked credentials can log in for a direct interactive foothold.", label),
			Assets:     []entities.AssetRef{assetRef("service", id)},
			Evidence:   []string{evidence(f)},
			References: []string{"MITRE ATT&CK T1133", "MITRE ATT&CK T1078", "CWE-668"},
		}.withChain(f))
	}
	return out
}
