// Package subfinder provides passive subdomain enumeration via the
// projectdiscovery/subfinder library, which aggregates many third-party passive
// DNS sources (crt.sh, VirusTotal, Shodan, and others).
//
// It follows the project's tool convention: [Client] is constructed from a
// validated [Config] and performs work through [Client.Enumerate], emitting typed
// [tooleventlog.Event] values (see events.go) for every notable outcome so the
// orchestrator can log tool activity. Enumerate returns the
// discovered subdomains as [Result] values, each carrying the subfinder sources
// that reported it, which supports comparing tool coverage and efficiency across
// data providers.
//
// Provider keys are Vanguard's, not the host's. subfinder normally reads source
// API keys from an on-disk file (~/.config/subfinder/provider-config.yaml), which
// is ambient developer-machine state and silently absent on a fresh server,
// gutting passive discovery without any signal. To keep the Vanguard config the
// single source of truth, [Client.Enumerate] writes [Config.ProviderKeys] to a
// throwaway provider-config in a temp directory, points subfinder at it via
// runner.Options.ProviderConfig (which subfinder prefers over its default
// location), and deletes it when the run ends. A [ProvidersConfigured] event
// records which keyed sources were supplied (names only, never the secret), so a
// key-less run is visible instead of silent. Behaviour is then identical on a
// developer machine and a server.
//
// An empty key map alone cannot say why a source went unkeyed, so the caller also
// declares a [ProviderStatus] per keyed source it decided about
// ([Config.Providers]). The closed [ProviderDisposition] set separates the four
// cases: DispositionConfigured (Vanguard supplied the key), DispositionHandledElsewhere
// (Vanguard holds a key but a dedicated Vanguard tool owns that capability, so the
// key is withheld to avoid a second paid or quota-consuming query),
// DispositionDisabled (the source policy does not ask for it), and
// DispositionMissing (the policy asks for it and no usable key exists). Only
// DispositionMissing warns, through [ProviderKeyMissing]; DispositionHandledElsewhere
// states the owning tool through the informational [ProviderHandledElsewhere]. The
// status carries provider names and dispositions only - key material never leaves
// [Config.ProviderKeys]. [New] rejects a policy that contradicts the keys (a
// configured source with no key, or an unkeyed disposition that has one), so the
// contradiction fails at construction rather than becoming a false diagnostic. A
// caller that declares nothing gets the derived default: a supplied key is
// configured, and an absent one is missing when all sources are requested and
// disabled otherwise.
//
// During execution and upon completion, the tool classifies and reports granular
// operational failure events per provider, including [ProviderRateLimited] (HTTP 429),
// [ProviderAuthFailed] / [ProviderPaidPlanRequired] (HTTP 401/403), and [ProviderFailed].
// These events implement [tooleventlog.HealthEvent] because an attempted source
// produced incomplete evidence. [EnumerationFailed] carries a top-level failure
// that provider statistics cannot explain. Provider events are emitted in sorted
// provider order. [EnumerationCompleted] separately reports successful, failed,
// and skipped provider counts, and is degraded for partial failure, total failure,
// a top-level error, or a run in which no provider actually ran. The aggregate is
// health-neutral so it does not count a granular failure twice.
//
// [ProviderKeyMissing] and [ProviderHandledElsewhere] remain diagnostics rather than
// health events. Configuration can request all available sources but does not declare
// an individual keyed source mandatory, so a provider that was never configured or
// attempted is not a failed collection operation; a deliberately withheld key is a
// policy statement about who queries the provider, and the owning tool reports its own
// health.
//
// The package does not produce domain events itself: the orchestrator is the
// single translator from these results into DnsDomainNameDiscovered domain events.
package subfinder
