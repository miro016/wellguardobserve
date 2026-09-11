package events

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// SchemaVersion is the version stamped on every persisted event envelope. During
// the POC it identifies the current format but is intentionally not bumped for
// incompatible vocabulary cleanup; existing captures must be regenerated instead
// of treated as readable by the current structs.
const SchemaVersion = 1

// eventRegistry maps a type tag (the concrete event struct name) to a decoder
// that unmarshals a JSON payload into that event in its canonical form (value
// or pointer, matching how the rest of the code type-switches on it).
//
// It is the single place an event type is registered. Adding a new DomainEvent
// means adding one register call in the init below; the codec, replay, and the
// round-trip test then cover it automatically. This keeps decoding extensible as
// new tools or recon phases are introduced.
var eventRegistry = map[string]func(json.RawMessage) (DomainEvent, error){}

// register wires a single event type into the registry. T is the concrete event
// struct; toEvent returns it in the form the rest of the code expects (return *e
// for events whose pointer implements DomainEvent, *e dereferenced for value
// events). The type tag is derived from T via reflection, so it always matches
// TypeName.
func register[T any](toEvent func(*T) DomainEvent) {
	name := reflect.TypeFor[T]().Name()
	eventRegistry[name] = func(data json.RawMessage) (DomainEvent, error) {
		v := new(T)
		if err := json.Unmarshal(data, v); err != nil {
			return nil, fmt.Errorf("decode %s: %w", name, err)
		}
		return toEvent(v), nil
	}
}

func init() {
	// Value-form events (the struct value implements DomainEvent).
	register(func(e *ScanStarted) DomainEvent { return *e })
	register(func(e *ScanEnvironmentRecorded) DomainEvent { return *e })
	register(func(e *ScanCompleted) DomainEvent { return *e })
	register(func(e *DnsDomainNameDiscovered) DomainEvent { return *e })
	register(func(e *CertificateDiscovered) DomainEvent { return *e })
	register(func(e *FindingRaised) DomainEvent { return *e })
	register(func(e *IssueObserved) DomainEvent { return *e })

	// Pointer-form events (only the pointer implements DomainEvent).
	register(func(e *DnsRecordsDiscovered) DomainEvent { return e })
	register(func(e *ZoneTransferDiscovered) DomainEvent { return e })
	register(func(e *DomainRegistrationDiscovered) DomainEvent { return e })
	register(func(e *MailSecurityDiscovered) DomainEvent { return e })
	register(func(e *BreachDataDiscovered) DomainEvent { return e })
	register(func(e *CensysHostsDiscovered) DomainEvent { return e })
	register(func(e *DomainReputationDiscovered) DomainEvent { return e })
	register(func(e *WebAssetsDiscovered) DomainEvent { return e })
	register(func(e *TlsPostureDiscovered) DomainEvent { return e })
	register(func(e *MxTlsDiscovered) DomainEvent { return e })
	register(func(e *ShodanHostsDiscovered) DomainEvent { return e })
	register(func(e *NetlasHostsDiscovered) DomainEvent { return e })
	register(func(e *IPAddressDiscovered) DomainEvent { return e })
	register(func(e *ActiveTargetApproved) DomainEvent { return e })
	register(func(e *NetblockDiscovered) DomainEvent { return e })
	register(func(e *IPReachabilityObserved) DomainEvent { return e })
	register(func(e *HostOSGuessed) DomainEvent { return e })
	register(func(e *ServiceDiscovered) DomainEvent { return e })
	register(func(e *HttpEndpointDiscovered) DomainEvent { return e })
	register(func(e *HttpRedirectObserved) DomainEvent { return e })
	register(func(e *TechnologyFingerprinted) DomainEvent { return e })
	register(func(e *HostProfileObserved) DomainEvent { return e })
	register(func(e *ServiceScriptObserved) DomainEvent { return e })
	register(func(e *TlsSecurityAssessed) DomainEvent { return e })
	register(func(e *SshPostureDiscovered) DomainEvent { return e })
}

// RegisteredEventTypeNames returns every registered event type tag, sorted. It makes the
// event vocabulary enumerable, which is what lets a consumer assert it handles all
// of it: a read model that folds no observation for a registered type is invisible
// in every report, and nothing but an enumeration of the vocabulary can catch that.
//
// Its caller today is the projection-coverage test, which walks the vocabulary and
// requires each type either to change a read model or to be excused with a stated
// reason. That makes it test-support API rather than a runtime path, and the
// dead-code check allowlists it on those grounds.
func RegisteredEventTypeNames() []string {
	out := make([]string, 0, len(eventRegistry))
	for name := range eventRegistry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// TypeName returns the stable type tag for an event: the concrete struct name,
// dereferencing pointer events. It matches the keys in the registry and is what
// the codec writes as the envelope "type".
func TypeName(evt DomainEvent) string {
	t := reflect.TypeOf(evt)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Name()
}

// AsValue returns evt in value form: if evt is a non-nil pointer to an event
// struct, the pointed-to value is returned; otherwise evt is returned unchanged.
//
// The orchestrator emits events as values during a live scan, while the codec
// decodes them as pointers on replay (see the pointer-form group in the registry
// above). Read-model folds (the inventory graph, the findings rollup, the
// eager entity snapshots) switch on the value form, so normalizing every incoming
// event through AsValue lets them fold a live value and a replayed pointer of the
// same event identically. Without it a value would fall through a pointer case arm
// (or vice versa) and the fold would silently drop the event, diverging the live
// read models from a replay of the same log.
func AsValue(evt DomainEvent) DomainEvent {
	v := reflect.ValueOf(evt)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return evt
	}
	if de, ok := v.Elem().Interface().(DomainEvent); ok {
		return de
	}
	return evt
}

// DecodeByType decodes a JSON payload into the event registered under the given
// type tag. It returns an error if the tag is unknown, which flags an event type
// that was persisted but never registered.
func DecodeByType(typeName string, data json.RawMessage) (DomainEvent, error) {
	dec, ok := eventRegistry[typeName]
	if !ok {
		return nil, fmt.Errorf("unknown event type %q: not registered", typeName)
	}
	return dec(data)
}
