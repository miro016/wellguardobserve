// Package detectors composes and runs the finding rules over the domain-event
// stream. The rule functions themselves live in the findings package
// (internal/projections/findings), one file per finding type; this
// package only assembles them into a Registry and applies them.
//
// A Rule is a pure function from a single domain event to zero or more
// events.FindingRaised. Rules read only the event they are given and set the
// finding content plus its severity and category; they do not stamp scan
// correlation metadata (EventID, ScanID, CausationID), which the orchestrator
// applies when it publishes the finding.
//
// All event types implement DomainEvent on value receivers, so every event must
// be emitted and type-asserted as a value (evt.(events.X)), never as a pointer.
// See the findings package doc for details.
//
// # Extensibility
//
// The model is built to grow. New passive or active tools contribute findings by
// adding a rule to the findings package and registering it here, not by changing
// existing code. Because a Rule keys off the event type it cares about and
// ignores everything else, many rules can observe the same event stream
// independently, and the same kind of weakness can be raised from different
// sources. Downstream, findings with the same rule and asset collapse into one
// Finding entity, so corroborating reports from multiple tools accumulate as
// provenance rather than duplicates.
//
// Note that "the same weakness from different sources" has limits: an expired
// certificate is only a real weakness when it is observed live, not when it is a
// historical Certificate Transparency log entry (crt.sh). See findings.ExpiredCert
// and the findings package doc for how that distinction is drawn.
//
// Optional tools register their rules conditionally: build a Registry with only
// the rules whose source tools are enabled for a given scan.
//
// # The live-detector bridge
//
// These rules run during collection, and the orchestrator persists what they raise
// as FindingRaised events. That makes a finding part of the capture rather than
// something derived from it, with one consequence worth stating plainly: projecting
// an existing capture consumes the findings that capture recorded, and does not
// silently re-evaluate a changed rule against its event stream. Editing a rule here
// changes what future collections raise; it does not regenerate the findings of a
// capture already on disk.
//
// So a rule change that matters to old captures needs both halves tested: this
// registry (the live producer) and the offline consumers in internal/projections.
// Moving detector execution into the projection stage is worthwhile architectural
// work and is deliberately out of scope of any single rule change.
package detectors
