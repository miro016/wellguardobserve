// Package valueobjects defines the core Value Objects and domain primitives
// that establish the Ubiquitous Language for the Vanguard bounded context.
//
// These immutable types encapsulate structural validation and business invariants,
// ensuring semantic integrity and type safety across the domain model.
//
// # Design Decisions & Architectural Alignment
//
//   - Value Object Semantics: Identity is defined entirely by attributes rather than
//     an identifier. These types enforce structural correctness upon creation, preventing
//     the proliferation of invalid domain states throughout the application layers.
//   - Bounded Context Decoupling: As fundamental primitives of the domain, these objects
//     are isolated to prevent cyclical dependencies between internal layers and to maintain
//     a clean separation of concerns within the enterprise architecture.
//   - Shared identity vocabulary: Technology normalization and CPE parsing live here
//     because several producers describe same software differently. Translators and
//     projections must share one canonical decision instead of importing tool packages
//     or growing private normalizers. Technology aliases are evidence-driven: add one
//     only after captures prove two names share product identity.
//   - Provider transport: a passive host keeps its provider's services as
//     port-and-transport pairs rather than a bare port list, because a port number
//     alone cannot distinguish tcp/53 from udp/53 and the two are different
//     services. Only an explicit tcp or udp is recorded; a provider that states
//     none leaves the transport empty, which means unknown. Unknown is never
//     resolved to tcp, and neither a well-known port nor an application protocol
//     counts as transport evidence.
//   - Provider observation time: passive host value objects preserve the provider's
//     timestamp separately from the domain event's scan time. Facts projections use it
//     to date host and service assets without losing when Vanguard observed the claim.
//   - Certificate serial canonicalization: CanonicalCertSerial lives here for the same
//     decoupling reason as technology normalization. The domain entities build the
//     canonical certificate asset key from it, and the collection translators normalize a
//     serial as they read a tool result; neither layer may import the other, so the one
//     implementation belongs in this leaf package.
package valueobjects
