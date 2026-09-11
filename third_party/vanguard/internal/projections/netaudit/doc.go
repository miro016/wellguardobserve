// Package netaudit turns a collection's packet capture into a deterministic,
// bounded, immutable evidence model that the operator report renders beside its
// event-derived views. It is a second, independent evidence source: the capture
// corroborates that exclusion enforcement held, or exposes a possible or confirmed
// policy violation, without ever replacing the canonical domain and tool event
// streams, creating findings about the target, altering target risk, or mutating
// the append-only event log.
//
// # Two layers, both pure
//
// The package performs no filesystem I/O and reads no clock. It has two layers:
//
//   - a streaming pcap/pcapng reader ([Extract]) that accepts an io.Reader and
//     emits normalized, bounded packet [Observation] values plus capture-health
//     counters, decoding mixed link types - Ethernet, Linux cooked v1 and v2, raw
//     IP, and loopback - and degrading unsupported ptcpdump
//     metadata explicitly rather than discarding packets. Linux cooked v2 is the
//     normal link type of collected evidence, because the wrapper captures on the
//     Linux "any" pseudo-interface; gopacket has neither a decoder for that header
//     nor a link type wide enough to hold its number, so the package decodes the
//     header itself and tracks link types as the capture formats store them. A link
//     type that still has no decoder is counted as skipped and reported as its own
//     limitation, never as truncation. The input may be
//     gzipped - collected packet evidence is compressed on the VM the moment the
//     capture stops - and both forms decode to the same model, because compression
//     says nothing about the capture. Decompression is streamed, so the bounded
//     memory guarantee holds for a compressed capture too;
//   - the pcapng half of that reader walks blocks itself rather than through
//     gopacket, whose reader discards every per-packet option. Those options are
//     the evidence: opt_epb_flags carries the travel direction, and ptcpdump writes
//     the owning process into opt_comment. Frame decoding is still gopacket's; only
//     block framing and option parsing are ours. A process identity is reduced to a
//     command base name and pid, never the argument vector, so the bounded-metadata
//     rule holds. Absence stays absence: a capture without those options leaves
//     [Observation.Direction] unknown and [CaptureHealth.ProcessAttribution] false,
//     and no conclusion is drawn from either;
//   - a pure assessment ([AssessCapture]) that joins the engagement exclusion
//     rules, the domain exclusion issue rows, the active/exploit tool spans, and
//     the extracted packet conversations into per-rule verdicts and a capture
//     health status.
//
// A filesystem adapter (outside this package) discovers the capture files, reads
// the meta/log sidecars, loads the collection's config snapshot and tool-event
// spans, hashes the source capture as stored (the compressed bytes, which
// are the collected evidence), and assembles the [Model]. Keeping
// discovery and hashing out of this package lets the report stay a pure function of
// an explicit immutable input, and lets a later offline replay rebuild byte-identical
// evidence from the same event log, config snapshots, tool log, and capture hash.
//
// # Evidence discipline
//
// Packet absence is evidence only when the capture is complete: parsed to EOF,
// overlapping the collection, covering non-loopback traffic when active work ran,
// and reporting no drops or skipped traffic the check needed. A missing or broken
// capture is never rendered as "no exclusion violations"; it is an explicit
// [StatusAbsent], [StatusUnreadable], [StatusParseFailed], [StatusPartial], or
// [StatusCollectionMismatch] status with limitations.
//
// Verdicts are conservative. Positive packet evidence (an outbound target-facing
// packet to an excluded CIDR, or a TLS SNI / plaintext HTTP Host directly matching
// an excluded domain) confirms a violation even from a partial capture, because
// incompleteness cannot weaken a packet that was observed. Negative evidence
// (concluding a rule was honored because no matching conversation exists) is drawn
// only from a complete capture. Passive DNS lookups of excluded names are never a
// violation, and provider/API traffic is never classified as target-facing solely
// because its destination happens to fall in an excluded prefix.
//
// # Attributing a tool rejection
//
// A typed tool rejection is enforcement evidence, and it is attributed to a rule by
// the destination the rejection itself named ([ToolSpan.Destinations]), never by the
// invocation target the tool event was correlated under. The two differ in the
// common case: a zone-transfer rejection is raised under the root domain while it
// denies a nameserver, and an MX rejection denies a mail host. A rejection can deny
// more than one destination (a host and its resolved address), so all of them are
// kept and a rule matching any one of them counts the rejection once. A rejection
// whose destinations match no configured rule is reported as an
// [UnmatchedRejection] rather than silently dropped from every rule row, since an
// unattributable rejection is itself a reconciliation gap.
//
// Only bounded audit metadata leaves the capture. Payload bodies, credentials,
// cookies, request paths, banners, and raw packet bytes are never copied into the
// model; the retained pcap remains the detailed evidence.
//
// # Raw investigation projection
//
// Beside the verdict-bearing [Model], the package renders a decoded investigation
// view ([BuildRaw], [SummaryMarkdown], [RawJSONL]) of the same bounded metadata: the
// deduplicated conversations, the DNS answers, and the SNI/Host observations. The
// persistence adapter writes it to netaudit/ at the caller-provided
// projection destination (summary.md and raw.jsonl), so an operator can inspect what the capture contained without
// opening the pcap in Wireshark, and can grep or pipe the JSONL into duckdb/jq. It
// is a rebuildable projection of the immutable capture, deterministic, and carries
// no payloads; it states what the traffic was, never a policy verdict.
package netaudit
