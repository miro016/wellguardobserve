# Exposure knowledge base

The knowledge base turns retained findings into prevention data. It is intentionally deterministic: saving a completed investigation does not make another LLM request.

It also provides a governed improvement loop. This is intentionally not autonomous self-modification: the worker measures, proposes, and waits for a human decision.

## Product semantics

The UI separates four states:

- `new`: first retained observation, present in the latest completed scan for the target;
- `persistent`: present now and observed in an earlier run;
- `not_observed`: retained previously but absent from the latest completed run;
- `resolved`: explicitly confirmed through the owner workflow.

`not_observed` is not a synonym for fixed. A different profile, unavailable endpoint, scope change, or interrupted request can reduce coverage. The application keeps the record visible until an owner has enough evidence to resolve it.

## Pattern model

`agent/knowledge.ts` assigns every finding a stable `patternKey` from:

1. a generic configuration category;
2. the directly observed technology, when one is available;
3. the first weakness ID, or a normalized title when no weakness is mapped.

Target hostnames, version numbers, and large numeric identifiers are removed from the normalized key. This lets equivalent observations recur across assets while keeping product-specific prevention useful. Categories are generic—identity and access, transport, domain and email, browser boundary, input handling, API surface, patch lifecycle, exposure, and configuration hygiene—rather than hard-coded around one product.

Each completed run appends immutable `knowledgeObservations` records containing the target and scan relationship, pattern key, category, technology, severity, asset type, weakness IDs, framework controls, configuration signals, and observation time. Collection rules restrict records to the target owner and the internal worker.

## Governed improvement cycle

1. A completed scan receives a deterministic quality receipt covering tool success, evidence/source coverage, finding-to-asset linkage, unresolved services, duplicate actions, and external-cache use.
2. Workspace owners and administrators can label retained finding examples as confirmed, false positive, or unclear. Feedback is attributed to the reviewer and does not rewrite the original finding.
3. Repeated signals can create only three code-defined proposal types: cap confidence for a disputed pattern, prioritize the existing unknown-service inspector, or request engineering review for an unreliable tool.
4. A workspace owner or administrator must approve a behavioral proposal. Approved values are parsed into typed directives; proposal prose is never inserted into the model prompt.
5. Applied proposals retain an application counter and timestamp, so the change remains auditable and reversible by rejecting it later.

No proposal can authorize another hostname, select a stronger profile, raise an action/rate limit, install a tool, alter source code, or create arbitrary prompt text.

## External-source cache

The worker persistently caches only third-party intelligence and catalogue responses: CVE/CWE/advisory sources, lifecycle and supply-chain context, RDAP, certificate transparency, passive host search, and pinned fingerprint packs. Cache keys cover method, URL, request body, and representation headers without retaining authorization headers. Fresh entries are reused, stale entries are conditionally revalidated when validators exist, and explicitly non-cacheable responses are skipped. A bounded stale response may be used only for source outages when the response did not require revalidation.

Customer-target HTTP/TLS/banner/port observations are excluded. This preserves the meaning of a new scan while reducing repeated consumption of public-source quotas.

The current Knowledge page can immediately aggregate legacy `findings.observations` and `runCount` values. Newly completed runs add the immutable records needed for longer retention, time-window queries, and later materialized rollups.

## Safe future extensions

- Materialize per-workspace weekly pattern counts for faster trend charts.
- Recommend preventive controls when the same pattern recurs across several owned targets.
- Compare scan-profile coverage before interpreting a missing observation.
- Add owner labels for environment, team, and service criticality.
- Offer cross-customer benchmarks only through explicit opt-in and minimum cohort thresholds; never expose target names, endpoints, evidence, or raw counts from another tenant.
- Measure correlations as correlations. Do not claim that a configuration caused an incident without separate evidence.

## Query examples

Useful future questions include:

- Which configuration category produces the most current high-severity observations?
- Which technology has the highest persistent-pattern rate?
- Which issue returned after being not observed?
- Which target repeatedly misses the same browser or identity control?
- Did a profile change reduce coverage enough to explain a missing finding?
