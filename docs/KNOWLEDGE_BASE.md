# Exposure knowledge base

The knowledge base turns retained findings into prevention data. It is intentionally deterministic: saving a completed investigation does not make another LLM request.

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
