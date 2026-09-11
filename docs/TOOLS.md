# Agent tool governance

The **Agent tools** page has two related registries:

- **Installed runtime tools** is the code-owned catalogue. It shows source, revision, risk class, global enabled state, and an explicit Baseline/Standard/Active/Advanced/Unbounded grant matrix. A platform administrator can disable a non-essential tool or change its future profile grants. The finding recorder is essential and cannot be disabled.
- **Generated capabilities** contains checksum-bound declarative request plans. An administrator can create a one-step GET/body-marker probe directly, review model proposals, assign a compatible minimum profile, disable them, or remove their registry entry.

The worker synchronizes compiled metadata and immutable supported-profile boundaries on startup but preserves administrator enablement and grants. It intersects that policy with code-level profile gates before a scan begins and stores the resulting tool names in the scan request snapshot. Browser changes cannot inject a callable tool or widen a capability's implementation limits; muted cells on the matrix are deliberately unavailable.

Every completed invocation writes the existing `agentActions` audit record and a normalized `toolOutputs` record containing its inputs, parsed output, failure state, occurrence time, and output digest. Deterministic graph and report assembly may consume those outputs; the model cannot rewrite historical receipts.

# Generated capability registry

Wellguard can turn an evidence-backed coverage gap into a reusable HTTP probe without generating executable source code. The model proposes a declarative `http-probe-v1` document; server-owned code validates, fingerprints and compiles it into existing scope-guarded request primitives.

## Lifecycle

1. An investigation observes a concrete path, form, API schema, parameter, header or response marker.
2. If installed tools cannot answer a useful security question, the agent calls `propose_generated_probe` with the evidence and a bounded request plan.
3. The worker validates the plan and stores an immutable SHA-256 receipt in `generatedTools`.
4. An Unbounded run may immediately use a valid proposal only when `unboundedAutoUse` is enabled. This is the explicit non-production experimentation lane.
5. A platform administrator reviews the exact requests and assertions on **Agent tools**, then approves, rejects, disables, or assigns the lowest automatic profile.
6. Every execution is revalidated and retained in `generatedToolExecutions` with profile, hostname, request count, assertion count and outcome.

An administrator approval never changes the tool body. Any material change produces a different checksum and a new proposal.

## Capability language

`http-probe-v1` supports at most twelve ordered same-origin steps:

- `GET`
- `HEAD`
- `OPTIONS`
- `POST_JSON` with at most eight string fields and a 2 KiB body

Assertions are data comparisons, not executable expressions:

- allowed HTTP status values;
- header presence;
- bounded header substring;
- bounded body substring;
- dotted JSON-key existence.

Generated tools cannot supply a URL origin, redirect destination, IP address, DNS resolver, `Host`, `Cookie`, `Authorization`, forwarding header, file path, process, shell command, JavaScript, regular expression, callback, or external source. Responses are size-bounded, secret-shaped values are redacted from previews, and target DNS is pinned through the same `ScopeGuard` used by built-in tools.

## Profile policy

| Profile | Generated proposal | Unreviewed execution | Approved execution |
| --- | --- | --- | --- |
| Baseline | No | No | GET-only, max 2 steps |
| Standard | No | No | GET/HEAD, max 4 steps |
| Active validation | Yes | No | GET/HEAD/OPTIONS, max 6 steps |
| Advanced interactive | Yes | No | Adds bounded JSON POST, max 8 steps |
| Unbounded | Yes | Optional | All DSL methods, max 12 steps |

The runtime—not the model or browser—enforces this matrix. Choosing an incompatible minimum profile in the UI is rejected and a stale or edited checksum is blocked at execution.

## Why declarative tools

An unrestricted shell inside the observer would inherit PocketBase credentials, filesystem access and network reach. That conflicts with OWASP guidance to use narrow, least-privilege tools and creates an excessive-agency path from untrusted target content. The registry therefore uses a small capability language today. A future arbitrary-code tier should run in a separate credential-free Wasmtime/WASI service with explicit host capabilities, independent network policy, resource quotas and signed artifacts.

References:

- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [OWASP LLM06: Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [Wasmtime security model](https://docs.wasmtime.dev/security.html)
- [ProjectDiscovery template signing](https://docs.projectdiscovery.io/templates/reference/template-signing)
- [OWASP Web Security Testing Guide](https://wstg.owasp.org/latest/2-Introduction/)

## Black-box evaluation

Benchmark targets are not named in prompts, path lists, adapters, fingerprints or generated-tool templates. Coverage is built from DNS/TLS/HTTP evidence, crawling, public metadata, shipped frontend bundles, discovered schemas, forms, parameters and server responses. Target-provided status surfaces may be used only after ordinary discovery exposes them.

No black-box scanner can prove it found every issue. Wellguard reports observed coverage, failed tools, unresolved surfaces, and retained execution receipts instead of asserting completeness.
