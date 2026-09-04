# Architecture

## Browser and data plane

The Angular SPA uses the official PocketBase client directly. Collection API rules enforce record ownership. Public registration is disabled because preview users are invited by an administrator.

Users can read their targets, scans, findings, TLS observations, and agent actions. They can create a `scanRequests` record only for a target they own and only in the `queued` state. Administrators can create an `admin_override` target owned by their own account after recording authorization; public and member target creation remains blocked.

## Observer plane

The Bun process claims queued requests, loads the immutable authorized target, creates a scan, and starts a LangChain investigation. Each agent tool is a small typed capability rather than a shell or generic network client.

The agent chooses investigation order and depth. One bounded discovery tool combines stored host hints, a fixed passive-host query, and safe HTTPS verification before presenting distinct services to the agent. Wildcard and EasyPanel-style missing routes are removed. The executor controls destination scope, private-address policy, request sizes, timeouts, candidate and port counts, protocol behavior, and total action budget.

## Collections

- `users`: invited application users and role.
- `targets`: hostname scope, optional owned-host hints, and authorization evidence.
- `scanRequests`: browser-to-worker queue.
- `scans`: investigation lifecycle and final summary.
- `findings`: evidence, severity, confidence, remediation, and sources.
- `tlsObservations`: structured certificate and protocol evidence.
- `agentActions`: auditable tool calls and bounded outputs.
- `agentMessages`: the application-visible LangChain transcript for each scan.

## Production image

nginx serves Angular and proxies `/api` to PocketBase. PocketBase listens only on loopback. Its administrative dashboard is blocked at nginx. The Bun observer also reaches PocketBase through loopback. Persistent state lives under `/data`.
