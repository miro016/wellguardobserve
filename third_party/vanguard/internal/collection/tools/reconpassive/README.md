# Passive reconnaissance tools

These packages query public records and third-party providers for evidence about
the customer estate without contacting the target directly. Sources include
certificate transparency, DNS, registration, mail posture, breach, search, and
host-intelligence providers.

This is a navigation folder, not a Go package. Each child package owns its
provider interaction and operational events; orchestration applies scope,
budgets, circuit breaking, and domain-event translation.
