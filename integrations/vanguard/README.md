# Vanguard integration

Wellguard invokes the pinned Vanguard collector only through
`run_vanguard_observation`. The checked-in profile enables free passive discovery
plus bounded HTTP, HTTPS, web-info, and Wappalyzer observations. Paid providers,
zone transfer, SMTP probing, port scanning, GoScans, and its external nmap/SSLyze
runtime are disabled.

Each invocation receives a generated engagement document containing the exact
authorized root. It writes to a fresh temporary collection, builds the deterministic
offline projection, imports a bounded JSON result into Wellguard's normal tool
output, and removes the temporary files. The agent trace and `toolOutputs`
collection retain the normalized result and its digest.
