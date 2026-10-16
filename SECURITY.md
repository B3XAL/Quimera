# Security policy

## Supported version

Security fixes are applied to the latest release on `main`.

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Use GitHub's private security-advisory form for
this repository and include the affected version, reproduction steps, impact and any suggested
mitigation. Do not include live-target credentials or customer traffic. Maintainers should
acknowledge a report within 7 days and coordinate disclosure after a fix is available.

## Security boundaries

- Analysis is local and offline. Quimera has no telemetry, updater or cloud service.
- Passive analysis is the default. Every feature that sends additional target requests is clearly
  labelled and opt-in.
- The browser bridge is off by default, binds only to loopback, caps request bodies at 1 MiB,
  validates extension origins and requires a random pairing token for ingestion and scope reads.
Scope synchronization exposes only bounded hosts derived from observed HTTP(S) URLs; it does not
expose Burp configuration or grant browser permissions.
The ingest endpoint also checks every browser snapshot against Burp Target Scope before analysis or
storage, so optional global browser collection does not populate Quimera with out-of-scope results.
- Extension-owned executors are bounded and are stopped by the Burp unload handler.
- Never use Quimera against systems without authorization.
