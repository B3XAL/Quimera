<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/Quimera-card.png">
  <img src="Quimera.png" alt="Quimera logo" width="960">
</picture>

# Quimera

**A Burp Suite extension that actually understands HTTP security headers, cookies, tokens, sessions and browser storage, not just greps for their names.**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://openjdk.org/)
[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Montoya%20API-red.svg)](https://portswigger.net/burp)

</div>

---

Every scanner flags a missing `X-Frame-Options`. Almost none of them know the difference between
`Server: Apache` and `Server: Apache/2.4.41`, know that flagging CORS wildcards on a font file is
noise, know that a JWT with `alg: none` is a completely different severity than one that just
lacks an `aud` claim, know whether logout actually kills the session server-side, or bother
checking whether your session token quietly ended up in `localStorage` next to a Firebase auth
cache. Quimera does.

It's not a bigger regex list. It's a rule engine with a CVSS-grounded severity model, active
probing (CORS bypass battery, TRACE, HSTS downgrade, JWT forgery, session-invalidation replay),
JWT/Basic/Bearer/API-key recognition across headers, cookies **and** the URL query string, static
analysis of what your app's own JavaScript is doing with `localStorage`/`sessionStorage`/
`document.cookie`, and an optional browser-side companion that reads real runtime values instead
of guessing from response bodies. All offline, all passive-by-default, zero external dependencies,
one jar.

## Why it exists

Most header-analysis extensions either flood you with every technically-true finding regardless of
exploitability, or hardcode a handful of headers and call it a day. Quimera was built the other
way around: every finding has to survive the question *"would this actually matter against a real,
modern browser?"* A `Server: cloudflare` doesn't get flagged, `Access-Control-Allow-Origin: *` on
a webfont doesn't get flagged, a CSP missing `base-uri` only escalates when the policy actually
relies on nonces, a security-header check doesn't fire on a 404 or an OPTIONS preflight that no
browser will ever render. Where it *does* matter, Quimera goes further than "the header is
missing": it runs a real CORS bypass battery against the live target, replays an old session
credential after a logout to prove it still works instead of assuming it doesn't, resolves JWTs
found stashed away in Web Storage back to their claims, and fingerprints known auth SDKs (Cognito,
Firebase, MSAL, Auth0, Okta, Supabase) by their actual storage key formats instead of guessing from
names.

## Features

### Passive header analysis
- 60+ built-in detection rules covering missing/misconfigured security headers (HSTS, CSP,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP...),
  information-disclosure and technology-fingerprint headers (`Server`, `X-Powered-By`, and
  verified real-world framework/platform signatures: Jenkins, Elasticsearch, Atlassian, Symfony,
  Liferay, Kibana, New Relic and more), and deprecated-header hygiene.
- Severity follows a documented CVSS-grounded methodology, not a flat "security header = bad"
  label: bare product-family disclosure is LOW, an exact version escalates to MEDIUM, an
  attack-enabling misconfiguration is scored by what it actually grants an attacker.
- Content-type, status-code and HTTP-method aware: framing/CSP/feature-policy findings don't fire
  on a JSON API response, an error page (404/405/5xx), a redirect, or an OPTIONS preflight, the
  same way they wouldn't matter to a real browser.
- Deep CSP analysis: nonce strength, wildcard/scheme sources, missing `base-uri` escalation logic,
  and a JSONP/AngularJS script-allowlist-bypass check (data ported from Google's `csp-evaluator`).

### Active probing
- CORS Origin-reflection battery: arbitrary reflection, null origin, HTTP downgrade of the site's
  own origin, subdomain-suffix and domain-concatenation bypass tricks, off-by-one truncation,
  unescaped-dot regex bypass, underscore-concatenation bypass, TRACE-via-preflight detection.
  Replays the *real* captured request (method, cookies, headers) with only Origin swapped where
  possible, not a cookie-less synthetic probe that misses auth-gated bugs.
- TRACE / Cross-Site Tracing probe.
- HTTP to HTTPS downgrade probe (is HSTS actually enforced, or just advertised?).
- JWT active probe (opt-in): forges `alg: none` and a bad-signature variant of any JWT it sees and
  replays it, so a broken verification implementation is *proven*, not just suspected from a
  passively-observed weak `alg` claim. Fires once per distinct token.
- Session invalidation probe (opt-in): replays a previously-visited request with an old,
  supposedly-dead session cookie or Bearer token to prove whether logout actually revoked it
  server-side. Two independent triggers: a cookie deletion `Set-Cookie` (the protocol-level "this
  session just ended" signal), or, for Bearer tokens (which have no such signal), the same host
  being seen with a *different* token than before, or a request to a logout-shaped path. Every
  verdict is a live differential test against a credential-stripped control request, capped so an
  app that legitimately rotates tokens on every call can't turn this into a request flood.
- Optional auto-active-scan: fires the CORS/TRACE/HSTS battery automatically on every new URL seen
  passively.

### Session lifecycle (passive)
- Stale-session replay detection: flags when a session cookie value that was previously cleared by
  a deletion `Set-Cookie` gets sent again and the server still responds as if it were valid,
  without needing an active probe, purely from traffic Quimera already saw.
- Static-session-across-logins detection: flags when a session cookie (or Bearer token) comes back
  with the *exact same value* across separate login cycles, a sign the app isn't actually rotating
  session identifiers on login.

### Cookies & Auth
- Full cookie flag analysis (Secure, HttpOnly, SameSite, `__Secure-`/`__Host-` prefix rules,
  Domain over-scoping, long-lived session cookie detection) with a built-in tracking/analytics
  cookie allowlist (Google Analytics, Facebook Pixel, Hotjar, AWS ALB affinity cookies...) so that
  noise doesn't drown out real findings.
- JWT recognition wherever it shows up: Authorization header, cookies, URL query string, or
  hardcoded in a `localStorage.setItem()` call, with claim-level analysis (`alg: none`, missing
  `exp`, missing `aud`/`iss`, lifetime thresholds).
- HTTP Basic Authentication, opaque Bearer tokens, API-key headers, and token-shaped query string
  parameters (including a dedicated, elevated finding for OAuth `client_secret` leaking into a URL).
- Web Storage analysis with four independent confidence tiers: known auth-SDK storage signatures
  (Cognito, Firebase, MSAL, Auth0, Okta, Supabase, exact key-format matches, not guesses),
  JWTs resolved through simple variable assignments, opaque (non-JWT) token literals, and
  naming-only heuristics for everything else, with severity split by where the value actually
  lives (`localStorage`, persistent and XSS-exfiltratable at leisure, is scored higher than
  `sessionStorage`, tab-scoped and shorter-lived). Cookies set via `document.cookie` client-side JS
  (which can never carry HttpOnly, by construction) get their own dedicated check.

### Browser bridge (optional)
- A companion browser extension (Quimera, a from-scratch fork of Cookie-Editor's cookie-jar
  engine) talks to Burp over a local loopback bridge and surfaces what it reads directly from the
  live page: real `localStorage`/`sessionStorage`/`document.cookie` values, and window-global
  auth-shaped values a SPA only ever populates client-side, long after the HTTP response Quimera's
  own engine parsed.
- Same known-SDK-signature/JWT/opaque-token judgment calls as the passive Web Storage analyzer,
  but landing at CERTAIN confidence instead of FIRM/TENTATIVE, because the extension already read
  the real runtime value instead of guessing from response-body text.
- Findings feed Burp's Issues tab the same way HTTP-driven findings do, same dedup, same
  remediation text, clearly marked as browser-sourced since there's no real HTTP transaction behind
  them.

### Rules engine
- Every built-in rule is user-editable: disable it, tweak the regex, change severity/confidence, or
  write entirely new custom rules from scratch, all from the Rules tab.
- Import/export the whole rule set as JSON.

### Workflow
- Grouped Logger view (findings grouped by issue across every URL of a domain, not a wall of
  per-request rows), with a per-request affected-URLs table that shows status, method and
  Content-Length, filterable (include or exclude) by path, status and length.
- Advisory panel alongside the raw Request/Response view, the full finding description and
  remediation guidance in place, the same way Burp's own Issue Advisory tab works.
- Bulk passive re-analysis or active scan of an entire target/host, one-click retest of a specific
  finding, an in-app tech-fingerprint inventory, and an optional Burp Collaborator inspector for
  out-of-band header injection testing.
- Findings feed Burp's native Issues tab too (deduplicated per host, informational-only findings
  kept out of it to avoid noise there while still showing in Quimera's own tabs).

## Installation

### Build from source

Use the checked-in wrapper (Java 17+):
```bash
git clone https://github.com/B3XAL/Quimera.git
cd Quimera
./gradlew clean test build
```
The release jar lands in `build/libs/`. The Montoya API is compile-only and is not bundled.

### Load into Burp
Extensions → Installed → Add → Extension type: **Java** → select the jar. That's it, no
dependencies to install separately, everything ships in one fat jar.

### Browser bridge (optional)
To get real runtime Web Storage/DOM findings instead of just body-text-based guesses, load the
companion browser extension (same GitHub org), enable **Browser Bridge** in Quimera's Settings,
and copy its generated pairing token into the browser options. Both sides communicate through a
versioned loopback-only endpoint; the bridge is disabled by default. The authenticated
`/quimera/v1/scope` endpoint exposes a bounded snapshot of hosts observed by Quimera that currently
pass Burp's scope predicate. Browser permission remains an explicit browser-side decision.
Browser snapshots may be collected globally when the user grants all-websites access, but the
`/quimera/v1/ingest` endpoint analyzes and records them only when their URL is in Burp Target Scope.

## Quick start

Quimera listens passively by default across Proxy, Repeater, Intruder, Scanner and Target traffic
(configurable in Settings), just browse the target normally and findings appear grouped in the
Headers tab as they come in. Right-click any request anywhere in Burp for one-off active
analysis, or use the Headers tab's **Analyze** button to passively re-analyze everything already
crawled, or actively sweep an entire host/target. Active probes beyond the CORS/TRACE/HSTS battery
(JWT forgery, session-invalidation replay) are opt-in switches in Settings, off by default since
they send real extra requests at the target.

## Configuration

Everything is tunable from the Settings tab: which Burp tools feed passive analysis, in-scope-only
restriction, which active probes run and whether they fire automatically on new traffic (auto
active scan, JWT active probe, session invalidation probe), per-check toggles for cookies/JWT/
auth-token/Web-Storage recognition (Cookies & Auth Rules dialog), browser bridge on/off and port, a
suppressed-headers allowlist for your own noisy internal headers, and content-type/extension skip
lists.

## Architecture

Pure Java, built against the [Montoya API](https://github.com/PortSwigger/burp-extensions-montoya-api),
zero third-party runtime dependencies by design, one dependency-free fat jar, nothing to vet,
nothing to version-conflict with other loaded extensions.

```
analyzer/   detection engine: header rules, CSP/cookie/JWT/auth/Web-Storage analyzers, session
            lifecycle tracking, active CORS/TRACE/HSTS/JWT/session-invalidation probes, tech
            fingerprinting, the rule store
browser/    the browser-bridge loopback server and the analyzers that turn what it sends into
            findings/Issues, the extension side lives in its own repo
config/     runtime-editable settings, persisted to the Burp project
context/    right-click context menu integration
model/      findings, severity/confidence model, per-URL analysis results
proxy/      the passive HTTP handler feeding everything above
scanner/    Burp-native passive scan check (feeds the Issues tab)
ui/         the suite tab: grouped logger, detail/rules/settings panels
```

## Contributing

Issues and PRs welcome. If you're adding a detection rule, the existing severity model
(`model/Severity.java`) documents the reasoning every rule is expected to follow, read it first.

## Credits

Quimera was informed by ideas, test methodology, public datasets, and security research from
PortSwigger's `additional-cors-checks`, `json-web-tokens`, `header-guardian`, `html5-auditor`, and
`js-miner`; CompassSecurity's `jwt-scanner`; Google's `csp-evaluator`; CYS4's
`SensitiveDiscoverer`; streaak's `KeyHacks`; joanbono's `gap`; and Swissky's
`PayloadsAllTheThings`. The companion browser extension is a GPL-3.0 fork of Christophe Gagnier's
Cookie-Editor.

Quimera's Java implementation, context rules, parsers, noise controls, and verdict logic are its
own. See [`CREDITS.md`](CREDITS.md) for direct repository links, licenses, the exact influence of
each project, and the distinction between adapted licensed data, methodology references, and
projects used only as research checklists.

## License

GPL-3.0, see [`LICENSE`](LICENSE). Use it, fork it, modify it, just keep it open: any distributed
fork or derivative must stay GPL-3.0 and make its source available.
