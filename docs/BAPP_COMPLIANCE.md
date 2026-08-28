# BApp Store readiness matrix

This is a pre-submission engineering checklist, not a PortSwigger approval. The authoritative
criteria are [PortSwigger's BApp Store submission requirements](https://portswigger.net/bappstore/submitting).

| Criterion | Evidence in this repository | Status before submission |
|---|---|---|
| Useful and sufficiently distinct | Header/auth/session/browser-runtime correlation and documented feature set | Manual reviewer decision |
| Clear, professional name | `Quimera`; same name in source, README and artifact | Ready |
| Safe and secure | Passive defaults; explicit active controls; authenticated loopback bridge; bounded parsing/queues; `SECURITY.md` | Ready; threat-model review required per release |
| Dependencies appropriate and maintained | Montoya 2026.7 is `compileOnly`; JUnit is test-only; Dependabot configured | Ready |
| No Burp/event-thread blocking | Analysis uses bounded background pools; Swing updates are marshalled to the EDT | Ready; exercise large-project test |
| Clean unload | Registered unload handler stops tab, context, bulk, HTTP and bridge resources | Ready |
| Burp networking APIs for target traffic | Active target requests use Montoya HTTP APIs; raw sockets are loopback bridge only | Ready |
| Works offline | No telemetry, remote code, CDN or service dependency | Ready |
| Handles large projects | Scope/content filtering, bounded worker queues and bounded bridge/JSON inputs | Manual stress test required |
| Correct GUI parenting/integration | Suite tab/dialogs use Burp/Swing integration | Manual UI inspection required |
| Current Montoya artifact | `net.portswigger.burp.extensions:montoya-api:2026.7` | Ready |
| Burp AI rules | This release neither uses nor declares an AI capability | Ready |

## Required manual release gate

Test the built JAR in the current Burp Suite Community and Professional releases on Windows,
macOS and Linux: load/reload/unload, temporary project, a large saved project, dark/light theme,
Proxy/Repeater/Scanner workflows, bridge disabled/enabled/bad token, port conflict, active-scan
consent, cancellation and offline startup. Inspect logs for uncaught exceptions and confirm no
threads or listener sockets remain after unload.

The submission must use the release JAR from CI, a concise store description, release notes,
repository/source URL, GPL-3.0 license and the minimum/current Burp version actually verified.

## Hosted privacy policy

`docs/privacy/index.html` mirrors `PRIVACY.md` and is ready to serve as-is. Once this repository
is public: Settings > Pages > Source: "Deploy from a branch" > Branch: `main`, folder `/docs`. The
policy URL is then `https://b3xal.github.io/Quimera/privacy/`. No build step or Actions workflow
is required for this.

See `SUBMISSION.md` for exact BApp Store submission copy.
