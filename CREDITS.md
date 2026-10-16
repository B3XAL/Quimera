# Credits

Quimera's active CORS battery, JWT recognition, CSP analysis, Web Storage checks, and credential
discovery were informed by the projects below. Unless an entry explicitly says that licensed
data was adapted, Quimera uses the project as a methodology or research reference and implements
its own Java logic against the Montoya API.

- **[PortSwigger `additional-cors-checks`](https://github.com/PortSwigger/additional-cors-checks)**
  (no LICENSE file found, all rights reserved by default):
  the Origin-reflection test battery approach (null origin, subdomain-suffix and concatenation
  bypasses, off-by-one truncation, regex-escape bypass).
- **[PortSwigger `json-web-tokens`](https://github.com/PortSwigger/json-web-tokens)**
  (GPL-3.0): where a JWT can show up in a request (Authorization header, cookies) and the
  structural-validation approach for recognizing one.
- **[CompassSecurity `jwt-scanner`](https://github.com/CompassSecurity/jwt-scanner)** (MIT):
  which JWT claims are worth checking (algorithm, expiry) and how to think about severity.
- **[Google `csp-evaluator`](https://github.com/google/csp-evaluator)** (Apache-2.0): the
  JSONP/AngularJS script-allowlist-bypass hostname data and a few CSP directive checks (base-uri
  escalation, nonce strength, IP-address sources).
- **[PortSwigger `header-guardian`](https://github.com/PortSwigger/header-guardian)**
  (AGPL-3.0): the idea of a user-editable suppressed-headers allowlist.
- **[PortSwigger `html5-auditor`](https://github.com/PortSwigger/html5-auditor)** (no LICENSE
  file found, all rights reserved by default): its localStorage/sessionStorage detection approach,
  used as a baseline before building Quimera's
  own (cookie-value correlation, known-SDK signatures, resolved-variable JWT detection).
- **[CYS4 `SensitiveDiscoverer`](https://github.com/CYS4srl/SensitiveDiscoverer)** (Apache-2.0):
  its section-aware, high-specificity credential discovery methodology and curated links to
  public provider token formats. Quimera limits this
  use to passive authentication/API-key discovery and reimplements the matching and context logic.
- **[PortSwigger `js-miner`](https://github.com/PortSwigger/js-miner)** (Apache-2.0): the
  methodology of preserving the complete source assignment as match evidence and using value
  quality/entropy to grade secret confidence. Quimera
  uses its own bounded parser, assignment grammar and false-positive controls.
- **[streaak `KeyHacks`](https://github.com/streaak/keyhacks)** (no LICENSE file found): used only
  as a checklist of provider families to research against their official documentation. No
  KeyHacks text, regex, validation command
  or code is included; Quimera's passive field/context rules and noise controls are independent.
- **[joanbono `gap`](https://github.com/joanbono/gap)** (Apache-2.0): the idea of validating an
  exposed Google API key by calling it read-only against a battery of Google API endpoints and
  reporting which ones
  accepted it. Quimera's endpoint list, HTTP client, accept/reject logic (JSON status/error
  envelope parsing, image-check hardening) and consolidated single-finding-per-key reporting are
  its own implementation, no gap code or text is included.
- **[Swissky `PayloadsAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings)**
  (MIT): a secondary research reference used while reviewing CORS misconfiguration and bypass
  cases. Quimera's probes and response-verification logic are independently implemented.
- **[Cookie-Editor](https://github.com/Moustachauve/cookie-editor)** by Christophe Gagnier
  (GPL-3.0): the cookie-management foundation of Quimera's separately distributed companion
  browser extension. The browser extension retains GPL-3.0 and its original attribution; no
  Cookie-Editor code is included in this GPL-3.0 Burp JAR.

Additional non-repository technical references, including PortSwigger Web Security Academy,
OWASP cheat sheets, RFCs, MDN, vendor authentication documentation, and Corben Leo's advanced
CORS research, are linked directly from the relevant advisory or source rule rather than listed
as code-project dependencies here. Quimera preserves the notices and license obligations that
apply to material it actually incorporates; research-only references are identified as such.
