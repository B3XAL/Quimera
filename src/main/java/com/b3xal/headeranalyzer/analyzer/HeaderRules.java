package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;

import java.util.List;

import static com.b3xal.headeranalyzer.analyzer.FieldCheck.TriggerOn.*;
import static com.b3xal.headeranalyzer.model.Confidence.*;
import static com.b3xal.headeranalyzer.model.HeaderFinding.Category.*;
import static com.b3xal.headeranalyzer.model.Severity.*;

/**
 * All HTTP header security rules with Burp-standard severity and confidence.
 *
 * Severity is assigned per the CVSS v3.1-grounded methodology documented on {@link Severity}
 * itself (the canonical source of truth every analyzer follows), not a flat per-category label.
 * In short: information-disclosure headers are LOW when they only confirm a product/framework
 * FAMILY ("Server: Apache") and MEDIUM when they disclose an exact VERSION ("Server: Apache/1.3.4")
 * or internal infrastructure that enables a direct WAF/CDN bypass; missing/misconfigured security
 * headers and CORS/cookie findings are scored by what the attack class they enable actually grants
 * under CVSS (Attack Vector/Complexity/Privileges/User Interaction, Confidentiality/Integrity/
 * Availability impact), not by "this is a security header" alone.
 */
public final class HeaderRules {

    private HeaderRules() {}

    /**
     * Bump whenever {@link #all()}'s content changes in a way existing installs should pick up
     * (new/changed severity, regex, description, ...). RuleStore persists rules to the Burp
     * project on first run, so without this, an updated jar keeps evaluating whatever stale
     * builtin rule definitions were serialized months ago, silently ignoring the code fix.
     * Bumping it makes RuleStore re-seed builtin rules from {@link #all()} on next load, while
     * leaving user-added custom rules and each rule's enabled/disabled toggle untouched.
     */
    public static final int RULES_VERSION = 12;

    public static List<HeaderRule> all() {
        return List.of(

            // ══ MANDATORY SECURITY HEADERS ══════════════════════════════════════

            new HeaderRule("Strict-Transport-Security",
                "Missing HTTP Strict Transport Security",
                "The server does not enforce HTTPS via the Strict-Transport-Security (HSTS) header. " +
                "Without HSTS, browsers can be downgraded to HTTP, enabling man-in-the-middle attacks.",
                MEDIUM, CERTAIN, SECURITY_MISSING,
                List.of(
                    new FieldCheck("(?s).*\\n.*", MATCH,
                        "Multiple HSTS field lines create ambiguous policy",
                        "More than one Strict-Transport-Security field line was received. User agents are not " +
                        "required to reconcile conflicting policies consistently; emit one canonical HSTS field.",
                        LOW, FIRM, SECURITY_MISCONFIGURED,
                        "https://www.rfc-editor.org/rfc/rfc6797.html#section-8.1"),
                    new FieldCheck("(?i)(?:^|;)\\s*max-age\\s*=\\s*\"?\\d+\"?\\s*(?:;|$)", NO_MATCH,
                        "HSTS max-age missing",
                        "The Strict-Transport-Security header is present but missing a valid 'max-age' directive. " +
                        "Without max-age, HSTS policy is not enforced.",
                        MEDIUM, CERTAIN, SECURITY_MISCONFIGURED,
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"),
                    new FieldCheck("(?i).*max-age\\s*=\\s*\"?[1-9][0-9]{0,6}\"?(?:[^0-9]|$).*", MATCH,
                        "HSTS max-age below recommended minimum",
                        "A short max-age remains a valid HSTS policy. This provisional regex result is " +
                        "contextualized numerically and retained only when the policy also declares preload.",
                        INFORMATION, TENTATIVE, ADVISABLE,
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"),
                    new FieldCheck("(?i).*max-age\\s*=\\s*\"?0\"?(?:[^0-9]|$).*", MATCH,
                        "HSTS policy explicitly disabled (max-age=0)",
                        "The HSTS field sets max-age=0, instructing browsers to remove the HSTS policy. " +
                        "Use this only for a deliberate rollback; it provides no downgrade protection.",
                        MEDIUM, CERTAIN, SECURITY_MISCONFIGURED,
                        "https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.1"),
                    new FieldCheck("(?i)^.*includeSubDomains.*$", NO_MATCH,
                        "HSTS does not cover subdomains",
                        "The HSTS policy does not include 'includeSubDomains'. " +
                        "If this domain has subdomains, they remain accessible over HTTP and may be " +
                        "targeted for MITM attacks. Add 'includeSubDomains' if all subdomains are HTTPS-capable.",
                        INFORMATION, TENTATIVE, ADVISABLE,
                        "https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.2")
                ),
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
            ),

            new HeaderRule("Content-Security-Policy",
                "Missing Content Security Policy",
                "No Content-Security-Policy header was found. Without CSP, the application cannot restrict " +
                "which scripts and resources are loaded, significantly increasing the XSS attack surface.",
                MEDIUM, CERTAIN, SECURITY_MISSING,
                List.of(), // deep CSP analysis handled by CspAnalyzer
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
            ),

            new HeaderRule("X-Frame-Options",
                "Missing Clickjacking Protection",
                "The X-Frame-Options header is absent. Without this header (or a CSP frame-ancestors directive), " +
                "the page can be embedded in iframes on attacker-controlled sites, enabling clickjacking.",
                MEDIUM, CERTAIN, SECURITY_MISSING,
                List.of(
                    new FieldCheck("(?i)^\\s*(DENY|SAMEORIGIN)\\s*$", NO_MATCH,
                        "X-Frame-Options misconfigured",
                        "X-Frame-Options is present but does not use 'DENY' or 'SAMEORIGIN'. " +
                        "Use 'DENY' to block framing entirely, or 'SAMEORIGIN' to allow only same-origin framing.",
                        LOW, CERTAIN, SECURITY_MISCONFIGURED,
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"),
                    new FieldCheck("(?i).*allow-from.*", MATCH,
                        "X-Frame-Options uses deprecated ALLOW-FROM",
                        "'ALLOW-FROM' is deprecated and not supported in modern browsers. " +
                        "Migrate to Content-Security-Policy frame-ancestors directive instead.",
                        LOW, FIRM, SECURITY_MISCONFIGURED,
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options")
                ),
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
            ),

            new HeaderRule("X-Content-Type-Options",
                "Missing MIME Sniffing Protection",
                "The X-Content-Type-Options header is absent. Without 'nosniff', browsers may " +
                "interpret responses with an incorrect MIME type, enabling MIME-sniffing attacks.",
                LOW, CERTAIN, SECURITY_MISSING,
                List.of(
                    new FieldCheck("(?i).*nosniff.*", NO_MATCH,
                        "X-Content-Type-Options not set to nosniff",
                        "X-Content-Type-Options is present but does not contain 'nosniff'. " +
                        "Set it to 'nosniff' to prevent MIME-sniffing attacks.",
                        LOW, CERTAIN, SECURITY_MISCONFIGURED,
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options")
                ),
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
            ),

            new HeaderRule("Referrer-Policy",
                "Missing Referrer Policy",
                "The Referrer-Policy header is absent. Modern browsers normally default to " +
                "strict-origin-when-cross-origin, so absence is not a vulnerability by itself. An explicit " +
                "policy is still useful when the application requires stricter or legacy-browser behaviour.",
                INFORMATION, CERTAIN, ADVISABLE,
                List.of(
                    new FieldCheck(
                        "(?i)^(no-referrer|no-referrer-when-downgrade|origin|origin-when-cross-origin|" +
                        "same-origin|strict-origin|strict-origin-when-cross-origin|unsafe-url)" +
                        "(?:\\s*,\\s*(?:no-referrer|no-referrer-when-downgrade|origin|origin-when-cross-origin|" +
                        "same-origin|strict-origin|strict-origin-when-cross-origin|unsafe-url))*$",
                        NO_MATCH,
                        "Referrer-Policy uses an unrecognised value",
                        "Referrer-Policy is present but the value is not a recognised directive. " +
                        "Browsers ignore unrecognised tokens and otherwise use the last recognised policy; " +
                        "if none is recognised, the browser default applies. " +
                        "Use a valid value such as 'strict-origin-when-cross-origin' or 'no-referrer'.",
                        LOW, CERTAIN, SECURITY_MISCONFIGURED,
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"),
                    new FieldCheck("(?i)(?:^|,)\\s*unsafe-url\\s*$", MATCH,
                        "Referrer-Policy set to unsafe-url",
                        "Referrer-Policy is set to 'unsafe-url', which sends the full URL (including path " +
                        "and query string) to all destinations, potentially exposing sensitive data.",
                        MEDIUM, CERTAIN, SECURITY_MISCONFIGURED,
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy")
                ),
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
            ),

            new HeaderRule("X-XSS-Protection",
                false, null, null, null, null, null,
                List.of(
                    new FieldCheck("^\\s*0\\s*$", NO_MATCH,
                        "X-XSS-Protection active (deprecated, recommend removing or disabling)",
                        "X-XSS-Protection is present and not set to '0'. This header is deprecated and removed " +
                        "from all modern browsers. Worse, the '1; mode=block' value can introduce " +
                        "XSS vulnerabilities in some scenarios. Best practice: set to '0' or remove the header entirely.",
                        LOW, CERTAIN, SECURITY_MISCONFIGURED,
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection")
                )
            ),

            new HeaderRule("Cache-Control",
                "Missing Cache-Control header",
                "The Cache-Control header is absent. Without explicit cache directives, sensitive responses " +
                "may be cached by browsers or intermediate proxies. Verify whether this response contains " +
                "user-specific or sensitive data that should not be cached.",
                LOW, CERTAIN, SECURITY_MISSING,
                List.of(
                    // TENTATIVE: same reasoning as the CORS wildcard finding, public caching is
                    // routinely the deliberately-correct choice, only a real problem if THIS
                    // response actually carries user-specific/sensitive data, unverified here.
                    new FieldCheck("(?i)\\bpublic\\b", MATCH,
                        "Cache-Control set to public",
                        "Cache-Control includes the 'public' directive, allowing shared caches (CDNs, proxies) " +
                        "to store and serve this response to other users. " +
                        "If the response contains user-specific or sensitive data this is a confidentiality risk.",
                        LOW, TENTATIVE, SECURITY_MISCONFIGURED,
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control")
                ),
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
            ),

            // Cross-Origin-Embedder-Policy ("missing COEP") deliberately removed: by its own former
            // description "most sites do not need this unless using SharedArrayBuffer/high-res
            // timers", which in practice means it fired on ~every site that doesn't need it,
            // pure noise even at INFORMATION severity. "Missing Cross-Origin-Resource-Policy" was
            // removed the same way later on (see that rule below, kept its invalid-VALUE check).
            // COOP stays: XS-Leaks/window.opener protection applies broadly enough to clear the bar.

            new HeaderRule("Cross-Origin-Opener-Policy",
                "Missing Cross-Origin Opener Policy",
                "The Cross-Origin-Opener-Policy (COOP) header is absent. Without it, this page's window can " +
                "keep a live window.opener reference in either direction, whether it opens another window " +
                "(window.open(), not an <a target=_blank> link, browsers now default those to noopener, a " +
                "JS-driven window.open() call does not get that default) or is itself opened by one. " +
                "Whichever side lacks COOP keeps window.opener alive, letting a malicious counterpart page " +
                "navigate/rewrite the other (reverse tabnabbing) or use the shared browsing context as a " +
                "cross-window side channel, this works today in an unmodified browser regardless of whether " +
                "this application's own outbound links happen to set rel=noopener. Add " +
                "'Cross-Origin-Opener-Policy: same-origin' to sever it unconditionally.",
                INFORMATION, CERTAIN, ADVISABLE,
                List.of(
                    new FieldCheck("(?i)^(same-origin|same-origin-allow-popups|unsafe-none|noopener-allow-popups|restrict-properties)$", NO_MATCH,
                        "Invalid Cross-Origin-Opener-Policy value",
                        "COOP is present but uses an unrecognised value. " +
                        "Recognised values include 'same-origin', 'same-origin-allow-popups', " +
                        "'unsafe-none', 'noopener-allow-popups', and 'restrict-properties'.",
                        LOW, FIRM, SECURITY_MISCONFIGURED,
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy")
                ),
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
            ),

            // Static Access-Control-Allow-Origin wildcard/null checks used to live here, removed:
            // ActiveHeaderScanner's CORS Origin-reflection battery (corsProbe) now supersedes them
            // entirely with real, verified reflection tests, CERTAIN confidence instead of a
            // TENTATIVE guess from a single passively-observed value, PLUS null-origin, HTTP-
            // downgrade, and 6 further bypass patterns this static check never covered at all. Kept
            // both reporting the same ACAO value from two different mechanisms was redundant and
            // looked like inconsistent findings for the same underlying issue.

            // ══ ADVISABLE HEADERS (LOW when missing) ════════════════════════════

            new HeaderRule("Permissions-Policy",
                "Missing Permissions Policy",
                "The Permissions-Policy header is absent. This header allows restricting access to " +
                "browser features like camera, microphone, and geolocation. " +
                "When it is absent, each feature's specification-defined default allowlist and the browser's " +
                "permission model apply; this does not mean every feature is automatically enabled. Treat this " +
                "as a defence-in-depth recommendation for pages that do not need powerful features.",
                INFORMATION, CERTAIN, ADVISABLE,
                List.of(),
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
            ),

            // "Missing Cross-Origin-Resource-Policy" removed (2026-08-18), same call as the COEP
            // removal above and for the same reason: its own description had to hedge "MOST
            // relevant for sensitive API responses/assets", the tell that this doesn't clear the
            // exploitability bar (real exploit against a standard browser TODAY, not spec-true-
            // but-conditionally-relevant) for the vast majority of ordinary responses it fired on.
            // The invalid-VALUE check below is real signal (header present but malformed) and stays.
            new HeaderRule("Cross-Origin-Resource-Policy", List.of(
                new FieldCheck("^(same-origin|same-site|cross-origin)$", NO_MATCH,
                    "Invalid Cross-Origin-Resource-Policy value",
                    "Cross-Origin-Resource-Policy is present but the value is not valid. " +
                    "Valid values are: 'same-origin', 'same-site', 'cross-origin'.",
                    LOW, FIRM, SECURITY_MISCONFIGURED,
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy")
            )),

            // No standalone rule for Access-Control-Allow-Credentials: true by itself. Credentials
            // only matter combined with a dangerous Allow-Origin (wildcard/null, caught above, or a
            // reflected/attacker-controllable origin, which only the active CORS probe below can
            // actually verify, see ActiveHeaderScanner#checkReflection). Flagging bare presence of
            // the credentials flag reported "the app allows cookies cross-origin" as if it were a
            // finding on its own, real risk requires proving the origin side is actually exploitable.

            // Access-Control-Allow-Methods TRACE check used to live here, removed: this header only
            // ever appears on an actual OPTIONS preflight response, ActiveHeaderScanner's corsProbe
            // already sends a real preflight and checks it there (see its dedicated
            // sendOptionsPreflight call), so the passive version rarely saw real data to begin with
            // and duplicated the same finding when it did.

            new HeaderRule("Allow",
                false, null, null, null, null, null,
                List.of(
                    new FieldCheck("(?i)(?:^|,)\\s*TRACE\\s*(?:,|$)", MATCH,
                        "HTTP TRACE method enabled",
                        "The Allow header advertises TRACE on this endpoint. This is capability evidence, not " +
                        "proof that TRACE echoes credentials; the active probe can verify actual behaviour.",
                        INFORMATION, FIRM, SECURITY_MISCONFIGURED,
                        "https://www.rfc-editor.org/rfc/rfc9110.html#name-trace")
                )
            ),

            // TENTATIVE: same wildcard-is-often-intentional reasoning as ACAO/Cache-Control above,
            // the "on authenticated endpoints" qualifier in the description is exactly the
            // unverified condition that keeps this from being CERTAIN.
            new HeaderRule("Timing-Allow-Origin", List.of(
                new FieldCheck("^\\*$", MATCH,
                    "Timing-Allow-Origin set to wildcard",
                    "Timing-Allow-Origin: * allows any cross-origin website to access detailed resource " +
                    "timing information (network timings, redirect chains) via the Resource Timing API. " +
                    "On authenticated endpoints this can enable timing-based side-channel attacks. " +
                    "Remove this header or restrict it to trusted origins.",
                    LOW, TENTATIVE, SECURITY_MISCONFIGURED,
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Timing-Allow-Origin")
            )),

            new HeaderRule("Public-Key-Pins", List.of(
                new FieldCheck(".*", MATCH,
                    "Deprecated HPKP header present",
                    "HTTP Public Key Pinning (HPKP) is deprecated and removed from Chrome (v67) and Firefox (v72). " +
                    "A misconfigured HPKP header can render your site permanently inaccessible to users (HPKP DoS). " +
                    "Remove this header and rely on HSTS + Certificate Transparency instead.",
                    INFORMATION, CERTAIN, SECURITY_MISCONFIGURED,
                    "https://www.rfc-editor.org/rfc/rfc7469")
            )),

            new HeaderRule("Public-Key-Pins-Report-Only", List.of(
                new FieldCheck(".*", MATCH,
                    "Deprecated HPKP-Report-Only header present",
                    "HTTP Public Key Pinning (HPKP) is deprecated. The report-only variant is harmless but " +
                    "serves no purpose in modern browsers. Remove this header.",
                    INFORMATION, CERTAIN, SECURITY_MISCONFIGURED,
                    "https://www.rfc-editor.org/rfc/rfc7469")
            )),

            // ══ INFORMATION DISCLOSURE HEADERS ══════════════════════════════════
            // Severity follows Severity.java's CVSS methodology, not a blanket level: bare
            // product-family disclosure ("Apache") is LOW (recon only, needs chaining), an exact
            // VERSION string ("Apache/1.3.4") escalates one bucket to MEDIUM (collapses the
            // attacker's targeted-exploit search regardless of which version it is), and headers
            // that reveal internal infrastructure enabling a direct WAF/CDN bypass are MEDIUM too.

            // Bare-vs-versioned split (see Severity's version-escalation rule): two mutually
            // exclusive FieldChecks on the same "does the value contain a digit" heuristic, plus
            // the existing NO_MATCH exclusion for known CDN/PaaS identity strings on both, so
            // "cloudflare"/"AmazonS3"/etc. still don't fire at all (still visible in Tech via
            // TechFingerprinter). "Apache/2.4.41"/"Microsoft-IIS/10.0" -> versioned/MEDIUM;
            // "Apache"/"nginx" -> family/LOW; "cloudflare"/"Fastly" -> neither fires.
            new HeaderRule("Server",
                false, null, null, null, null, null,
                List.of(
                    new FieldCheck("(?i)^(?!(?:" + KnownInfrastructure.CDN_SERVER_ALT + ")$)(?=.*\\d).*", MATCH,
                        "Server exact version disclosure",
                        "The 'Server' header reveals the web server software AND its exact version. " +
                        "This lets an attacker go straight to searching known CVEs/exploits for that specific " +
                        "version instead of a generic product, materially narrowing their targeted-attack effort. " +
                        "Remove or redact the version component of this header.",
                        MEDIUM, CERTAIN, INFORMATION_DISCLOSURE),
                    new FieldCheck("(?i)^(?!(?:" + KnownInfrastructure.CDN_SERVER_ALT + ")$)(?!.*\\d).*", MATCH,
                        "Server technology family disclosure",
                        "The 'Server' header reveals the web server software family, but not an exact version. " +
                        "This aids reconnaissance but does not by itself point to a specific known vulnerability. " +
                        "Remove or redact this header.",
                        LOW, CERTAIN, INFORMATION_DISCLOSURE)
                )
            ),

            new HeaderRule("X-Powered-By",
                false, null, null, null, null, null,
                List.of(
                    new FieldCheck(".*[0-9].*", MATCH,
                        "X-Powered-By exact version disclosure",
                        "The 'X-Powered-By' header reveals the backend technology stack AND its exact version " +
                        "(e.g., 'PHP/8.1.2'). This lets an attacker go straight to version-specific CVEs/exploits. " +
                        "Remove this header.",
                        MEDIUM, CERTAIN, INFORMATION_DISCLOSURE),
                    new FieldCheck(".*[0-9].*", NO_MATCH,
                        "X-Powered-By technology family disclosure",
                        "The 'X-Powered-By' header reveals the backend technology family (e.g., 'ASP.NET', " +
                        "'Express') without an exact version. Aids reconnaissance. Remove this header.",
                        LOW, CERTAIN, INFORMATION_DISCLOSURE)
                )
            ),

            new HeaderRule("X-Generator",
                false, null, null, null, null, null,
                List.of(
                    new FieldCheck(".*[0-9].*", MATCH,
                        "CMS/framework exact version disclosure via X-Generator",
                        "X-Generator reveals the exact version of the framework or CMS that generated this " +
                        "response (e.g., 'WordPress 6.4.2'). Attackers can target known CVEs for that version. " +
                        "Remove it to reduce the attack surface.",
                        MEDIUM, CERTAIN, INFORMATION_DISCLOSURE),
                    new FieldCheck(".*[0-9].*", NO_MATCH,
                        "CMS/framework family disclosure via X-Generator",
                        "X-Generator reveals the framework or CMS family that generated this response, without " +
                        "an exact version. Remove it to reduce the attack surface.",
                        LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // Exact exploitable version (not just "this is ASP.NET"), bumped to MEDIUM.
            new HeaderRule("X-AspNet-Version",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "ASP.NET version disclosure",
                    "X-AspNet-Version reveals the ASP.NET version. Attackers can use this to find " +
                    "version-specific vulnerabilities. Disable via httpRuntime enableVersionHeader=false.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE,
                    "https://learn.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.enableversionheader"))
            ),

            new HeaderRule("X-AspNetMvc-Version",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "ASP.NET MVC version disclosure",
                    "X-AspNetMvc-Version reveals the ASP.NET MVC version. Remove via MvcHandler.DisableMvcResponseHeader.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // X-Powered-By-ASP.NET, X-Powered-By-PHP and X-PHP-Version removed (2026-08-24): none
            // of these are real headers any mainstream software actually sends, verified against
            // IIS/Kestrel/ASP.NET Core and PHP/Apache/php.ini docs. The real-world signal is a
            // single "X-Powered-By" header with VALUE "ASP.NET" or "PHP/8.1.2", already covered by
            // the generic X-Powered-By rule above (family/version split on the value). These three
            // were dead rules that could never fire against real traffic.

            new HeaderRule("X-Drupal-Cache",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Drupal CMS family disclosure via X-Drupal-Cache",
                    "X-Drupal-Cache reveals that Drupal CMS is in use and exposes its page cache hit/miss status. " +
                    "Can be suppressed via Drupal performance settings or proxy header stripping.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("X-Framework",
                false, null, null, null, null, null,
                List.of(
                    new FieldCheck(".*[0-9].*", MATCH,
                        "Application framework exact version disclosure",
                        "X-Framework reveals the exact version of the application framework in use " +
                        "(e.g., 'Symfony/6.2'). Attackers can target known CVEs for that version. Remove it.",
                        MEDIUM, CERTAIN, INFORMATION_DISCLOSURE),
                    new FieldCheck(".*[0-9].*", NO_MATCH,
                        "Application framework family disclosure",
                        "X-Framework reveals the application framework family (e.g., Laravel, Symfony), without " +
                        "an exact version. Remove it.",
                        LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // X-Powered-CMS and X-CMS-API removed (2026-08-24): no evidence any real, widely-
            // deployed CMS/API platform sends either by default, both were unverifiable/dead rules.

            // The real Joomla header (confirmed against Joomla's own issue tracker, removed
            // upstream in 4.0 for exactly this disclosure reason) is X-Content-Encoded-By, not
            // "X-Powered-By-Joomla", which doesn't exist. It carries a version by default
            // ("Joomla! 3.9.2"), same bare-vs-versioned split as X-Generator/X-Framework.
            new HeaderRule("X-Content-Encoded-By",
                false, null, null, null, null, null,
                List.of(
                    new FieldCheck(".*[0-9].*", MATCH,
                        "Joomla CMS exact version disclosure via X-Content-Encoded-By",
                        "X-Content-Encoded-By reveals the exact Joomla CMS version in use (e.g., 'Joomla! 3.9.2'). " +
                        "Attackers can target known CVEs for that version. Remove via a plugin that strips this " +
                        "header, or Joomla 4.0+ which no longer sends it by default.",
                        MEDIUM, CERTAIN, INFORMATION_DISCLOSURE),
                    new FieldCheck(".*[0-9].*", NO_MATCH,
                        "Joomla CMS family disclosure via X-Content-Encoded-By",
                        "X-Content-Encoded-By reveals that Joomla CMS is in use, without an exact version. " +
                        "Remove it to reduce fingerprinting surface.",
                        LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("X-Runtime",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Ruby on Rails family disclosure (response time fingerprint)",
                    "X-Runtime exposes server response time in seconds and is typically added by Ruby on Rails. " +
                    "This confirms the Rails family (no version). Remove via config.middleware.delete ActionDispatch::Static.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // These four reveal actual backend hostnames/IPs behind the CDN/WAF, worth more than a
            // generic tech-fingerprint disclosure: they enable direct-to-origin attacks that bypass
            // the CDN/WAF entirely. Bumped to MEDIUM.
            new HeaderRule("X-Server",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Internal server name disclosure",
                    "X-Server reveals internal server naming, useful for attackers mapping infrastructure. Remove it.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("X-Backend-Server",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Backend server disclosure",
                    "X-Backend-Server reveals the name or IP of the backend server behind proxies/CDNs. " +
                    "This is valuable for targeted attacks on internal infrastructure. Remove it.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("X-Origin-Server",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Origin server disclosure",
                    "X-Origin-Server reveals the origin server address. This can be used to bypass CDN/WAF protection. Remove it.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("X-Backend-Name",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Backend service name disclosure",
                    "X-Backend-Name reveals internal service/container names, aiding infrastructure mapping.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // Always carries an exact module version by definition (e.g. "1.13.35.2-0"), so it
            // lands at the versioned/MEDIUM tier like the other always-versioned headers
            // (X-AspNet-Version, X-PHP-Version...), no per-product exception.
            new HeaderRule("X-Mod-Pagespeed",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "PageSpeed module exact version disclosure",
                    "X-Mod-Pagespeed reveals that the Google PageSpeed Apache/Nginx module is in use, " +
                    "along with its exact version. Remove or suppress this header.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // Its presence confirms the Envoy proxy family, same signal as X-Runtime/X-Drupal-Cache
            // (both LOW), the timing value itself is not attacker-actionable.
            new HeaderRule("X-Envoy-Upstream-Service-Time",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Envoy proxy family disclosure",
                    "X-Envoy-Upstream-Service-Time confirms an Envoy proxy is in the request path and reveals " +
                    "backend response times, enabling infrastructure fingerprinting and timing analysis.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // Always an exact version by definition, but of a bespoke application with no public
            // CVE corpus (unlike X-AspNet-Version/X-PHP-Version which name a widely-deployed
            // product), so the bump lands at LOW rather than MEDIUM.
            new HeaderRule("X-Version",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Application version disclosure",
                    "X-Version reveals the exact application version, which can help correlate against any " +
                    "vulnerabilities disclosed for this specific application elsewhere.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("X-Cache",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Cache infrastructure disclosure",
                    "X-Cache reveals caching infrastructure details and hit/miss status, " +
                    "which aids cache poisoning attack research.",
                    INFORMATION, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("X-Cache-Hits",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Cache hit count disclosure",
                    "X-Cache-Hits exposes the number of cache hits, revealing internal system behaviour.",
                    INFORMATION, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("X-Cache-Hit",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Cache status disclosure",
                    "X-Cache-Hit reveals caching status and infrastructure details.",
                    INFORMATION, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // CERTAIN, not TENTATIVE: this is the exact same bare-presence ".*" MATCH shape as
            // every other INFORMATION_DISCLOSURE header in this file, detection is 100%
            // deterministic and the disclosure is unconditionally true once present, no "if this
            // happens to be sensitive" hedge the way e.g. Cache-Control: public has.
            //
            // LOW, not INFORMATION: unlike pure infrastructure noise (X-Cache, Via, cache hit
            // counts, none of which correlate to any specific application/library version), this
            // is a precise timestamp tied to the SERVED CONTENT itself. A well-known recon
            // technique correlates an unmodified vendored static file's Last-Modified against
            // known release dates (jQuery/Bootstrap/etc. CDN-vendored copies are the common case)
            // to infer its exact version without ever seeing a version string. Quimera doesn't
            // (and won't, it's deliberately offline, no release-date database) do that
            // correlation itself, so this stays well short of MEDIUM/exact-version-disclosure,
            // but "helps an attack, needs chaining with something else first" is exactly LOW's
            // own definition, a materially better fit than "no exploitable vector beyond default
            // probing" (INFORMATION).
            new HeaderRule("Last-Modified",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Content modification timestamp disclosure",
                    "Last-Modified reveals when content was last changed. On an unmodified vendored " +
                    "static file (a CDN-style copy of a JS/CSS library, for example) this timestamp can " +
                    "be correlated against known release dates to infer its exact version without ever " +
                    "seeing a version string, the same recon value a version disclosure gives, just one " +
                    "extra correlation step removed. Also aids cache poisoning and content-change " +
                    "pattern-recognition. Consider suppressing this header.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("Via",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Proxy infrastructure disclosure via Via header",
                    "The Via header reveals intermediate proxy or gateway infrastructure details. " +
                    "Remove if not required by the application.",
                    INFORMATION, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("Expect-CT",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Obsolete Expect-CT header present",
                    "The Expect-CT header is deprecated (Chrome 107+) and no longer provides security benefits. " +
                    "Remove it to maintain a clean security configuration.",
                    INFORMATION, CERTAIN, INFORMATION_DISCLOSURE,
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT"))
            ),

            new HeaderRule("X-Debug-Token",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Symfony debug token disclosure",
                    "X-Debug-Token is added by the Symfony web profiler in debug mode. " +
                    "It confirms debug mode is active and can be used to retrieve the profiler URL. " +
                    "Disable the Symfony profiler in production.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE,
                    "https://symfony.com/doc/current/profiler.html"))
            ),

            // Direct URL to a live debug profiler in production, not just "this uses Symfony",
            // an active exposure with a clickable path to full request data/env vars/stack traces.
            new HeaderRule("X-Debug-Token-Link",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Symfony profiler URL exposed",
                    "X-Debug-Token-Link provides the direct URL to the Symfony web profiler for this request. " +
                    "The profiler exposes full request/response data, environment variables, and stack traces. " +
                    "Disable in production immediately.",
                    MEDIUM, FIRM, INFORMATION_DISCLOSURE,
                    "https://symfony.com/doc/current/profiler.html"))
            ),

            new HeaderRule("X-Application-Context",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Spring Boot application context disclosure",
                    "X-Application-Context is added by Spring Boot and reveals the application name, " +
                    "active profiles, and port. This aids targeted exploitation of Spring-specific vulnerabilities.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // Always an exact version by definition, same tier as the other always-versioned
            // product headers (X-AspNet-Version, X-PHP-Version), and Exchange/OWA in particular
            // has a large public CVE surface (e.g. ProxyLogon), MEDIUM not LOW.
            new HeaderRule("X-OWA-Version",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Outlook Web App exact version disclosure",
                    "X-OWA-Version reveals the exact Microsoft Exchange / Outlook Web App version. " +
                    "Attackers use this to target known Exchange vulnerabilities. Remove via Exchange custom headers.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("X-Drupal-Dynamic-Cache",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Drupal family disclosure via dynamic cache status",
                    "X-Drupal-Dynamic-Cache reveals Drupal's dynamic page cache status (HIT/MISS/UNCACHEABLE). " +
                    "Confirms Drupal is in use and exposes caching behaviour. Remove via Drupal performance settings.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("X-WP-Nonce",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "WordPress nonce disclosure",
                    "X-WP-Nonce exposes a WordPress nonce token in response headers. " +
                    "Nonces are single-use tokens that authorise WordPress REST API requests. " +
                    "Exposing them in headers may allow CSRF or REST API abuse if intercepted.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE,
                    "https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/#cookie-authentication"))
            ),

            // ── Framework/platform runtime headers ──────────────────────────────

            // Downgraded LOW -> INFORMATION (2026-08-24): the value is 100% developer-defined free
            // text with no fixed schema, most real-world Server-Timing headers are auto-added by
            // a CDN/framework with generic metric names ("total;dur=123.4", "cache;desc=HIT") and
            // disclose nothing. It CAN occasionally carry a sensitive custom metric name if a
            // specific backend chose to put one there, but that's conditional on this exact
            // deployment, not something the header structurally guarantees, the same "in practice
            // it frequently..." hedge that already got COEP/CORP-missing removed elsewhere in this
            // file. It does NOT reveal the OS or anything else with a fixed meaning, worth a manual
            // glance, not an automatic LOW finding. Still worth flagging (see it in Quimera itself,
            // not spammed into Burp's shared Issues tab, INFORMATION severity is excluded there).
            new HeaderRule("Server-Timing", List.of(
                new FieldCheck(".*", MATCH,
                    "Server-Timing header present",
                    "Server-Timing exposes server-side performance metrics intended for browser DevTools. " +
                    "The metric names are entirely defined by this application, most are generic timing " +
                    "data, but worth a manual look, some backends put internal service/query names in " +
                    "there (e.g., 'Server-Timing: db;dur=14.2,auth-svc;desc=\"us-east-1\"'). " +
                    "Remove or redact it in production if it does carry anything internal.",
                    INFORMATION, CERTAIN, INFORMATION_DISCLOSURE)
            )),

            new HeaderRule("X-Pingback", List.of(
                new FieldCheck(".*", MATCH,
                    "WordPress XML-RPC pingback endpoint disclosed",
                    "X-Pingback reveals the URL of the WordPress XML-RPC endpoint (usually /xmlrpc.php). " +
                    "XML-RPC is a legacy API frequently abused for credential brute-force attacks " +
                    "(bypassing login-attempt limits) and DDoS amplification via the multicall method. " +
                    "Disable XML-RPC if not required, or restrict access to trusted IPs.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE)
            )),

            // Same direct-origin-bypass reasoning that already puts X-Server/X-Backend-Server at
            // MEDIUM: this reveals the real hostname behind a CDN/WAF, enabling a bypass.
            new HeaderRule("X-Forwarded-Host", List.of(
                new FieldCheck(".*", MATCH,
                    "Internal hostname disclosed via X-Forwarded-Host",
                    "X-Forwarded-Host appearing in a response header reveals the original Host header " +
                    "value as seen by the proxy, which can expose the real hostname behind a CDN or WAF. " +
                    "Knowing the origin hostname can allow attackers to bypass CDN/WAF protections " +
                    "by directly targeting the origin server. Remove from response headers.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE)
            )),

            new HeaderRule("X-Forwarded-Server", List.of(
                new FieldCheck(".*", MATCH,
                    "Internal server name disclosed via X-Forwarded-Server",
                    "X-Forwarded-Server reveals the internal hostname or FQDN of the proxy or origin server " +
                    "handling this request. Internal hostnames aid infrastructure mapping and may " +
                    "allow attackers to target specific internal nodes, and can enable direct-to-origin " +
                    "attacks that bypass a CDN/WAF entirely. Remove from response headers.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE)
            )),

            new HeaderRule("X-Real-IP", List.of(
                new FieldCheck(".*", MATCH,
                    "IP address disclosed via X-Real-IP response header",
                    "X-Real-IP is being returned in the response, revealing an IP address " +
                    "(typically the client's real IP or an internal proxy IP). " +
                    "If this is an internal or private IP, it aids infrastructure reconnaissance. " +
                    "This header should only be used in requests from proxy to backend, not in responses.",
                    INFORMATION, FIRM, INFORMATION_DISCLOSURE)
            )),

            // CF-Ray, X-Amz-Request-Id, X-Amz-Id-2, X-Azure-Ref, X-Served-By, X-Timer and
            // X-LiteSpeed-Cache used to be blanket ".*" MATCH rules here, but they are pure
            // CDN/cloud identity strings with zero ambiguity, TechFingerprinter already reports
            // them in the Technology inventory, so keeping them as issues here was duplicate
            // noise. Removed as HeaderRule (no longer generate an issue); unchanged in Tech.

            // ── Well-known application/platform headers (added 2026-08-24) ──────────────────
            // Each verified against the vendor's own docs/issue tracker/source before adding,
            // same bar the Joomla fix above was held to: no header goes in here on a guess.

            // Jenkins sends this on every response by default, always a bare exact version
            // ("2.401.3"). Jenkins has a very large public CVE corpus across core and plugins,
            // MEDIUM not LOW, same tier as X-OWA-Version/Liferay-Portal below.
            new HeaderRule("X-Jenkins",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Jenkins exact version disclosure",
                    "X-Jenkins reveals the exact Jenkins version running. Jenkins has a large public CVE " +
                    "corpus across core and plugins; attackers can target known exploits for that specific " +
                    "version directly. Strip it at a reverse proxy in front of Jenkins.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("X-Jenkins-Session",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Jenkins family disclosure via X-Jenkins-Session",
                    "X-Jenkins-Session confirms a Jenkins instance without disclosing its version. " +
                    "Strip it at a reverse proxy in front of Jenkins.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // Elasticsearch itself adds this to every authenticated response so official clients
            // can verify server identity, value is always the bare string "Elasticsearch" (no
            // version). LOW: confirms the product only. If the endpoint is reachable without
            // authentication at all, that's a separate, far more severe finding on its own.
            new HeaderRule("X-elastic-product",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Elasticsearch family disclosure via X-elastic-product",
                    "X-elastic-product confirms this endpoint is Elasticsearch (added by Elasticsearch itself " +
                    "for client server-identity verification), without disclosing a version. If this endpoint " +
                    "doesn't also require authentication, treat unauthenticated Elasticsearch access as a " +
                    "separate, much higher-severity finding, this header alone only confirms the product.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // Atlassian products (Jira, Confluence, Bitbucket Server) add these to responses.
            // X-ASEN carries a support entitlement number, not a version, family-only like X-AREQUESTID.
            // Given Atlassian's frequent, actively-exploited RCE CVEs (Confluence OGNL, Jira auth
            // bypass chains), confirming the product family is still worth a LOW finding.
            new HeaderRule("X-AREQUESTID",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Atlassian product family disclosure via X-AREQUESTID",
                    "X-AREQUESTID is added by Atlassian products (Jira, Confluence, Bitbucket Server). Confirms " +
                    "the product family, relevant given Atlassian's history of actively-exploited RCE CVEs.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("X-ASEN",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Atlassian license/product disclosure via X-ASEN",
                    "X-ASEN discloses an Atlassian support entitlement number, confirming a licensed Atlassian " +
                    "instance (Jira/Confluence). Combine with other recon to target known Atlassian CVEs.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // Symfony's built-in HttpCache reverse proxy adds this when trace_level isn't 'none',
            // revealing cache hit/miss and route details. Confirms the Symfony family, same
            // shape/tier as X-Drupal-Cache above.
            new HeaderRule("X-Symfony-Cache",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Symfony family disclosure via X-Symfony-Cache",
                    "X-Symfony-Cache is added by Symfony's built-in HTTP reverse proxy (HttpCache) and reveals " +
                    "cache hit/miss/route details. Confirms the Symfony framework family. Disable via the " +
                    "trace_level config option.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // Liferay sends the FULL edition+version string by default ("Liferay Portal Community
            // Edition 7.4.0 CE GA1"), controlled by the http.header.version.verbosity portal
            // property. Real RCE history (e.g. CVE-2020-7961), MEDIUM not LOW.
            new HeaderRule("Liferay-Portal",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Liferay Portal exact version disclosure",
                    "Liferay-Portal reveals the exact Liferay Portal edition and version. Attackers can target " +
                    "known CVEs for that version directly. Set http.header.version.verbosity to 'off' in " +
                    "portal properties.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // Kibana sends both by default (originally added for XSRF protection). kbn-version is
            // always a bare exact version; kbn-name is always the bare string "kibana". Real RCE
            // history (e.g. CVE-2019-7609 prototype pollution), MEDIUM for the versioned one.
            new HeaderRule("kbn-version",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Kibana exact version disclosure",
                    "kbn-version reveals the exact Kibana version. Attackers can target known CVEs for that " +
                    "version directly. Strip via a reverse proxy or server.customResponseHeaders in kibana.yml.",
                    MEDIUM, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            new HeaderRule("kbn-name",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "Kibana family disclosure via kbn-name",
                    "kbn-name confirms a Kibana instance without disclosing its version. Strip via a reverse " +
                    "proxy or server.customResponseHeaders in kibana.yml.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // New Relic's now-deprecated "Cross Application Tracing" feature (New Relic itself
            // recommends distributed tracing instead), still occasionally seen on older agents.
            // Value is a base64-encoded blob (Account ID, App ID, transaction name/GUID), one
            // decode/correlation step from real internal detail, same LOW-tier reasoning as
            // Last-Modified above (helps an attack, needs chaining, not a bare exploit itself).
            new HeaderRule("X-NewRelic-App-Data",
                false, null, null, null, null, null,
                List.of(new FieldCheck(".*", MATCH,
                    "New Relic APM cross-application-trace data disclosure",
                    "X-NewRelic-App-Data exposes a base64-encoded blob containing the New Relic Account ID, " +
                    "Application ID, and transaction name/GUID for this endpoint (New Relic's deprecated Cross " +
                    "Application Tracing feature). Decoding it reveals internal application/service naming. " +
                    "Disable cross application tracing in the New Relic agent config.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE))
            ),

            // ── Deprecated headers ───────────────────────────────────────────────

            new HeaderRule("Feature-Policy", List.of(
                new FieldCheck(".*", MATCH,
                    "Deprecated Feature-Policy header present",
                    "Feature-Policy was renamed to Permissions-Policy and is now deprecated. " +
                    "Modern browsers use Permissions-Policy instead. " +
                    "Replace with 'Permissions-Policy' to ensure the policy is actually enforced.",
                    INFORMATION, CERTAIN, INFORMATION_DISCLOSURE,
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy")
            )),

            new HeaderRule("X-Content-Security-Policy", List.of(
                new FieldCheck(".*", MATCH,
                    "Deprecated X-Content-Security-Policy header present",
                    "X-Content-Security-Policy was the experimental Firefox/IE prefix for CSP and is now deprecated. " +
                    "It has no effect in modern browsers. If this is the only CSP header present, " +
                    "the application has NO enforced Content Security Policy. " +
                    "Replace with the standard 'Content-Security-Policy' header.",
                    INFORMATION, CERTAIN, INFORMATION_DISCLOSURE,
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy")
            )),

            new HeaderRule("X-WebKit-CSP", List.of(
                new FieldCheck(".*", MATCH,
                    "Deprecated X-WebKit-CSP header present",
                    "X-WebKit-CSP was the experimental WebKit/Chrome prefix for CSP and is now deprecated. " +
                    "It has no effect in modern browsers. If this is the only CSP header present, " +
                    "the application has NO enforced Content Security Policy. " +
                    "Replace with the standard 'Content-Security-Policy' header.",
                    INFORMATION, CERTAIN, INFORMATION_DISCLOSURE,
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy")
            )),

            new HeaderRule("X-Redirect-By", List.of(
                new FieldCheck(".*", MATCH,
                    "Redirect mechanism and CMS family disclosed via X-Redirect-By",
                    "X-Redirect-By reveals the component responsible for the redirect " +
                    "(e.g., 'WordPress', 'Polylang', 'The SEO Framework'). " +
                    "This confirms CMS platform usage and internal redirect handling details. " +
                    "Remove this header to reduce fingerprinting surface.",
                    LOW, CERTAIN, INFORMATION_DISCLOSURE)
            ))
        );
    }
}
