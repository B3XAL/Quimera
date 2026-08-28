package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.b3xal.headeranalyzer.model.Confidence.*;
import static com.b3xal.headeranalyzer.model.Severity.*;

/**
 * Deep Content-Security-Policy analysis with HIGH/MEDIUM/LOW/INFO + CERTAIN/FIRM/TENTATIVE.
 */
public final class CspAnalyzer {

    private CspAnalyzer() {}

    private static final String HDR = "Content-Security-Policy";

    private static final Pattern NONCE_PATTERN  = Pattern.compile("^'nonce-(.+)'$");
    private static final Pattern BASE64_CHARSET = Pattern.compile("^[A-Za-z0-9+/=_-]+$");
    private static final Pattern IPV4_PATTERN   = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

    public static List<HeaderFinding> analyze(String cspValue) {
        if (cspValue == null || cspValue.isBlank()) return List.of();
        List<String> policies = Arrays.stream(cspValue.split("\\n"))
                .map(String::trim).filter(s -> !s.isEmpty()).toList();
        if (policies.size() <= 1) return analyzeSingle(policies.isEmpty() ? cspValue : policies.get(0));

        // Multiple enforced CSP fields are applied simultaneously by browsers. A source or
        // keyword allowed by one policy is still blocked when another policy rejects it, so a
        // weakness is actionable only when it survives every policy. Intersect findings by their
        // stable issue name and keep the strongest assessment as representative evidence.
        Map<String, HeaderFinding> common = new LinkedHashMap<>();
        for (HeaderFinding finding : analyzeSingle(policies.get(0))) common.put(finding.issueName, finding);
        for (int i = 1; i < policies.size(); i++) {
            Map<String, HeaderFinding> current = new LinkedHashMap<>();
            for (HeaderFinding finding : analyzeSingle(policies.get(i))) current.put(finding.issueName, finding);
            common.keySet().retainAll(current.keySet());
        }
        List<HeaderFinding> combined = new ArrayList<>();
        for (HeaderFinding finding : common.values()) {
            combined.add(new HeaderFinding(finding.issueName, finding.headerName, cspValue,
                    finding.description,
                    finding.evidence + " The condition is present in all " + policies.size()
                            + " simultaneously enforced CSP policies.",
                    finding.severity, finding.confidence, finding.category, finding.referenceUrl));
        }
        return combined;
    }

    /** True only for a real directive name, not a substring inside a source or report URL. */
    public static boolean hasDirective(String cspValue, String directive) {
        if (cspValue == null || directive == null) return false;
        for (String policy : cspValue.split("\\n")) {
            if (parseDirectives(policy).containsKey(directive.toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    private static List<HeaderFinding> analyzeSingle(String cspValue) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (cspValue == null || cspValue.isBlank()) return findings;

        Map<String, List<String>> directives = parseDirectives(cspValue);

        List<String> scriptSrc  = getEffective(directives, "script-src");
        List<String> styleSrc   = getEffective(directives, "style-src");
        List<String> defaultSrc = directives.getOrDefault("default-src", List.of());
        List<String> objectSrc  = directives.getOrDefault("object-src", null);
        List<String> objectSrcEffective = getEffective(directives, "object-src");
        List<String> baseUri    = directives.getOrDefault("base-uri", List.of()); // no default-src fallback per spec

        boolean hasNonce = scriptSrc.stream().anyMatch(v -> v.startsWith("'nonce-"));
        boolean hasHash  = scriptSrc.stream().anyMatch(
                v -> v.startsWith("'sha256-") || v.startsWith("'sha384-") || v.startsWith("'sha512-"));

        // 'strict-dynamic' only takes effect alongside a nonce/hash (a bare strict-dynamic with
        // neither would block every script, so this combination is the real "modern CSP3 fallback"
        // pattern: script-src 'strict-dynamic' 'nonce-x' 'unsafe-inline' https: data:). Per spec,
        // browsers that support strict-dynamic then IGNORE every host/scheme-source expression in
        // script-src (wildcard, http:, data:, blob:...), those only exist for older browsers that
        // don't understand strict-dynamic/nonces at all. Flagging them at full MEDIUM/CERTAIN in
        // that scenario over-claims exploitability in every modern browser, so they get downgraded
        // to LOW/TENTATIVE "legacy-browser-only" notes below instead of being suppressed outright.
        boolean strictDynamicActive = contains(scriptSrc, "'strict-dynamic'") && (hasNonce || hasHash);

        // ── MEDIUM – CSP misconfigurations that severely weaken XSS protection ─

        // unsafe-inline is already correctly suppressed here whenever a nonce/hash is present
        // (CSP2 rule: browsers that understand nonces/hashes ignore unsafe-inline unconditionally,
        // no strict-dynamic needed for this specific one), so no extra gate needed on this check.
        if (contains(scriptSrc, "'unsafe-inline'") && !hasNonce && !hasHash) {
            findings.add(f(MEDIUM, CERTAIN,
                "CSP: unsafe-inline allows XSS execution",
                "'unsafe-inline' in script-src permits inline <script> blocks and event handlers, " +
                "completely defeating CSP's XSS protection. Use nonces or hashes instead.",
                "script-src contains: 'unsafe-inline'"));
        }

        // unsafe-eval is NOT neutralized by strict-dynamic, no gate here.
        if (contains(scriptSrc, "'unsafe-eval'")) {
            findings.add(f(MEDIUM, CERTAIN,
                "CSP: unsafe-eval enables dynamic code execution",
                "'unsafe-eval' in script-src allows eval(), new Function(), and similar APIs. " +
                "This significantly expands the XSS attack surface.",
                "script-src contains: 'unsafe-eval'"));
        }

        if (containsWildcard(scriptSrc)) {
            findings.add(strictDynamicActive
                ? f(LOW, TENTATIVE,
                    "CSP: wildcard in script-src (neutralized by strict-dynamic in modern browsers)",
                    "A wildcard (*) is present in script-src, but 'strict-dynamic' plus a nonce/hash makes " +
                    "browsers that support it ignore this wildcard entirely. It only still applies to older " +
                    "browsers without strict-dynamic support, so real-world exploitability is much lower than " +
                    "a bare wildcard. Consider removing the wildcard once legacy-browser support is not required.",
                    "script-src contains: * (with 'strict-dynamic' + nonce/hash also present)")
                : f(MEDIUM, CERTAIN,
                    "CSP: wildcard in script-src allows arbitrary script sources",
                    "A wildcard (*) in script-src allows scripts to be loaded from any origin. " +
                    "This completely negates CSP protection against XSS.",
                    "script-src contains: *"));
        }

        if (containsScheme(scriptSrc, "http:")) {
            findings.add(strictDynamicActive
                ? f(LOW, TENTATIVE,
                    "CSP: HTTP scheme in script-src (neutralized by strict-dynamic in modern browsers)",
                    "'http:' is present in script-src, but 'strict-dynamic' plus a nonce/hash makes browsers " +
                    "that support it ignore this scheme-source entirely. It only still applies to older " +
                    "browsers without strict-dynamic support.",
                    "script-src contains: http: (with 'strict-dynamic' + nonce/hash also present)")
                : f(MEDIUM, FIRM,
                    "CSP: HTTP scheme in script-src",
                    "'http:' in script-src allows scripts to be loaded over unencrypted HTTP from any host. " +
                    "This enables MITM injection of malicious scripts.",
                    "script-src contains: http:"));
        }

        if (directives.containsKey("default-src") && containsWildcard(defaultSrc)) {
            findings.add(f(MEDIUM, CERTAIN,
                "CSP: wildcard in default-src",
                "A wildcard (*) in default-src allows all resource types from any origin.",
                "default-src contains: *"));
        }

        // ── HIGH – allowlisted host known to enable a documented CSP bypass ────
        // Ported from Google's csp-evaluator (see CREDITS.md): a script-src entry that LOOKS like
        // a trusted, restrictive allowlist can still be a complete bypass if that host serves a
        // JSONP endpoint (reflects a caller-controlled callback parameter into executable JS) or
        // an AngularJS library build (enables the well-known Angular sandbox-escape gadgets). This
        // names an exact, documented bypass technique against an exact trusted domain, a much
        // stronger finding than "you used a wildcard".
        if (!contains(scriptSrc, "'none'")) {
            for (String value : scriptSrc) {
                if (value.equals("'self'")) {
                    findings.add(f(MEDIUM, TENTATIVE,
                        "CSP: 'self' may host JSONP/Angular/user-uploaded content",
                        "'self' in script-src is exploitable if this origin itself hosts a JSONP endpoint, " +
                        "an AngularJS library build, or user-uploaded files (e.g. an avatar/document upload " +
                        "endpoint an attacker can use to smuggle a script). Verify none of these are reachable " +
                        "on this origin.",
                        "script-src contains: 'self'"));
                    continue;
                }
                if (value.startsWith("'")) continue; // other keywords: unsafe-*, nonce-x, sha256-x...

                boolean isWildcardSub = value.startsWith("*.") || value.contains("://*.")
                        || value.contains("//*.");
                String host = hostnameOf(value);
                if (isWildcardSub && host.startsWith("*.")) host = host.substring(2);
                if (host.isEmpty() || host.indexOf('.') < 0) continue; // not a real domain

                boolean jsonpMatch;
                boolean angularMatch;
                if (isWildcardSub) {
                    jsonpMatch   = CspBypassDomains.coversWildcardDomain(CspBypassDomains.JSONP_HOSTS, host);
                    angularMatch = CspBypassDomains.coversWildcardDomain(CspBypassDomains.ANGULAR_HOSTS, host);
                } else {
                    jsonpMatch   = CspBypassDomains.JSONP_HOSTS.contains(host);
                    angularMatch = CspBypassDomains.ANGULAR_HOSTS.contains(host);
                    // Some JSONP gadgets only work if 'unsafe-eval' is also allowed, a match here
                    // alone isn't actually exploitable without it.
                    if (jsonpMatch && CspBypassDomains.JSONP_NEEDS_EVAL.contains(host)
                            && !contains(scriptSrc, "'unsafe-eval'")) {
                        jsonpMatch = false;
                    }
                }

                if (jsonpMatch || angularMatch) {
                    String bypassTxt = jsonpMatch && angularMatch ? "JSONP endpoints and Angular libraries"
                            : jsonpMatch ? "JSONP endpoints" : "Angular libraries";
                    String finalHost = host;
                    findings.add(strictDynamicActive
                        ? f(LOW, TENTATIVE,
                            "CSP: allowlisted host known to host " + bypassTxt + " (neutralized by strict-dynamic)",
                            "'" + finalHost + "' is known to host " + bypassTxt + " that would normally bypass " +
                            "this CSP, but 'strict-dynamic' plus a nonce/hash makes browsers that support it " +
                            "ignore this host-source entirely. It only still applies to older browsers without " +
                            "strict-dynamic support.",
                            "script-src contains: " + value)
                        : f(HIGH, FIRM,
                            "CSP: allowlisted host known to host " + bypassTxt,
                            "'" + finalHost + "' is a known source of " + bypassTxt + " that let an attacker " +
                            "bypass this CSP: they can load a script from an endpoint on this trusted origin " +
                            "that executes arbitrary attacker-controlled JavaScript despite the policy being " +
                            "in place. Remove this origin from script-src, or restrict it to a specific path " +
                            "known not to serve JSONP/Angular content.",
                            "script-src contains: " + value,
                            "https://github.com/google/csp-evaluator"));
                }
            }
        }

        // ── MEDIUM – missing critical directives ──────────────────────────────

        boolean hasScriptControl = directives.containsKey("script-src") || directives.containsKey("default-src");
        if (!hasScriptControl) {
            findings.add(new HeaderFinding(
                "CSP: no script source restriction defined",
                HDR, cspValue,
                "Neither 'script-src' nor 'default-src' is defined. " +
                "Scripts can be loaded from any origin, effectively making CSP useless for XSS protection.",
                "CSP header present but no default-src or script-src directive found.",
                MEDIUM, CERTAIN, Category.CSP));
        }

        // ── MEDIUM – significant misconfigurations ────────────────────────────

        if (objectSrc == null) {
            // object-src not specified – inherits from default-src
            if (defaultSrc.isEmpty() || containsWildcard(defaultSrc)) {
                findings.add(f(MEDIUM, FIRM,
                    "CSP: object-src not restricted",
                    "'object-src' is not defined and default-src does not restrict it. " +
                    "This allows <object>, <embed>, and <applet> tags, which may execute plugins (Flash, Java).",
                    "object-src not present in CSP; default-src does not restrict plugins."));
            }
        }

        // object-src/base-uri were previously only checked for "not restricted at all", an
        // EXPLICIT wildcard or bare scheme is just as exploitable and is checked here the same
        // way script-src already is, closing a real coverage gap.
        if (containsWildcard(objectSrcEffective)) {
            findings.add(f(MEDIUM, CERTAIN,
                "CSP: wildcard in object-src",
                "A wildcard (*) in object-src allows plugin content (<object>/<embed>/<applet>) to be " +
                "loaded from any origin.",
                "object-src contains: *"));
        }
        for (String scheme : List.of("http:", "data:")) {
            if (containsScheme(objectSrcEffective, scheme)) {
                findings.add(f(MEDIUM, FIRM,
                    "CSP: " + scheme + " scheme in object-src",
                    "'" + scheme + "' in object-src allows plugin content to be loaded via that scheme from " +
                    "any host, widening the attack surface for the same reasons as in script-src.",
                    "object-src contains: " + scheme));
            }
        }

        if (containsScheme(scriptSrc, "data:")) {
            findings.add(strictDynamicActive
                ? f(LOW, TENTATIVE,
                    "CSP: data: URI in script-src (neutralized by strict-dynamic in modern browsers)",
                    "'data:' is present in script-src, but 'strict-dynamic' plus a nonce/hash makes browsers " +
                    "that support it ignore this scheme-source entirely. It only still applies to older " +
                    "browsers without strict-dynamic support.",
                    "script-src contains: data: (with 'strict-dynamic' + nonce/hash also present)")
                : f(MEDIUM, CERTAIN,
                    "CSP: data: URI allowed in script-src",
                    "'data:' in script-src allows data: URI scripts, enabling XSS via injected data: URIs.",
                    "script-src contains: data:"));
        }

        if (containsScheme(scriptSrc, "blob:")) {
            findings.add(strictDynamicActive
                ? f(LOW, TENTATIVE,
                    "CSP: blob: URI in script-src (neutralized by strict-dynamic in modern browsers)",
                    "'blob:' is present in script-src, but 'strict-dynamic' plus a nonce/hash makes browsers " +
                    "that support it ignore this scheme-source entirely. It only still applies to older " +
                    "browsers without strict-dynamic support.",
                    "script-src contains: blob: (with 'strict-dynamic' + nonce/hash also present)")
                : f(MEDIUM, FIRM,
                    "CSP: blob: URI allowed in script-src",
                    "'blob:' in script-src allows blob: URI scripts. " +
                    "An attacker with XHR write capability can use blob: to bypass CSP.",
                    "script-src contains: blob:"));
        }

        // unsafe-hashes is NOT neutralized by strict-dynamic, no gate here.
        if (contains(scriptSrc, "'unsafe-hashes'")) {
            findings.add(f(MEDIUM, FIRM,
                "CSP: unsafe-hashes allows inline event handlers",
                "'unsafe-hashes' allows execution of inline event handlers (onclick, onerror, etc.). " +
                "Prefer refactoring to use external scripts with nonces.",
                "script-src contains: 'unsafe-hashes'"));
        }

        if (contains(styleSrc, "'unsafe-inline'")) {
            findings.add(f(MEDIUM, CERTAIN,
                "CSP: unsafe-inline in style-src",
                "'unsafe-inline' in style-src allows arbitrary inline <style> blocks and style attributes. " +
                "This can be abused for UI-redressing (CSS injection) attacks.",
                "style-src contains: 'unsafe-inline'"));
        }

        // ── LOW – defence-in-depth directives missing ─────────────────────────

        // Missing base-uri is a defence-in-depth gap in general (LOW), but when the policy relies
        // on nonces (or hashes + strict-dynamic) to authorize scripts, an attacker who injects a
        // <base> tag can redirect every relative script URL to an attacker-controlled origin,
        // completely undermining the nonce-based trust model, not just "some navigation hijacking".
        // That specific combination escalates to HIGH.
        boolean needsBaseUri = hasNonce || (hasHash && contains(scriptSrc, "'strict-dynamic'"));
        if (!directives.containsKey("base-uri")) {
            findings.add(needsBaseUri
                ? f(HIGH, CERTAIN,
                    "CSP: missing base-uri undermines nonce-based script authorization",
                    "'base-uri' is not defined, and this policy relies on nonces/hashes to authorize scripts. " +
                    "An attacker who can inject a <base> tag can redirect all relative (script) URLs to an " +
                    "attacker-controlled domain, completely undermining the nonce/hash-based trust model this " +
                    "policy relies on. Set 'base-uri 'none'' or 'base-uri 'self''.",
                    "base-uri directive not found in CSP; script-src relies on nonces/hashes.")
                : f(LOW, TENTATIVE,
                    "CSP: base-uri directive missing",
                    "'base-uri' is not defined. An attacker who can inject a <base> tag can redirect all " +
                    "relative URLs, hijacking navigation and resource loading. Add 'base-uri 'none'' or 'base-uri 'self''.",
                    "base-uri directive not found in CSP."));
        } else if (containsWildcard(baseUri)) {
            // A wildcarded base-uri is functionally equivalent to having none at all for this
            // specific attack, same escalation logic applies.
            findings.add(needsBaseUri
                ? f(HIGH, CERTAIN,
                    "CSP: wildcard base-uri undermines nonce-based script authorization",
                    "base-uri allows any origin (*), which is functionally equivalent to having no base-uri " +
                    "restriction at all: an attacker who injects a <base> tag can still redirect every " +
                    "relative script URL, undermining the nonce/hash-based trust model this policy relies on.",
                    "base-uri contains: *")
                : f(MEDIUM, CERTAIN,
                    "CSP: wildcard base-uri",
                    "base-uri allows any origin (*), an attacker who can inject a <base> tag can redirect " +
                    "relative URL resolution to an attacker-controlled domain.",
                    "base-uri contains: *"));
        }

        if (!directives.containsKey("form-action")) {
            findings.add(f(LOW, TENTATIVE,
                "CSP: form-action directive missing",
                "'form-action' is not defined. Form submissions may target arbitrary external origins. " +
                "Add 'form-action 'self'' to restrict where forms can submit.",
                "form-action directive not found in CSP."));
        }

        if (!directives.containsKey("frame-ancestors")) {
            findings.add(f(LOW, TENTATIVE,
                "CSP: frame-ancestors directive missing",
                "'frame-ancestors' is not defined in CSP. This directive provides clickjacking protection " +
                "alongside (or instead of) X-Frame-Options. Add 'frame-ancestors 'none'' or 'frame-ancestors 'self''.",
                "frame-ancestors directive not found in CSP."));
        }

        if (containsScheme(scriptSrc, "https:") && !directives.containsKey("script-src")) {
            findings.add(f(LOW, TENTATIVE,
                "CSP: overly broad HTTPS scheme in script-src",
                "'https:' in script-src allows scripts from any HTTPS host. " +
                "Specify explicit trusted origins instead.",
                "script-src (via default-src) contains: https:"));
        }

        boolean hasMixedContent = directives.containsKey("block-all-mixed-content") ||
                                  directives.containsKey("upgrade-insecure-requests");
        if (!hasMixedContent) {
            findings.add(f(LOW, TENTATIVE,
                "CSP: no mixed content protection",
                "Neither 'upgrade-insecure-requests' nor 'block-all-mixed-content' is defined. " +
                "Add 'upgrade-insecure-requests' to force all sub-resources to load over HTTPS.",
                "No upgrade-insecure-requests or block-all-mixed-content in CSP."));
        }

        // ── Nonce quality (any directive): a weak/short nonce undermines the whole nonce model ──

        for (Map.Entry<String, List<String>> e : directives.entrySet()) {
            for (String value : e.getValue()) {
                Matcher m = NONCE_PATTERN.matcher(value);
                if (!m.matches()) continue;
                String nonceValue = m.group(1);
                if (nonceValue.length() < 8) {
                    findings.add(f(MEDIUM, CERTAIN,
                        "CSP: nonce too short",
                        "The nonce in '" + e.getKey() + "' is shorter than 8 characters. A short nonce is " +
                        "easier to guess or brute-force, weakening the CSP's core trust mechanism, a script " +
                        "with a guessed nonce runs exactly like one the page actually authorized.",
                        e.getKey() + " contains: " + value));
                }
                if (!BASE64_CHARSET.matcher(nonceValue).matches()) {
                    findings.add(f(Severity.INFORMATION, TENTATIVE,
                        "CSP: nonce uses non-base64 characters",
                        "The nonce in '" + e.getKey() + "' contains characters outside the base64 charset, " +
                        "unusual for a properly random-generated nonce and worth checking how it's generated.",
                        e.getKey() + " contains: " + value));
                }
            }
        }

        // ── IP address as CSP source (any directive), usually a dev/debug leftover ──────────────

        for (Map.Entry<String, List<String>> e : directives.entrySet()) {
            for (String value : e.getValue()) {
                if (value.startsWith("'")) continue;
                String host = hostnameOf(value);
                if (!IPV4_PATTERN.matcher(host).matches()) continue;
                findings.add(host.equals("127.0.0.1")
                    ? f(Severity.INFORMATION, FIRM,
                        "CSP: localhost as source",
                        "'" + e.getKey() + "' allows localhost (127.0.0.1) as a source, likely a " +
                        "development/debug leftover. Verify this isn't present in the production policy.",
                        e.getKey() + " contains: " + value)
                    : f(Severity.INFORMATION, FIRM,
                        "CSP: IP address as source",
                        "'" + e.getKey() + "' has a raw IP address (" + host + ") as a source instead of a " +
                        "hostname, unusual and may indicate leftover internal/testing infrastructure.",
                        e.getKey() + " contains: " + value));
            }
        }

        // ── INFORMATION ───────────────────────────────────────────────────────

        if (!directives.containsKey("report-uri") && !directives.containsKey("report-to")) {
            findings.add(f(Severity.INFORMATION, TENTATIVE,
                "CSP: no violation reporting configured",
                "No 'report-uri' or 'report-to' directive is defined. " +
                "Adding a reporting endpoint allows detecting CSP violations in production.",
                "report-uri and report-to not found in CSP."));
        }

        return findings;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static HeaderFinding f(Severity sev, Confidence conf,
                                   String issueName, String desc, String evidence) {
        return new HeaderFinding(issueName, HDR, null, desc, evidence, sev, conf, Category.CSP);
    }

    private static HeaderFinding f(Severity sev, Confidence conf,
                                   String issueName, String desc, String evidence, String referenceUrl) {
        return new HeaderFinding(issueName, HDR, null, desc, evidence, sev, conf, Category.CSP, referenceUrl);
    }

    private static List<String> getEffective(Map<String, List<String>> directives, String directive) {
        return directives.containsKey(directive)
                ? directives.get(directive)
                : directives.getOrDefault("default-src", List.of());
    }

    private static boolean contains(List<String> values, String target) {
        return values.stream().anyMatch(v -> v.equalsIgnoreCase(target));
    }

    private static boolean containsWildcard(List<String> values) {
        return values.contains("*");
    }

    private static boolean containsScheme(List<String> values, String scheme) {
        return values.stream().anyMatch(v -> v.equalsIgnoreCase(scheme));
    }

    /** Strips scheme (scheme://, //) and any path/query/port from a CSP source expression, a
     * leading "*." wildcard prefix (if present) is left in place for the caller to strip/detect. */
    private static String hostnameOf(String source) {
        String s = source;
        int schemeIdx = s.indexOf("://");
        if (schemeIdx >= 0) s = s.substring(schemeIdx + 3);
        else if (s.startsWith("//")) s = s.substring(2);
        int slash = s.indexOf('/');
        if (slash >= 0) s = s.substring(0, slash);
        int colon = s.indexOf(':');
        if (colon >= 0) s = s.substring(0, colon);
        return s;
    }

    static Map<String, List<String>> parseDirectives(String csp) {
        Map<String, List<String>> map = new LinkedHashMap<>();
        for (String part : csp.split(";")) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) continue;
            String[] tokens = trimmed.split("\\s+");
            if (tokens.length == 0) continue;
            String name = tokens[0].toLowerCase(Locale.ROOT);
            List<String> values = new ArrayList<>();
            for (int i = 1; i < tokens.length; i++) values.add(tokens[i].toLowerCase(Locale.ROOT));
            // CSP requires duplicate directives inside one policy to be ignored after the first.
            // Keeping the last one could invent permissions that the browser never applies.
            map.putIfAbsent(name, values);
        }
        return map;
    }
}
