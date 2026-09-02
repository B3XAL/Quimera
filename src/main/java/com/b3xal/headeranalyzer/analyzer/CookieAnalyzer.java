package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.b3xal.headeranalyzer.model.Confidence.*;
import static com.b3xal.headeranalyzer.model.Severity.*;

/**
 * Analyzes Set-Cookie headers for missing/incorrect security flags.
 * Expects a merged value: multiple cookies joined by "\n" (one per line).
 */
public final class CookieAnalyzer {

    private CookieAnalyzer() {}

    private static final String HDR = "Set-Cookie";

    /**
     * Well-known third-party tracking/analytics cookie name prefixes.
     * These are set by external scripts (GA, Facebook, Hotjar, Cloudflare Bot Mgmt,
     * Matomo, etc.), the application developer does not control their flags.
     * Flagging them as HIGH for missing Secure would be noise in a pentest report.
     */
    private static final Set<String> TRACKING_PREFIXES = Set.of(
        // Google Analytics / GTM
        "_ga", "_gid", "_gat", "_gac_", "__utma", "__utmb", "__utmc", "__utmz", "__utmt",
        // Facebook / Meta
        "_fbp", "_fbc", "fr", "datr", "sb", "wd",
        // Hotjar
        "_hjid", "_hjsessionuser", "_hjfirstseen", "_hjsession", "_hjabsolutesessioni",
        // Cloudflare Bot Management
        "__cf_bm", "__cfduid", "__cflb", "_cfuvid",
        // Matomo / Piwik
        "_pk_id", "_pk_ses", "_pk_ref", "_pk_cvar",
        // Cookie consent banners
        "cookieconsent_status", "euconsent", "cmapi_gtm_bl", "notice_gdpr_prefs",
        // Microsoft Clarity
        "_clck", "_clsk",
        // AWS Application/Classic Load Balancer session-stickiness cookies, set by the load
        // balancer infrastructure itself, not application code, same "developer doesn't control
        // the flags" rationale as Cloudflare Bot Management above.
        "awsalb", "awsalbcors", "awsalbtg", "awsalbtgcors"
    );

    // Session/auth-looking cookie names, used only to GATE the long-lifetime check below so an
    // ordinary long-lived preference cookie ("theme=dark; Max-Age=31536000") doesn't get flagged
    // as a security issue, only cookies that actually look like they carry a session/auth token do.
    private static final Set<String> SESSION_NAME_KEYWORDS = Set.of(
        "session", "sid", "auth", "token", "jwt", "sso"
    );

    public static List<HeaderFinding> analyze(String setCookieValue, String requestHost, CookiesAndAuthConfig config) {
        if (setCookieValue == null || setCookieValue.isBlank()) return List.of();

        List<HeaderFinding> all = new ArrayList<>();
        for (String cookie : setCookieValue.split("\n")) {
            cookie = cookie.trim();
            if (!cookie.isBlank()) all.addAll(analyzeCookie(cookie, requestHost, config));
        }
        return all;
    }

    private static List<HeaderFinding> analyzeCookie(String cookieStr, String requestHost, CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();

        String cookieName  = parseName(cookieStr);
        List<String> attrs = parseAttrs(cookieStr);

        // F5 BIG-IP Advanced WAF/ASM infrastructure state, not an application authentication
        // cookie. Its fixed name contains "session" and otherwise trips auth-cookie heuristics.
        if (isInfrastructureCookie(cookieName)) return findings;

        // Skip third-party tracking/analytics cookies, developer doesn't control their flags
        // (unless the user explicitly turned that skip off in Cookies & Auth Rules).
        if (config.cookieTrackingSkipEnabled && isKnownTrackingCookie(cookieName, config)) return findings;

        // Skip cookies being explicitly deleted (Max-Age=0/negative, or an Expires date already
        // in the past, see isBeingDeleted): a deletion sentinel's flags are irrelevant, it's
        // being cleared, not (re)issued, flagging missing Secure/HttpOnly/SameSite on every
        // logout response was pure noise.
        if (isBeingDeleted(cookieStr, attrs)) return findings;

        // A cookie can carry a JWT directly or bury one in JSON, percent-encoded JSON, or a
        // Base64/Base64URL-encoded JSON object. Analyze the value independently of the ordinary
        // flag checks below, preserving the deliberately broad cookie coverage this analyzer has.
        String cookieValue = parseValue(cookieStr);
        boolean containsJwt = config.jwtEnabled
                && !StructuredCookieJwtAnalyzer.extract(cookieValue).isEmpty();
        List<StructuredCookieJwtAnalyzer.EmbeddedCredential> embeddedOpaque =
                StructuredCookieJwtAnalyzer.extractOpaqueCredentials(cookieValue);
        findings.addAll(StructuredCookieJwtAnalyzer.analyze(cookieName, cookieValue, HDR, config));
        if (config.queryStringTokenEnabled) {
            findings.addAll(AuthHeaderAnalyzer.analyzeSensitiveUrlInCookie(cookieName, cookieValue, HDR));
        }

        boolean hasSecure   = attrs.stream().anyMatch(a -> a.equals("secure"));
        boolean hasHttpOnly = attrs.stream().anyMatch(a -> a.equals("httponly"));
        boolean partitioned = attrs.contains("partitioned");
        boolean authLikeCookie = looksLikeSessionCookie(cookieName, hasHttpOnly, config)
                || containsJwt || !embeddedOpaque.isEmpty();
        if (!embeddedOpaque.isEmpty()) {
            String paths = embeddedOpaque.stream().map(StructuredCookieJwtAnalyzer.EmbeddedCredential::path)
                    .distinct().limit(8).reduce((a, b) -> a + ", " + b).orElse("$");
            findings.add(new HeaderFinding(
                    "Opaque authentication material embedded in structured cookie: " + cookieName,
                    HDR, cookieStr,
                    "The cookie decodes to structured data containing opaque credential-shaped values under " +
                            "explicit authentication fields. This is an inventory signal; cookie flag and " +
                            "lifetime checks treat it as authentication material even though it is not a JWT.",
                    "Decoded credential paths: " + paths,
                    INFORMATION, FIRM, Category.AUTH,
                    "https://github.com/CYS4srl/SensitiveDiscoverer"));
        }
        String  sameSite    = attrs.stream()
                .filter(a -> a.startsWith("samesite="))
                .map(a -> a.substring("samesite=".length()))
                .findFirst().orElse(null);

        if (config.cookieFlagChecksEnabled) {
            // ------ Secure flag ---------------------------------------------------------------------------------------------------------------------------------------------------------
            if (!hasSecure && authLikeCookie && !partitioned && !"none".equals(sameSite)) {
                findings.add(f(MEDIUM, CERTAIN,
                    "Cookie missing Secure flag: " + cookieName,
                    "Cookie '" + cookieName + "' lacks the Secure flag. Without it the browser sends " +
                    "the cookie over unencrypted HTTP connections, allowing network attackers to intercept " +
                    "session tokens and authentication credentials.",
                    HDR + ": " + cookieStr, cookieStr));
            }

            // ------ HttpOnly flag ---------------------------------------------------------------------------------------------------------------------------------------------------
            if (!hasHttpOnly && authLikeCookie) {
                findings.add(f(MEDIUM, CERTAIN,
                    "Cookie missing HttpOnly flag: " + cookieName,
                    "Cookie '" + cookieName + "' lacks the HttpOnly flag. " +
                    "JavaScript can read this cookie via document.cookie, " +
                    "making it trivially stealable in an XSS attack.",
                    HDR + ": " + cookieStr, cookieStr));
            }

            // ------ SameSite attribute ------------------------------------------------------------------------------------------------------------------------------------
            if (sameSite == null) {
                if (authLikeCookie) {
                    findings.add(f(LOW, CERTAIN,
                        "Cookie missing SameSite attribute: " + cookieName,
                        "Cookie '" + cookieName + "' has no SameSite attribute. " +
                        "Without SameSite, older browsers send this cookie on all cross-site requests, " +
                        "enabling Cross-Site Request Forgery (CSRF) attacks. " +
                        "Modern browsers default to Lax but this should be explicitly declared. " +
                        "Set SameSite=Strict for session cookies, or SameSite=Lax if cross-site GET is needed.",
                        HDR + ": " + cookieStr, cookieStr));
                }
            } else if (sameSite.equals("none")) {
                if (!hasSecure && !partitioned) {
                    findings.add(f(MEDIUM, CERTAIN,
                        "SameSite=None without Secure flag: " + cookieName,
                        "Cookie '" + cookieName + "' uses SameSite=None without the Secure flag. " +
                        "This combination is invalid per RFC 6265bis; modern browsers will reject the cookie entirely.",
                        HDR + ": " + cookieStr, cookieStr));
                }
            } else if (!sameSite.equals("strict") && !sameSite.equals("lax")) {
                // Present, not "none" (handled above), and not a recognised value either, a typo
                // or garbage value (e.g. "SameSite=Stirct"). Browsers that don't recognise the
                // value ignore the whole attribute and fall back to their own default, the same
                // protection gap as SameSite being absent entirely, just less obvious in the raw
                // header, this used to silently pass as "present, not none, so fine".
                findings.add(f(LOW, CERTAIN,
                    "Cookie SameSite has an unrecognised value: " + cookieName,
                    "Cookie '" + cookieName + "' sets SameSite to '" + sameSite + "', which is not a valid " +
                    "value (Strict, Lax, or None). Browsers that don't recognise it ignore the attribute and " +
                    "fall back to their own default behaviour, the same protection gap as SameSite being " +
                    "absent entirely. Use one of: Strict, Lax, None.",
                    HDR + ": " + cookieStr, cookieStr));
            }

            // ------ Domain scoped wider than the host that set it ---------------------------------------------------------
            String domain = attrs.stream()
                    .filter(a -> a.startsWith("domain="))
                    .map(a -> a.substring("domain=".length()))
                    .findFirst().orElse(null);
            if (domain != null && requestHost != null && !requestHost.isBlank()) {
                String normalizedDomain = domain.startsWith(".") ? domain.substring(1) : domain;
                String canonicalDomain = canonicalDomain(normalizedDomain);
                String canonicalHost = canonicalDomain(requestHost);
                if (authLikeCookie && !canonicalHost.equalsIgnoreCase(canonicalDomain)) {
                    findings.add(f(LOW, FIRM,
                        "Cookie scoped to parent domain: " + cookieName,
                        "Cookie '" + cookieName + "' sets an explicit Domain attribute ('" + domain + "') " +
                        "scoping it to that domain and ALL its subdomains, instead of just '" + requestHost +
                        "' (the default, narrower scope when Domain is omitted entirely). Any subdomain, " +
                        "including less-trusted or third-party-operated ones, can read and set this cookie; " +
                        "a vulnerable or compromised subdomain can steal or forge it for use against this " +
                        "host. Remove the Domain attribute unless this cookie genuinely needs to be shared " +
                        "across subdomains.",
                        HDR + ": " + cookieStr, cookieStr));
                }
            }

            // ------ Cookie prefix violations ------------------------------------------------------------------------------------------------------------------
            if (cookieName.startsWith("__Secure-") && !hasSecure) {
                findings.add(f(MEDIUM, CERTAIN,
                    "__Secure- prefix violation: " + cookieName,
                    "Cookies with the '__Secure-' prefix MUST have the Secure flag set. " +
                    "This cookie will be rejected by all compliant browsers.",
                    HDR + ": " + cookieStr, cookieStr));
            }

            if (cookieName.startsWith("__Host-")) {
                boolean hasDomain = attrs.stream().anyMatch(a -> a.startsWith("domain="));
                boolean hasPathRoot = attrs.stream().anyMatch(a -> a.equals("path=/"));
                if (!hasSecure || hasDomain || !hasPathRoot) {
                    findings.add(f(LOW, CERTAIN,
                        "__Host- prefix violation: " + cookieName,
                        "Cookies with the '__Host-' prefix must have Secure flag, no Domain attribute, " +
                        "and Path=/. This cookie violates one or more of these requirements and will be rejected.",
                        HDR + ": " + cookieStr, cookieStr));
                }
            }

            if (partitioned && !hasSecure) {
                findings.add(f(MEDIUM, CERTAIN,
                    "Partitioned cookie missing required Secure flag: " + cookieName,
                    "Cookies using the Partitioned attribute must also use Secure; compliant browsers reject " +
                    "this cookie otherwise." + ("none".equals(sameSite)
                            ? " SameSite=None independently requires Secure as well." : ""),
                    HDR + ": " + cookieStr, cookieStr));
            }

            for (String attribute : List.of("domain=", "path=", "samesite=", "max-age=")) {
                List<String> values = attrs.stream().filter(a -> a.startsWith(attribute)).toList();
                if (values.size() > 1 && values.stream().distinct().count() > 1) {
                    findings.add(f(LOW, FIRM,
                        "Cookie has conflicting " + attribute.substring(0, attribute.length() - 1) +
                                " attributes: " + cookieName,
                        "The cookie emits multiple conflicting values for the same attribute. Browser handling " +
                                "can differ and effective scope or lifetime becomes ambiguous; emit one value.",
                        HDR + ": " + cookieStr, cookieStr));
                }
            }
        }

        // ------ Long-lived session cookie ---------------------------------------------------------------------------------------------------------------------------
        // Gated to cookies that already look session/auth-related (HttpOnly present, or a
        // matching name keyword), so an ordinary "remember my theme" cookie with a year-long
        // Max-Age doesn't get flagged, only cookies that actually look like they carry a token do.
        if (config.cookieLifetimeCheckEnabled && authLikeCookie) {
            Long lifetime = lifetimeMinutes(cookieStr, attrs);
            if (lifetime == null) {
                findings.add(f(INFORMATION, CERTAIN,
                    "Authentication cookie has no explicit persistence: " + cookieName,
                    "Cookie '" + cookieName + "' appears to carry session/authentication material and has " +
                    "neither Expires nor Max-Age, so it is a browser-session cookie. This is often the safer " +
                    "choice and is not a vulnerability by itself; it is recorded so the authentication " +
                    "lifetime model is complete. Verify the server also expires and revokes the session, " +
                    "because closing a browser is not a server-side invalidation mechanism.",
                    HDR + ": " + cookieStr + " (Expires absent, Max-Age absent)", cookieStr));
            } else if (lifetime > config.maxLifetimeMinutes) {
                findings.add(f(MEDIUM, FIRM,
                    "Session cookie has a long lifetime: " + cookieName,
                    "Cookie '" + cookieName + "' looks like a session/auth cookie and has a lifetime of " +
                    formatMinutes(lifetime) + ", longer than the " + formatMinutes(config.maxLifetimeMinutes) +
                    " threshold configured in Settings (Cookies & Auth). A longer-lived session cookie " +
                    "widens the exposure window if it's ever stolen (XSS, a shared/public machine, a lost " +
                    "device). Adjust the threshold in Settings if this lifetime is intentional for this " +
                    "application, or shorten the cookie's actual Max-Age/Expires.",
                    HDR + ": " + cookieStr, cookieStr));
            }
        }

        return findings;
    }

    // document.cookie = "name=value..."  a cookie set via client-side JavaScript rather than the
    // server's Set-Cookie header. Only the group-1 NAME is captured, up to the first "=" inside
    // the string literal.
    private static final Pattern DOCUMENT_COOKIE_SET = Pattern.compile(
        "document\\s*\\.\\s*cookie\\s*=\\s*['\"]([^'\"=]{1,64})=", Pattern.CASE_INSENSITIVE);

    /** Cookies set via client-side JavaScript (document.cookie) rather than the server's
     * Set-Cookie header, found by scanning the response body text, same static-analysis limits
     * as WebStorageAnalyzer, no JS is executed. A cookie written this way can NEVER carry
     * HttpOnly, a fixed architectural property (only a server Set-Cookie response header can set
     * that flag), so it's permanently readable by any script on the page regardless of any other
     * hardening. Worth flagging independent of whatever {@link #analyze} finds from actual
     * Set-Cookie headers, this can be an entirely different, server-invisible cookie. Gated on
     * cookieFlagChecksEnabled: same "is this cookie's client-side exposure a real gap" question
     * as the missing-HttpOnly check this is conceptually the unfixable version of. */
    public static List<HeaderFinding> analyzeJsCookies(String body, CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (body == null || body.isEmpty() || !config.cookieFlagChecksEnabled) return findings;

        Set<String> seen = new LinkedHashSet<>();
        Matcher m = DOCUMENT_COOKIE_SET.matcher(body);
        while (m.find()) {
            String name = m.group(1).trim();
            if (name.isEmpty() || !seen.add(name.toLowerCase(Locale.ROOT))) continue;
            if (!nameLooksSensitive(name, config)) continue; // avoid noise on "theme=dark"-style writes

            findings.add(new HeaderFinding(
                "Cookie set via client-side JavaScript (document.cookie): " + name,
                "(document.cookie)",
                "document.cookie = '" + name + "=...'",
                "This page sets the cookie '" + name + "' via JavaScript (document.cookie), not the server's " +
                "Set-Cookie header. A cookie set this way can NEVER carry the HttpOnly flag, only the server " +
                "can set that when issuing Set-Cookie, so it is permanently readable (and writable) by any " +
                "script on the page. If this cookie carries a session token or other credential, it offers no " +
                "protection against theft via XSS at all, the equivalent of a permanent 'missing HttpOnly' " +
                "with no server-side fix available short of moving this write to a real Set-Cookie header.",
                "document.cookie = '" + name + "=...' found in response body",
                Severity.LOW, Confidence.CERTAIN, Category.COOKIE));
        }
        return findings;
    }

    // ------ Helpers ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private static boolean looksLikeSessionCookie(String name, boolean hasHttpOnly, CookiesAndAuthConfig config) {
        return hasHttpOnly || nameLooksSensitive(name, config);
    }

    /** The keyword-matching half of looksLikeSessionCookie, factored out so
     * analyzeJsCookies can reuse it without the hasHttpOnly branch, which never applies to a
     * JS-set cookie (it can never have HttpOnly in the first place). Also exposed (public) for
     * {@link SessionLifecycleAnalyzer}, which only tracks session-shaped cookies across
     * login/logout cycles, not every cookie the app happens to set. */
    public static boolean nameLooksSensitive(String name, CookiesAndAuthConfig config) {
        if (isInfrastructureCookie(name)) return false;
        String lower = name.toLowerCase(Locale.ROOT);
        for (String kw : SESSION_NAME_KEYWORDS) {
            if (lower.contains(kw)) return true;
        }
        for (String kw : config.extraSessionKeywords) {
            if (!kw.isBlank() && lower.contains(kw.toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    private static String canonicalDomain(String value) {
        try { return java.net.IDN.toASCII(value.replaceFirst("\\.$", "")).toLowerCase(Locale.ROOT); }
        catch (IllegalArgumentException ex) { return value.toLowerCase(Locale.ROOT); }
    }

    /** Max-Age takes precedence over Expires per RFC 6265 when both are present. Null if neither
     * is parseable, or if the cookie is effectively session-only/already-expired-per-attribute. */
    private static Long lifetimeMinutes(String cookieStr, List<String> attrs) {
        for (String a : attrs) {
            if (a.startsWith("max-age=")) {
                try {
                    long seconds = Long.parseLong(a.substring("max-age=".length()).trim());
                    return seconds <= 0 ? null : seconds / 60;
                } catch (NumberFormatException ignored) { /* fall through to Expires */ }
            }
        }
        // parseAttrs() lowercases everything (correct for flag/attribute-name comparisons above),
        // but an RFC 1123 HTTP-date is case-sensitive ("Wed, ... Oct ... GMT"), so Expires is
        // re-read from the ORIGINAL, non-lowercased cookieStr rather than the shared attrs list.
        String expiresRaw = findRawAttrValue(cookieStr, "expires");
        if (expiresRaw != null) {
            try {
                ZonedDateTime expiry = ZonedDateTime.parse(expiresRaw, DateTimeFormatter.RFC_1123_DATE_TIME);
                long seconds = Duration.between(ZonedDateTime.now(expiry.getZone()), expiry).getSeconds();
                return seconds <= 0 ? null : seconds / 60;
            } catch (Exception ignored) { /* unparseable date, skip */ }
        }
        return null;
    }

    private static String findRawAttrValue(String cookieStr, String attrName) {
        String[] parts = cookieStr.split(";");
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i].trim();
            int eq = part.indexOf('=');
            if (eq < 0) continue;
            if (part.substring(0, eq).trim().equalsIgnoreCase(attrName)) return part.substring(eq + 1).trim();
        }
        return null;
    }

    private static String formatMinutes(long minutes) {
        if (minutes < 60) return minutes + "m";
        long hours = minutes / 60;
        if (hours < 48) return hours + "h";
        return (hours / 24) + "d";
    }

    /** Exposed (public) for {@link SessionLifecycleAnalyzer}, same reasoning as
     * {@link #nameLooksSensitive}. */
    public static String parseName(String cookieStr) {
        int semi = cookieStr.indexOf(';');
        String nameVal = semi > 0 ? cookieStr.substring(0, semi) : cookieStr;
        int eq = nameVal.indexOf('=');
        return (eq > 0 ? nameVal.substring(0, eq) : nameVal).trim();
    }

    /** Cookie VALUE only (no name, no attributes), the exact bytes the browser would send back in
     * a later Cookie: request header. Exposed for {@link SessionLifecycleAnalyzer}, which needs to
     * compare this across separate Set-Cookie issuances to tell a static session identifier from
     * one that actually rotates. */
    public static String parseValue(String cookieStr) {
        int semi = cookieStr.indexOf(';');
        String nameVal = semi > 0 ? cookieStr.substring(0, semi) : cookieStr;
        int eq = nameVal.indexOf('=');
        return eq >= 0 ? nameVal.substring(eq + 1).trim() : "";
    }

    /** Exposed (public) for {@link SessionLifecycleAnalyzer}, same reasoning as
     * {@link #nameLooksSensitive}. */
    public static List<String> parseAttrs(String cookieStr) {
        String[] parts = cookieStr.split(";");
        List<String> attrs = new ArrayList<>();
        for (int i = 1; i < parts.length; i++) {
            attrs.add(parts[i].trim().toLowerCase(Locale.ROOT));
        }
        return attrs;
    }

    /** Package-private (not private): reused by WebStorageAnalyzer.correlateCookies so the
     * cookie-to-Web-Storage correlation excludes the same tracking/analytics noise this class's
     * own flag checks already skip, one shared list instead of a second one that could drift. */
    static boolean isKnownTrackingCookie(String name, CookiesAndAuthConfig config) {
        String lower = name.toLowerCase(Locale.ROOT);
        for (String prefix : TRACKING_PREFIXES) {
            if (lower.equals(prefix) || lower.startsWith(prefix + "_") || lower.startsWith(prefix + ".")) {
                return true;
            }
        }
        for (String prefix : config.extraTrackingPrefixes) {
            if (prefix.isBlank()) continue;
            String p = prefix.toLowerCase(Locale.ROOT);
            if (lower.equals(p) || lower.startsWith(p + "_") || lower.startsWith(p + ".")) return true;
        }
        return false;
    }

    /** Cookies owned by reverse-proxy/WAF infrastructure rather than application auth. */
    public static boolean isInfrastructureCookie(String name) {
        return name != null && name.toLowerCase(Locale.ROOT)
                .startsWith("f5avraaaaaaaaaaaaaaaa_session_");
    }

    /** Exposed (public) for {@link SessionLifecycleAnalyzer}: a deletion Set-Cookie (Max-Age<=0 or
     * an already-past Expires) is the one reliable, protocol-level "this session just ended"
     * signal Quimera can observe passively, much sturdier than guessing from a URL like "/logout". */
    public static boolean isBeingDeleted(String cookieStr, List<String> attrs) {
        for (String attr : attrs) {
            if (attr.equals("max-age=0") || attr.startsWith("max-age=-")) return true;
        }
        // Common alternate deletion idiom (many frameworks clear cookies this way instead of
        // Max-Age=0): an Expires date already in the past, e.g.
        // "Expires=Thu, 01 Jan 1970 00:00:00 GMT". Missing this meant every logout/cookie-clear
        // response got flagged for missing Secure/HttpOnly/SameSite on a cookie whose flags are
        // irrelevant, it's being deleted, not (re)issued.
        String expiresRaw = findRawAttrValue(cookieStr, "expires");
        if (expiresRaw != null) {
            try {
                ZonedDateTime expiry = ZonedDateTime.parse(expiresRaw, DateTimeFormatter.RFC_1123_DATE_TIME);
                if (!expiry.isAfter(ZonedDateTime.now(expiry.getZone()))) return true;
            } catch (Exception ignored) { /* unparseable date, not a deletion signal either way */ }
        }
        return false;
    }

    private static HeaderFinding f(Severity sev, Confidence conf,
                                    String name, String desc, String evidence, String value) {
        return new HeaderFinding(name, HDR, value, desc, evidence, sev, conf, Category.COOKIE);
    }
}
