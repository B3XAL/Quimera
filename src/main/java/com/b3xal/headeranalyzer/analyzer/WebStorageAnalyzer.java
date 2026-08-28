package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Static, body-text-only Web Storage analysis, Quimera has no browser/DOM, it can't read actual
 * runtime localStorage/sessionStorage state, only what's visible in the HTTP response body text
 * (inline <script> blocks, SSR-hydration payloads, unminified/source-mapped bundles). Four
 * distinct signals, weakest to strongest:
 *
 *  1) {@link #correlateCookies}: a cookie's own value duplicated verbatim into the same body that
 *     also calls Web Storage's API. PortSwigger's own html5-auditor extension flags Web Storage
 *     USAGE with a bare "the string localStorage. is present somewhere in the body" check
 *     (confirmed by reading its source, see CREDITS.md), nearly zero-signal on its own, almost
 *     every modern app uses it for something harmless. A cookie's value showing up in that same
 *     body is concrete: cookie protections are being bypassed by the app's own client-side code.
 *  2) {@link #findKnownSdkSignatures}: an EXACT, documented localStorage/sessionStorage key
 *     format hardcoded by a widely-deployed auth SDK (AWS Cognito/Amplify, Firebase Auth,
 *     MSAL.js, Auth0 SPA SDK, Okta, Supabase), matching one means "this library really does put
 *     session/token material here by default", not a guess, CERTAIN confidence, the strongest
 *     signal this analyzer produces.
 *  3) A JWT-shaped value reaching a setItem() call, either directly as a literal
 *     ({@link #asStringLiteral}) or as a bare variable resolved via a nearby literal assignment
 *     earlier in the same body ({@link #resolveNearbyLiteral}, capped at Confidence.FIRM, the
 *     variable COULD have been reassigned between definition and use, this is a static-proximity
 *     heuristic, not a guaranteed data flow). Gets full {@link JwtAnalyzer} treatment (alg:none,
 *     missing exp, aud/iss, lifetime) either way.
 *  4) A sensitive-LOOKING key name and/or value-expression name (token/session/auth/secret/...)
 *     passed to setItem() whose actual value Quimera can't resolve at all, the weakest signal,
 *     just a naming-convention hint. OWASP's guidance is unambiguous that session/auth material
 *     has no business in Web Storage at all (JS-readable, no HttpOnly-equivalent protection
 *     exists for it), see
 *     https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html.
 *
 * None of these (besides #2, an exact format match) are a proven data-flow (no JS is actually
 * parsed/executed, no DOM exists), so findings stay at FIRM confidence or below and explicitly
 * ask the analyst to confirm in the browser's dev tools (Application &gt; Storage) before
 * reporting as a finding, except #2, which is deterministic string matching against a known,
 * fixed format, hence CERTAIN.
 */
public final class WebStorageAnalyzer {

    private WebStorageAnalyzer() {}

    // Safety cap: skip pathologically large bodies rather than doing repeated regex/contains() scans on them.
    private static final int MAX_BODY_LENGTH = 5_000_000;
    // Cookie values shorter than this are too likely to coincidentally appear elsewhere in the
    // body (a counter, a short flag...), only flag values long enough to plausibly be a real token.
    private static final int MIN_VALUE_LENGTH = 8;
    // Safety cap on how many setItem() call sites get the full variable-resolution treatment, a
    // giant combined vendor+app bundle could otherwise have hundreds of unrelated matches.
    private static final int MAX_SETITEM_MATCHES = 500;
    // How far back (characters) to search for a `identifier = "literal"` assignment before a
    // setItem(key, identifier) call. Bounded so the lookback itself stays cheap per match.
    private static final int LOOKBACK_WINDOW = 2000;

    // key/value-expression name in a Web Storage call worth a heuristic "verify this" nudge, same
    // spirit as CookieAnalyzer's SESSION_NAME_KEYWORDS but a bit broader (credentials, not just
    // sessions). "sessid"/"phpsessid" added separately from "session": PHP's default session
    // cookie name is literally "PHPSESSID", which does NOT contain the substring "session" (no
    // "ion"), a real gap if a PHP app's frontend JS mirrors that cookie into Web Storage verbatim.
    private static final Set<String> SENSITIVE_KEY_KEYWORDS = Set.of(
        "token", "jwt", "session", "sessid", "auth", "sso", "secret", "password", "passwd",
        "credential", "apikey", "api_key", "accesstoken", "refreshtoken", "idtoken"
    );

    // (?:localStorage|sessionStorage).setItem('key', <value>)  <value> captured as raw text,
    // covers every common real-world shape: a quoted literal, a bare identifier/property chain
    // (accessToken, res.data.token), or a simple single-level call (getToken()).
    private static final Pattern SET_ITEM_CALL = Pattern.compile(
        "(localStorage|sessionStorage)\\s*\\.\\s*setItem\\s*\\(\\s*['\"]([^'\"]{1,64})['\"]\\s*,\\s*" +
        "([^,()]+(?:\\([^()]*\\))?[^,()]*)\\)",
        Pattern.CASE_INSENSITIVE);

    private static final Pattern SIMPLE_IDENTIFIER = Pattern.compile("^[A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*$");

    /** Documented localStorage/sessionStorage key formats hardcoded by widely-deployed auth SDKs.
     * Sources: each SDK's own source/docs, amazon-cognito-identity-js/AWS Amplify
     * (CognitoIdentityServiceProvider.&lt;clientId&gt;.&lt;username&gt;.&lt;idToken|accessToken|refreshToken&gt;),
     * Firebase JS SDK (firebase:authUser:&lt;apiKey&gt;:&lt;appName&gt;), MSAL.js caching.md
     * (msal.idtoken / msal.token.keys / msal.account.keys / *accesstoken* cache entries),
     * auth0-spa-js (@@auth0spajs@@::&lt;clientId&gt;::... when cacheLocation: 'localstorage'),
     * okta-auth-js (fixed key "okta-token-storage"), supabase-js
     * (sb-&lt;project-ref&gt;-auth-token). */
    private static final class KnownSdkSignature {
        final String label;
        final Pattern pattern;
        KnownSdkSignature(String label, String regex) {
            this.label = label;
            this.pattern = Pattern.compile(regex);
        }
    }

    private static final List<KnownSdkSignature> KNOWN_SDK_SIGNATURES = List.of(
        new KnownSdkSignature("AWS Cognito (amazon-cognito-identity-js / Amplify)",
            "CognitoIdentityServiceProvider\\.[\\w-]+\\.[^.'\"\\s]+\\.(?:idToken|accessToken|refreshToken)"),
        new KnownSdkSignature("Firebase Authentication",
            "firebase:authUser:[\\w-]+:\\[?[\\w.-]*\\]?"),
        new KnownSdkSignature("MSAL.js (Microsoft Entra ID / Azure AD)",
            "msal\\.(?:idtoken|token\\.keys|account\\.keys|[\\w.-]*accesstoken[\\w.-]*)"),
        new KnownSdkSignature("Auth0 SPA SDK (auth0-spa-js, cacheLocation: 'localstorage')",
            "@@auth0spajs@@::[^'\"\\s]+"),
        new KnownSdkSignature("Okta (okta-auth-js)", "okta-token-storage"),
        new KnownSdkSignature("Supabase Auth", "sb-[\\w-]+-auth-token")
    );

    // redux-persist's default localStorage key format ("persist:root", or "persist:<key>" for a
    // custom persistConfig.key). Deliberately NOT in KNOWN_SDK_SIGNATURES/CERTAIN: unlike an
    // auth-specific SDK, redux-persist is a general state-persistence library, matching this key
    // format only proves the app uses it, not that auth/token data is inside, apps commonly
    // whitelist their auth reducer for persistence but that's a usage convention, not a
    // guarantee. Also the actual serialized JSON is written by client-side JS at runtime and
    // essentially never appears in the static response body Quimera reads, so this stays a
    // framework-usage hint (INFORMATION/TENTATIVE) rather than a real finding.
    private static final Pattern REDUX_PERSIST_KEY = Pattern.compile("['\"]persist:[\\w.-]*['\"]");

    /**
     * @param body           response body text, may be null/empty (no finding then)
     * @param setCookieValue the same merged Set-Cookie value already used by CookieAnalyzer
     *                       (multiple cookies joined by "\n"), may be null/empty
     * @param config         from Settings (Cookies & Auth Rules), gates the JWT sub-checks and is
     *                       passed straight through to any JwtAnalyzer delegation
     */
    public static List<HeaderFinding> analyze(String body, String setCookieValue, CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (body == null || body.isEmpty() || body.length() > MAX_BODY_LENGTH) return findings;
        if (!config.webStorageCheckEnabled) return findings;

        findings.addAll(correlateCookies(body, setCookieValue, config));
        findings.addAll(findReduxPersistHint(body));
        findings.addAll(findKnownSdkSignatures(body));
        if (config.jwtEnabled) findings.addAll(scanSetItemCalls(body, config));

        return findings;
    }

    /** Signal (1): a cookie's own value duplicated verbatim into a Web Storage call. Any CUSTOM
     * app cookie qualifies, not just JWT-shaped ones, the correlation is a plain substring match
     * against the cookie's raw value regardless of its shape. */
    private static List<HeaderFinding> correlateCookies(String body, String setCookieValue, CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (setCookieValue == null || setCookieValue.isBlank()) return findings;

        boolean usesLocalStorage = body.contains("localStorage.setItem")
                || body.contains("localStorage[\"") || body.contains("localStorage['");
        boolean usesSessionStorage = body.contains("sessionStorage.setItem")
                || body.contains("sessionStorage[\"") || body.contains("sessionStorage['");
        if (!usesLocalStorage && !usesSessionStorage) return findings;

        // localStorage is shared across every tab/window of the origin and survives browser
        // restarts until explicitly cleared, so any XSS anywhere on this origin, at any point
        // in time, is a viable theft path, sessionStorage is scoped to this one browsing context
        // and dies with the tab, a strictly narrower exploitation window for the same underlying
        // "no HttpOnly-equivalent protection" bug. This loose body-wide correlation can't tell
        // which specific API call the cookie value ended up next to, so it stays MEDIUM whenever
        // localStorage usage is present at all (the worse-case API wins), only drops to LOW when
        // sessionStorage is the sole API seen in this body.
        Severity severity = usesLocalStorage ? Severity.MEDIUM : Severity.LOW;

        for (String cookieLine : setCookieValue.split("\n")) {
            cookieLine = cookieLine.trim();
            if (cookieLine.isEmpty()) continue;

            String name  = parseName(cookieLine);
            String value = parseValue(cookieLine);
            // Same tracking/analytics skip list CookieAnalyzer's flag checks already apply (GA,
            // Meta, Hotjar, Cloudflare Bot Mgmt, Matomo, ...): the developer doesn't control those
            // cookies' values or whether some third-party script also touches Web Storage, a
            // coincidental match there is noise, not a finding, this correlation used to check
            // EVERY cookie in the response with no such filter at all.
            if (config.cookieTrackingSkipEnabled && CookieAnalyzer.isKnownTrackingCookie(name, config)) continue;
            if (value.length() < MIN_VALUE_LENGTH) continue;
            if (!body.contains(value)) continue;

            findings.add(new HeaderFinding(
                "Cookie value duplicated into browser Web Storage: " + name,
                "Set-Cookie",
                cookieLine,
                "The value of cookie '" + name + "' also appears verbatim in this response's body, which " +
                "separately calls the localStorage/sessionStorage API. If the application is writing this " +
                "cookie's own value into Web Storage, it defeats any HttpOnly protection the cookie has, " +
                "JavaScript (and therefore any XSS on this page) can read the same token directly from Web " +
                "Storage even though it cannot read an HttpOnly cookie. localStorage in particular has no " +
                "expiry and persists across tabs and browser restarts, extending the token's exposure window " +
                "well beyond the cookie's own lifetime. Severity is capped at the same level as a missing " +
                "HttpOnly flag (the impact primitive is identical: the token becomes JS-readable, still " +
                "requiring a separate XSS to actually exploit), this is a same-document correlation, not a " +
                "confirmed data flow, verify in the browser's dev tools (Application > Storage) whether it " +
                "really is the same token before reporting it as a finding.",
                "Cookie '" + name + "' value found in the response body alongside a Web Storage API call",
                severity, Confidence.TENTATIVE, Category.COOKIE,
                "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"));
        }
        return findings;
    }

    /** Signal (2): an exact, documented auth-SDK Web Storage key format. Deterministic string
     * matching against a known, fixed format, no ambiguity about what it means once matched. */
    private static List<HeaderFinding> findKnownSdkSignatures(String body) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (!body.contains("localStorage") && !body.contains("sessionStorage")) return findings;

        for (KnownSdkSignature sig : KNOWN_SDK_SIGNATURES) {
            Matcher m = sig.pattern.matcher(body);
            if (!m.find()) continue;
            String evidence = m.group();
            findings.add(new HeaderFinding(
                "Known auth SDK session cache detected in Web Storage: " + sig.label,
                "(Web Storage)",
                evidence,
                "This response body references '" + evidence + "', the documented localStorage/sessionStorage " +
                "key format used by " + sig.label + " to cache session tokens (access/ID/refresh tokens, or " +
                "the signed-in user's auth state). Unlike a naming heuristic, this is a known, exact format, " +
                "the library really does put session/token material there by default. Web Storage has no " +
                "HttpOnly-equivalent protection, any XSS on this origin can read it directly and impersonate " +
                "the signed-in user, with no additional bug needed beyond the XSS itself. Confirm in the " +
                "browser's dev tools (Application > Storage) what's actually cached, and check whether this " +
                "SDK's more restrictive storage option (in-memory, encrypted, or a same-site cookie) fits " +
                "this application's threat model better than its default.",
                "Matched known " + sig.label + " key format: " + evidence,
                Severity.INFORMATION, Confidence.FIRM, Category.AUTH,
                "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"));
        }
        return findings;
    }

    /** Framework-usage hint, not a real finding, see REDUX_PERSIST_KEY's own comment for why this
     * is deliberately weaker than findKnownSdkSignatures. */
    private static List<HeaderFinding> findReduxPersistHint(String body) {
        Matcher m = REDUX_PERSIST_KEY.matcher(body);
        if (!m.find()) return List.of();
        String evidence = m.group();
        return List.of(new HeaderFinding(
            "State-persistence library detected (redux-persist): possible auth state in Web Storage",
            "(Web Storage)",
            evidence,
            "This response references '" + evidence + "', the localStorage key format redux-persist uses by " +
            "default. redux-persist serializes the whole Redux store (or a whitelisted subset) into Web " +
            "Storage, and apps commonly whitelist their auth/session reducer, which usually holds the access " +
            "token, refresh token, or a logged-in user object. Quimera can't see the actual persisted JSON " +
            "(it's written by client-side JS at runtime, essentially never present in a static response " +
            "body), so this is only a framework-usage hint, not a confirmed finding. Check the browser's dev " +
            "tools (Application > Storage) for the actual entry and see whether it contains token/credential fields.",
            "redux-persist key format found in response body: " + evidence,
            Severity.INFORMATION, Confidence.TENTATIVE, Category.AUTH,
            "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"));
    }

    /** Signals (3) and (4): every setItem() call site, classified by what its value argument
     * actually looks like, a literal, a resolvable bare variable, or an unresolvable expression. */
    private static List<HeaderFinding> scanSetItemCalls(String body, CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        Set<String> seenAdvisoryKeys = new LinkedHashSet<>();
        Matcher m = SET_ITEM_CALL.matcher(body);
        int matchCount = 0;

        while (m.find()) {
            if (++matchCount > MAX_SETITEM_MATCHES) break;
            String api = m.group(1);
            String key = m.group(2);
            String valueRaw = m.group(3).trim();

            String literal = asStringLiteral(valueRaw);
            if (literal != null) {
                if (JwtAnalyzer.looksLikeJwt(literal)) {
                    findings.addAll(JwtAnalyzer.analyze(literal, "(Web Storage)",
                            api + ".setItem('" + key + "', ...)", config));
                } else if (isSensitiveKeyName(key.toLowerCase(Locale.ROOT)) && looksLikeOpaqueToken(literal)) {
                    // Not JWT-shaped, but the key name says credential AND the literal value
                    // itself looks like real token material (long, opaque, no spaces/prose, not
                    // an empty/placeholder default), covers plain session IDs, API keys, and any
                    // other opaque (non-JWT) token, previously this fell through with NO finding
                    // at all, JWT-shape was the only thing ever checked for a literal value.
                    findings.add(opaqueTokenFinding(api, key, literal, Confidence.FIRM));
                }
                continue; // literal handled either way, no further (weaker) tiers needed for this call
            }

            String identifier = SIMPLE_IDENTIFIER.matcher(valueRaw).matches() ? valueRaw : null;
            String lastSegment = identifier != null && identifier.contains(".")
                    ? identifier.substring(identifier.lastIndexOf('.') + 1) : identifier;

            // Tier (3), variable case: a bare identifier (no dots, a real local variable rather
            // than an object-property chain we can't statically resolve) whose value was assigned
            // a literal earlier in the same body, JWT-shaped or otherwise opaque.
            if (identifier != null && !identifier.contains(".")) {
                String resolved = resolveNearbyLiteral(body, m.start(), identifier);
                if (resolved != null && JwtAnalyzer.looksLikeJwt(resolved)) {
                    List<HeaderFinding> jwtFindings = JwtAnalyzer.analyze(resolved, "(Web Storage)",
                            api + ".setItem('" + key + "', " + identifier + ")  [resolved from '" + identifier +
                            " = ...' earlier in this same response]", config);
                    // Capped below CERTAIN: a static-proximity resolution, not a guaranteed data
                    // flow, the variable could theoretically be reassigned between its literal
                    // definition and this specific setItem() call.
                    for (HeaderFinding f : jwtFindings) findings.add(capConfidence(f, Confidence.FIRM));
                    continue;
                }
                if (resolved != null && isSensitiveKeyName(key.toLowerCase(Locale.ROOT)) && looksLikeOpaqueToken(resolved)) {
                    // Same non-JWT-opaque-token case as the direct-literal branch above, just
                    // resolved through one level of variable indirection, confidence one notch
                    // below the direct-literal case (FIRM, not the FIRM used there too, but the
                    // finding text says "resolved from" so it's clear it's not a direct literal).
                    findings.add(opaqueTokenFinding(api, key,
                            identifier + " = " + resolved + "  [resolved from earlier in this same response]",
                            Confidence.FIRM));
                    continue;
                }
            }

            // Tier (4): naming-only advisory. Two independent signals (the storage KEY name and
            // the value EXPRESSION's name) agreeing is meaningfully stronger evidence than either
            // alone, even without resolving the actual runtime value.
            boolean keySensitive   = isSensitiveKeyName(key.toLowerCase(Locale.ROOT));
            boolean valueSensitive = lastSegment != null && isSensitiveKeyName(lastSegment.toLowerCase(Locale.ROOT));
            if (!keySensitive && !valueSensitive) continue;
            if (!seenAdvisoryKeys.add(key.toLowerCase(Locale.ROOT))) continue;

            boolean dualSignal = keySensitive && valueSensitive;
            findings.add(new HeaderFinding(
                "Sensitive-looking key stored via Web Storage: " + key,
                "(Web Storage)",
                api + ".setItem('" + key + "', " + valueRaw + ")",
                "This page calls " + api + ".setItem('" + key + "', " + valueRaw + "). " +
                (dualSignal
                    ? "Both the storage key name AND the value expression being stored look credential-related, "
                    : "The storage key name looks credential-related, ") +
                "suggesting a session/auth token. Quimera can't see the actual runtime value (it's a variable " +
                "or expression, not a literal string), so this is a hint, not a confirmed finding. If it " +
                "really is a session token, API key, or credential, storing it in Web Storage makes it fully " +
                "readable by any JavaScript on the page (no HttpOnly-equivalent protection exists for Web " +
                "Storage), a single XSS is then enough to steal it outright, worse still for localStorage " +
                "specifically, which has no expiry and persists across tabs/restarts. Verify in the browser's " +
                "dev tools (Application > Storage) what this key actually holds before reporting it as a finding.",
                api + ".setItem('" + key + "', ...) found in response body",
                // sessionStorage is scoped to this one tab/browsing context and dies with it,
                // localStorage is shared across every tab of the origin and survives restarts,
                // same underlying exploitability, narrower window, one severity tier down.
                dualSignal ? (api.equals("sessionStorage") ? Severity.INFORMATION : Severity.LOW) : Severity.INFORMATION,
                dualSignal ? Confidence.FIRM : Confidence.TENTATIVE,
                Category.AUTH,
                "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"));
        }
        return findings;
    }

    /** Strips surrounding matching quotes if raw is a plain string literal, null otherwise
     * (a bare identifier, property chain, function call, concatenation, ...). */
    private static String asStringLiteral(String raw) {
        if (raw.length() < 2) return null;
        char first = raw.charAt(0);
        char last  = raw.charAt(raw.length() - 1);
        return (first == '\'' || first == '"') && last == first ? raw.substring(1, raw.length() - 1) : null;
    }

    /** Searches backward from a setItem() call for the CLOSEST prior `identifier = "literal"`
     * assignment, within a bounded window. Returns ANY literal found (not just JWT-shaped, the
     * caller classifies it, JWT vs. opaque-but-still-token-shaped vs. neither), the closest
     * (last) assignment before the call wins. */
    private static String resolveNearbyLiteral(String body, int callStart, String identifier) {
        int from = Math.max(0, callStart - LOOKBACK_WINDOW);
        String window = body.substring(from, callStart);
        Matcher assign = Pattern.compile(
            "\\b" + Pattern.quote(identifier) + "\\s*=\\s*['\"]([^'\"]{0,4096})['\"]"
        ).matcher(window);
        String resolved = null;
        while (assign.find()) resolved = assign.group(1);
        return resolved;
    }

    /** A literal value worth flagging as an opaque (non-JWT) token: long enough to plausibly be
     * real token material, no whitespace (rules out prose/sentences), and not one of the common
     * falsy/placeholder values a key like "authToken" legitimately holds before login (null,
     * empty, "false", "guest", ...), which would otherwise be a guaranteed false positive on
     * every logged-out page load. */
    /** Exposed for {@code com.b3xal.headeranalyzer.browser.BrowserStorageAnalyzer}, which runs the
     * same opaque-token judgment call against real (not statically-guessed) Web Storage values
     * collected by the browser bridge, no reason to duplicate this predicate there. */
    public static boolean looksLikeOpaqueToken(String value) {
        String v = value.trim();
        if (v.length() < 12 || v.length() > 2048) return false;
        if (v.contains(" ") || v.contains("\t") || v.contains("\n")) return false;
        String lower = v.toLowerCase(Locale.ROOT);
        if (lower.equals("null") || lower.equals("undefined") || lower.equals("false") || lower.equals("true")
                || lower.equals("none") || lower.equals("guest") || lower.equals("anonymous")) return false;
        // A leading '/' is a URL/route path (e.g. window.url_ResetPassword = "/Account/ResetPassword"),
        // not a secret, even though '/' is also a valid base64 character and would otherwise pass
        // the charset check below. Real tokens don't start with a literal path separator, this was
        // a real false-positive source once browser window-global scanning started feeding real values in.
        if (v.startsWith("/")) return false;
        // Opaque tokens/session IDs/API keys are typically base64(url)/hex charset, occasionally
        // with a few other URL-safe punctuation marks some vendors use (e.g. Stripe-style
        // "sk_live_..." keys), JWT's own dot-separated shape is handled separately upstream.
        return v.matches("[A-Za-z0-9+/=_.~-]+");
    }

    private static HeaderFinding opaqueTokenFinding(String api, String key, String valueEvidence, Confidence confidence) {
        return new HeaderFinding(
            "Session/auth token stored via Web Storage: " + key,
            "(Web Storage)",
            api + ".setItem('" + key + "', " + valueEvidence + ")",
            "This page stores a literal value under the key '" + key + "' via " + api + ".setItem(), a key " +
            "name that suggests a session/auth credential, and the value itself looks like real token " +
            "material (long, opaque, no spaces/prose), a plain session ID, API key, or opaque OAuth token " +
            "rather than a JWT Quimera can decode further. Web Storage has no HttpOnly-equivalent protection, " +
            "any XSS on this page can read it directly, no separate bug needed beyond the XSS itself. " +
            "localStorage in particular has no expiry and persists across tabs/restarts. Verify in the " +
            "browser's dev tools (Application > Storage) and confirm this value is still valid server-side " +
            "before reporting it as a finding.",
            api + ".setItem('" + key + "', ...) found in response body with a literal, opaque value",
            // sessionStorage dies with the tab and never leaves this one browsing context,
            // localStorage is shared across every tab of the origin and survives restarts, same
            // exploitability (XSS reads it either way), narrower window, one tier down.
            api.equals("sessionStorage") ? Severity.INFORMATION : Severity.LOW, confidence, Category.AUTH,
            "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html");
    }

    private static HeaderFinding capConfidence(HeaderFinding f, Confidence cap) {
        return f.confidence.order >= cap.order ? f
                : new HeaderFinding(f.issueName, f.headerName, f.headerValue, f.description, f.evidence,
                        f.severity, cap, f.category);
    }

    /** Exposed for {@code com.b3xal.headeranalyzer.browser.BrowserStorageAnalyzer}, same reasoning
     * as {@link #looksLikeOpaqueToken}. */
    public static boolean isSensitiveKeyName(String lowerKey) {
        for (String kw : SENSITIVE_KEY_KEYWORDS) {
            if (lowerKey.contains(kw)) return true;
        }
        return false;
    }

    /** Matches a real (browser-collected) key or value against the same known-SDK Web Storage key
     * formats {@link #findKnownSdkSignatures} checks statically against response bodies, exposed
     * for {@code com.b3xal.headeranalyzer.browser.BrowserStorageAnalyzer} so the browser bridge
     * gets the exact same CERTAIN-confidence signal without re-declaring the signature list.
     * @return the matched SDK's label, or null if nothing matched. */
    public static String matchKnownSdkSignature(String value) {
        if (value == null) return null;
        for (KnownSdkSignature sig : KNOWN_SDK_SIGNATURES) {
            if (sig.pattern.matcher(value).find()) return sig.label;
        }
        return null;
    }

    private static String parseName(String cookieStr) {
        int semi = cookieStr.indexOf(';');
        String nameVal = semi > 0 ? cookieStr.substring(0, semi) : cookieStr;
        int eq = nameVal.indexOf('=');
        return (eq > 0 ? nameVal.substring(0, eq) : nameVal).trim();
    }

    private static String parseValue(String cookieStr) {
        int semi = cookieStr.indexOf(';');
        String nameVal = semi > 0 ? cookieStr.substring(0, semi) : cookieStr;
        int eq = nameVal.indexOf('=');
        return eq >= 0 ? nameVal.substring(eq + 1).trim() : "";
    }
}
