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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Passive, cross-request session-lifecycle tracking: two checks neither {@link CookieAnalyzer}
 * (stateless, one response at a time) nor {@link RetestTracker} (tracks finding status, not
 * cookie VALUES) can do, both requiring memory of what Quimera has already seen for a given
 * (host, cookie name) pair over the whole capture session.
 *
 * 1) Stale-session-replay: a cookie value the server itself explicitly invalidated (a deletion
 *    Set-Cookie, Max-Age&lt;=0 or an already-past Expires, the same signal
 *    {@link CookieAnalyzer#isBeingDeleted} already uses) is later resent by a REQUEST and the
 *    server responds as if it's still a valid session, logout/invalidation isn't real.
 * 2) Static-session-on-login: across two or more separate "logout, then a fresh Set-Cookie for
 *    the same name" cycles, the granted value is byte-for-byte identical every time, the session
 *    identifier isn't actually being regenerated on login.
 *
 * Both anchor "a login happened" to the same protocol-level signal: a non-deleting Set-Cookie for
 * this (host, name) arriving right after a deleting one was observed. That's deliberate, a URL
 * keyword guess ("/login", "/signin", ...) would be far more fragile across the wide range of
 * real-world apps this needs to work against unmodified. The trade-off: an app that never sends
 * an explicit deletion Set-Cookie on logout (relies on purely server-side invalidation) won't
 * anchor either check, no login/logout cycle is ever observed for it. Scoped to COOKIES only,
 * not Authorization/Bearer/API-key tokens: those have no equivalent "this is now invalid"
 * signal over the wire the way a deletion Set-Cookie gives us, and plenty of long-lived API keys
 * are deliberately static, "static = bad" doesn't hold for them the way it does for a session
 * cookie regenerated (or not) on every login.
 *
 * Only tracks cookies whose name looks session/auth-shaped ({@link CookieAnalyzer#nameLooksSensitive}),
 * same gate CookieAnalyzer's own long-lifetime check uses, so an ordinary preference/analytics
 * cookie being cleared and reissued (extremely common, meaningless here) never enters this at all.
 */
public final class SessionLifecycleAnalyzer {

    // Bounds on the per-cookie history, a session that runs for days shouldn't grow this
    // unboundedly, and neither check needs more than a handful of samples to reach a conclusion.
    private static final int MAX_TRACKED_VALUES = 8;

    private static final class CookieState {
        final String name;
        final String domain;
        final String path;
        CookieState(String name, String domain, String path) {
            this.name = name;
            this.domain = domain;
            this.path = path;
        }
        // The last non-deleted value actually seen, kept up to date on every grant. Needed
        // because the deletion Set-Cookie's OWN value is almost always blank in practice
        // ("Set-Cookie: session=; Max-Age=0", the idiom every major framework uses to clear a
        // cookie), so it can't tell us what value is being invalidated, only that SOMETHING is.
        String lastActiveValue;
        final LinkedHashSet<String> clearedValues = new LinkedHashSet<>();
        // DISTINCT values granted after a clear, deduped, so this alone can't tell "granted once"
        // from "granted 5 times, always the same value", grantsAfterClearCount below is what
        // actually counts how many separate clear->regrant cycles happened.
        final LinkedHashSet<String> distinctValuesGrantedAfterClear = new LinkedHashSet<>();
        int grantsAfterClearCount;
        boolean awaitingRegrant;
        boolean staleReplayReported;
        boolean staticAcrossLoginsReported;
    }

    private final Map<String, CookieState> states = new ConcurrentHashMap<>();

    public void clear() {
        states.clear();
    }

    /**
     * @param host            the response's host, part of the tracking key (same cookie name on
     *                        two different hosts is two independent lifecycles)
     * @param path            just for evidence text, which URL this particular observation came from
     * @param responseHeaders this response's headers (case-insensitive map), read for Set-Cookie
     * @param requestHeaders  the SAME exchange's request headers, read for Cookie, may be null/empty
     *                        (some call sites don't have it), degrades to Set-Cookie-only tracking
     * @param statusCode      this response's status, used by the stale-replay check to judge
     *                        whether the server actually treated the request as authenticated
     * @param config          from Settings (Cookies & Auth Rules), same session-name-keyword gate
     *                        {@link CookieAnalyzer} itself uses, including any extra keywords the
     *                        analyst configured there
     */
    public List<HeaderFinding> observe(String host, String path, Map<String, String> responseHeaders,
                                        Map<String, String> requestHeaders, int statusCode,
                                        CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (host == null || host.isBlank()) return findings;

        // Check 1 first, against whatever state already exists, BEFORE this response's own
        // Set-Cookie mutates it below, evaluating a stale value against the state that was true
        // when the request was actually sent.
        String cookieHeader = getCI(requestHeaders, "Cookie");
        if (cookieHeader != null && !cookieHeader.isBlank()) {
            boolean isAsset = isAssetContentType(getCI(responseHeaders, "Content-Type"));
            checkStaleReplay(host, path, cookieHeader, statusCode, isAsset, findings);
        }

        String setCookie = getCI(responseHeaders, "Set-Cookie");
        if (setCookie != null && !setCookie.isBlank()) {
            for (String line : setCookie.split("\n")) {
                line = line.trim();
                if (line.isEmpty()) continue;
                ingestSetCookie(host, path, line, config, findings);
            }
        }
        return findings;
    }

    /** Excludes static assets from counting as "the server treated this as authenticated": an
     * image/font/CSS/JS bundle returns 2xx for anyone, cookie valid or not, that used to be the
     * single biggest false-positive source for the stale-replay check below. Deliberately a
     * deny-list, not an allow-list (matches HeaderAnalysisEngine#applyContextFilter's own
     * isAsset), an unknown/blank Content-Type still counts as "could be a real document". */
    private static boolean isAssetContentType(String contentType) {
        if (contentType == null) return false;
        String ct = contentType.toLowerCase(Locale.ROOT);
        return ct.startsWith("image/") || ct.startsWith("font/") || ct.contains("text/css")
                || ct.contains("javascript") || ct.startsWith("application/octet-stream");
    }

    private void checkStaleReplay(String host, String requestPath, String cookieHeader,
                                   int statusCode, boolean isAsset,
                                   List<HeaderFinding> findings) {
        // Cookie: request header is "name1=value1; name2=value2", not the Set-Cookie grammar.
        for (String pair : cookieHeader.split(";")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) continue;
            String name = pair.substring(0, eq).trim();
            String value = pair.substring(eq + 1).trim();
            if (value.isEmpty()) continue;

            for (CookieState state : states.values()) {
                if (!state.name.equals(name) || !domainMatches(host, state.domain)
                        || !pathMatches(requestPath, state.path)) continue;
                synchronized (state) {
                    if (state.staleReplayReported || !state.clearedValues.contains(value)) continue;

                // Heuristic, not a proof: a 2xx, non-asset response is the closest passive signal
                // Quimera has for "the server still treated this as an authenticated session". A
                // redirect (likely bounced to a login page), 401/403/4xx/5xx isn't that signal,
                // neither is a static asset (returns 2xx for anyone regardless of the cookie).
                if (isAsset || statusCode < 200 || statusCode >= 300) continue;

                state.staleReplayReported = true;
                findings.add(new HeaderFinding(
                    "Session cookie still accepted after being invalidated: " + name,
                    name, value,
                    "This request sent '" + name + "' with a value the server itself previously invalidated " +
                    "(a deletion Set-Cookie, Max-Age<=0 or an already-past Expires, was observed for this exact " +
                    "value earlier in this capture). The server responded HTTP " + statusCode + " instead of " +
                    "rejecting it (401/403) or bouncing to a login page, suggesting the old session is still " +
                    "accepted server-side despite being logically logged out. If this request was replayed on " +
                    "purpose (e.g. from Repeater/history) that's exactly the test this confirms; if it happened " +
                    "organically, it's still worth confirming server-side session invalidation actually revokes " +
                    "the token rather than just asking the browser to forget it. This is a 2xx/non-asset " +
                    "heuristic, not a proof of authentication, some apps return 200 with a body saying " +
                    "\"not logged in\" instead of a 401, always confirm this response's actual content before " +
                    "reporting.",
                    "Cookie: " + name + "=" + truncate(value) + "  (previously invalidated on " + host + ")  ->  HTTP " + statusCode,
                    Severity.MEDIUM, Confidence.TENTATIVE, Category.COOKIE,
                    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"));
                }
            }
        }
    }

    private void ingestSetCookie(String host, String path, String cookieStr, CookiesAndAuthConfig config,
                                  List<HeaderFinding> findings) {
        String name = CookieAnalyzer.parseName(cookieStr);
        if (name.isEmpty()) return;

        List<String> attrs = CookieAnalyzer.parseAttrs(cookieStr);
        String domain = attrValue(attrs, "domain=");
        if (domain == null || domain.isBlank()) domain = host.toLowerCase(Locale.ROOT);
        else domain = domain.toLowerCase(Locale.ROOT).replaceFirst("^\\.+", "");
        String cookiePath = attrValue(attrs, "path=");
        if (cookiePath == null || !cookiePath.startsWith("/")) {
            cookiePath = CookieConsistencyAnalyzer.defaultPath(path);
        }
        String key = name + "|" + domain + "|" + cookiePath;
        String finalDomain = domain;
        String finalCookiePath = cookiePath;
        CookieState state = states.get(key);
        String value = CookieAnalyzer.parseValue(cookieStr);
        boolean authenticationLike = CookieAnalyzer.nameLooksSensitive(name, config)
                || !StructuredCookieJwtAnalyzer.extract(value).isEmpty();
        // A deletion sentinel has an empty value, so a generic-name structured JWT can only be
        // recognized from the state created when its non-empty value was originally issued.
        if (!authenticationLike && state == null) return;
        if (state == null) {
            CookieState candidate = new CookieState(name, finalDomain, finalCookiePath);
            CookieState raced = states.putIfAbsent(key, candidate);
            state = raced == null ? candidate : raced;
        }

        synchronized (state) {
        if (CookieAnalyzer.isBeingDeleted(cookieStr, attrs)) {
            // The deletion Set-Cookie's OWN value is ignored on purpose, see lastActiveValue's
            // own comment, it's the value from the PRIOR grant that's actually being invalidated.
            if (state.lastActiveValue != null) addBounded(state.clearedValues, state.lastActiveValue);
            state.lastActiveValue = null;
            state.awaitingRegrant = true;
            return;
        }

        if (value.isBlank()) return;
        state.lastActiveValue = value;
        // This exact value is demonstrably active again right now, whether or not the grant
        // below counts as a fresh login. Without this, a value that gets cleared and later
        // legitimately re-granted (e.g. the static-across-logins bug this class itself detects)
        // would stay flagged as "invalidated" forever, false-positiving the stale-replay check
        // above on every completely normal subsequent request using that still-valid cookie.
        state.clearedValues.remove(value);

        if (!state.awaitingRegrant) return; // a normal refresh/reissue mid-session, not a login, ignore
        state.awaitingRegrant = false;

        state.grantsAfterClearCount++;
        addBounded(state.distinctValuesGrantedAfterClear, value);

        if (state.staticAcrossLoginsReported) return;
        // Need >=2 separate logout->login cycles to call it "static across logins" at all, and
        // every one of those grants must have produced the SAME value (the distinct-value set
        // stayed at size 1 despite >=2 separate adds) for it to mean anything, if it ever
        // produced a second distinct value, it does rotate, this never fires again for this pair.
        if (state.grantsAfterClearCount < 2) return;
        if (state.distinctValuesGrantedAfterClear.size() != 1) return;

        state.staticAcrossLoginsReported = true;
        findings.add(new HeaderFinding(
            "Session cookie value is static across separate logins: " + name,
            name, value,
            "'" + name + "' was granted the exact same value across multiple separate logout-then-login " +
            "cycles observed on " + host + " (a deletion Set-Cookie followed by a fresh one, more than " +
            "once, same value every time). A session identifier that doesn't actually regenerate on login " +
            "enables session fixation and makes the value trivially predictable once seen a single time. " +
            "Confirmed only for this one browser/account in this capture, worth testing a second real " +
            "account to see whether the value is static across users too, or just across repeat logins by " +
            "the same one. Ensure the server issues a genuinely new, random session identifier on every login.",
            "Set-Cookie: " + name + "=" + truncate(value) + " (unchanged across repeat logins, seen at " + path + ")",
            Severity.MEDIUM, Confidence.FIRM, Category.COOKIE,
            "https://owasp.org/www-community/attacks/Session_fixation"));
        }
    }

    private static void addBounded(LinkedHashSet<String> set, String value) {
        if (set.contains(value)) return;
        if (set.size() >= MAX_TRACKED_VALUES) {
            // Drop the oldest entry to make room, iteration order is insertion order.
            var it = set.iterator();
            it.next();
            it.remove();
        }
        set.add(value);
    }

    private static String truncate(String value) {
        return value.length() > 200 ? value.substring(0, 200) + "…" : value;
    }

    private static String getCI(Map<String, String> headers, String name) {
        if (headers == null) return null;
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (name.equalsIgnoreCase(e.getKey())) return e.getValue();
        }
        return null;
    }

    private static String attrValue(List<String> attrs, String prefix) {
        for (String attr : attrs) if (attr.startsWith(prefix)) return attr.substring(prefix.length()).trim();
        return null;
    }

    private static boolean domainMatches(String requestHost, String cookieDomain) {
        String host = requestHost == null ? "" : requestHost.toLowerCase(Locale.ROOT);
        return host.equals(cookieDomain) || host.endsWith("." + cookieDomain);
    }

    private static boolean pathMatches(String requestPath, String cookiePath) {
        String request = requestPath == null || requestPath.isBlank() ? "/" : requestPath;
        if (request.equals(cookiePath)) return true;
        if (!request.startsWith(cookiePath)) return false;
        return cookiePath.endsWith("/") || (request.length() > cookiePath.length()
                && request.charAt(cookiePath.length()) == '/');
    }
}
