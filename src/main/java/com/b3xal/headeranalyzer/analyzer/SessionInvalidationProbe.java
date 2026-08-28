package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.net.URI;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Active companion to {@link SessionLifecycleAnalyzer}'s passive stale-session-replay check:
 * rather than waiting to passively observe an old, invalidated credential get resent (rare in
 * practice, a real browser deletes a cleared cookie and never resends it on its own, only a
 * Repeater replay or a race would trigger the passive check), this REPLAYS one request per
 * recently-visited path with the OLD credential the moment a logout is detected, and checks
 * whether the server still accepts it.
 *
 * Two credential types, different "the old one might be dead now" signals:
 *   - Cookies: the server ITSELF says so, an explicit deletion Set-Cookie (Max-Age&lt;=0 / a
 *     past Expires), the same protocol-level signal {@link SessionLifecycleAnalyzer} anchors to.
 *   - Authorization: Bearer tokens have no protocol-level deletion signal, so active replay is
 *     triggered only by a successful logout-shaped request carrying that token. A normal A-to-B
 *     rotation merely resets touch history; it never implies that A was revoked.
 *
 * Every verdict is confirmed with a differential test against a CONTROL request (the same path,
 * credential stripped entirely), the same shape {@link JwtActiveProbe} already uses: if even the
 * control (no credential at all) resembles the original authenticated baseline, this path
 * doesn't actually depend on the credential (a public page, a shared layout), skip it rather
 * than risk a false positive, exactly the guard that class already relies on.
 *
 * Opt-in only ({@link com.b3xal.headeranalyzer.config.QuimeraSettings#isSessionInvalidationProbeEnabled()},
 * off by default): sends real replayed requests at the target, same sensitivity class as the JWT
 * active probe.
 */
public final class SessionInvalidationProbe {

    private static final String LABEL_COOKIE        = "Session invalidation probe (stale cookie replay)";
    private static final String LABEL_BEARER        = "Session invalidation probe (stale Bearer token replay)";
    private static final String LABEL_BEARER_PASSIVE = "Session invalidation check (stale Bearer reuse observed)";

    // Bounds: neither list needs to be large to catch the realistic case, and an analyst
    // browsing for hours before finally logging out shouldn't make either grow unboundedly.
    private static final int MAX_TOUCHED_PATHS = 10;
    private static final int MAX_INVALIDATED_BEARER_TOKENS = 20;

    private static final List<String> LOGOUT_PATH_KEYWORDS = List.of(
        "logout", "log-out", "log_out", "signout", "sign-out", "sign_out"
    );

    private static final class TouchedPath {
        final HttpRequest template;
        final HttpResponse baseline;
        TouchedPath(HttpRequest template, HttpResponse baseline) {
            this.template = template;
            this.baseline = baseline;
        }
    }

    private static final class CredentialHistory {
        String lastValue;
        // path -> most recent touch, LinkedHashMap so eviction drops the OLDEST path, not a
        // random one, when the bound is hit.
        final LinkedHashMap<String, TouchedPath> touches = new LinkedHashMap<>();
    }

    private final MontoyaApi api;
    private final HeaderAnalysisEngine engine;

    // Cookies: keyed by host+"|"+cookieName, one history per distinct session cookie.
    private final Map<String, CredentialHistory> cookieHistories = new ConcurrentHashMap<>();
    // Bearer: keyed by host alone, only the single most-recently-seen token's touch history is
    // kept per host, matches the "one active session per host at a time" assumption already
    // implicit elsewhere in Quimera (SessionLifecycleAnalyzer's own cookie tracking works the
    // same way, one lastValue per cookie name, not per every value ever seen).
    private final Map<String, CredentialHistory> bearerHistories = new ConcurrentHashMap<>();
    // Bearer tokens known to have been used in a logout-shaped request, per host, so later reuse
    // (passive, no extra request needed) can still be caught even without a touched-path history.
    private final Map<String, Set<String>> invalidatedBearerTokens = new ConcurrentHashMap<>();
    // Dedup for the passive Bearer-reuse finding, host+"|"+token, one-shot per token like every
    // other latch in this feature.
    private final Set<String> reportedStaleBearerReuse = ConcurrentHashMap.newKeySet();
    // Dedup for the ACTIVE Bearer probe burst, host+"|"+token, so repeated logout-shaped traffic
    // only ever replays the touched-path history once.
    private final Set<String> activeProbedBearerTokens = ConcurrentHashMap.newKeySet();
    public SessionInvalidationProbe(MontoyaApi api, HeaderAnalysisEngine engine) {
        this.api    = api;
        this.engine = engine;
    }

    public void clear() {
        cookieHistories.clear();
        bearerHistories.clear();
        invalidatedBearerTokens.clear();
        reportedStaleBearerReuse.clear();
        activeProbedBearerTokens.clear();
    }

    /** Called for every real (non-probe) response Quimera sees, when the setting is on. Records
     * this exchange as a "touch" for whatever session cookies / Bearer token it carries, then
     * checks whether it IS itself a logout (or reuses an already-invalidated Bearer token),
     * firing replay probes against the recently-touched paths when it is.
     * @return zero or more synthetic probe/observation results, already tagged with a
     * probeLabel and ready for {@code tab.onResultAdded}. */
    public List<UrlAnalysisResult> observe(String host, HttpRequestResponse rr, CookiesAndAuthConfig config) {
        List<UrlAnalysisResult> results = new ArrayList<>();
        if (host == null || host.isBlank() || rr == null || rr.request() == null || rr.response() == null) {
            return results;
        }
        String url  = safeUrl(rr.request());
        String path = HeaderAnalysisEngine.extractPath(url);

        recordCookieTouches(host, path, rr, config);
        results.addAll(checkCookieLogout(host, rr, config));

        // Rotation is tracked only to avoid mixing baselines. It is not an invalidation signal.
        recordBearerTouch(host, path, rr);
        results.addAll(checkBearerLogout(host, path, rr, config));
        results.addAll(checkBearerReuse(host, rr));

        return results;
    }

    // ── Cookies ──────────────────────────────────────────────────────────────

    private void recordCookieTouches(String host, String path, HttpRequestResponse rr, CookiesAndAuthConfig config) {
        var cookieHeader = rr.request().header("Cookie");
        if (cookieHeader == null || cookieHeader.value() == null) return;
        String[] pairs = cookieHeader.value().split(";");
        Map<String, Integer> counts = new HashMap<>();
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq > 0) counts.merge(pair.substring(0, eq).trim(), 1, Integer::sum);
        }
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq <= 0) continue;
            String name  = pair.substring(0, eq).trim();
            String value = pair.substring(eq + 1).trim();
            // Same-name cookies with different Path/Domain are serialized without their scope;
            // attributing either value to this path would be a guess and can produce a false
            // stale-session replay. Passive cookie analysis remains unaffected.
            if (counts.getOrDefault(name, 0) > 1) continue;
            if (value.isEmpty() || (!CookieAnalyzer.nameLooksSensitive(name, config)
                    && StructuredCookieJwtAnalyzer.extract(value).isEmpty())) continue;
            CredentialHistory h = cookieHistories.computeIfAbsent(host + "|" + name, k -> new CredentialHistory());
            synchronized (h) {
                h.lastValue = value;
                addTouch(h, path, rr.request(), rr.response());
            }
        }
    }

    private List<UrlAnalysisResult> checkCookieLogout(String host, HttpRequestResponse rr,
                                                       CookiesAndAuthConfig config) {
        List<UrlAnalysisResult> results = new ArrayList<>();
        List<String> setCookieLines = new ArrayList<>();
        rr.response().headers().forEach(h -> {
            if (h.name().equalsIgnoreCase("Set-Cookie")) setCookieLines.add(h.value());
        });

        for (String cookieStr : setCookieLines) {
            String name = CookieAnalyzer.parseName(cookieStr);
            if (name.isEmpty()) continue;
            List<String> attrs = CookieAnalyzer.parseAttrs(cookieStr);
            if (!CookieAnalyzer.isBeingDeleted(cookieStr, attrs)) continue;

            String domainAttr = attrValue(attrs, "domain=");
            boolean hostOnly = domainAttr == null || domainAttr.isBlank();
            String effectiveDomain = hostOnly ? host : domainAttr.toLowerCase(Locale.ROOT).replaceFirst("^\\.+", "");
            String pathAttr = attrValue(attrs, "path=");
            String deletionUrl = safeUrl(rr.request());
            String effectivePath = pathAttr != null && pathAttr.startsWith("/")
                    ? pathAttr : CookieConsistencyAnalyzer.defaultPath(HeaderAnalysisEngine.extractPath(deletionUrl));

            CredentialHistory hist = cookieHistories.get(host + "|" + name);
            if (hist == null) continue;
            String oldValue;
            List<TouchedPath> touches;
            synchronized (hist) {
                oldValue = hist.lastValue;
                touches  = hist.touches.values().stream()
                        .filter(t -> cookieScopeMatches(safeUrl(t.template), effectiveDomain, effectivePath, hostOnly))
                        .toList();
                hist.lastValue = null; // consumed, next grant starts a fresh "active value"
            }
            if (oldValue == null || oldValue.isBlank()) continue;

            for (TouchedPath t : touches) {
                UrlAnalysisResult r = probeCookiePath(host, name, oldValue, t, config);
                if (r != null) results.add(r);
            }
        }
        return results;
    }

    private UrlAnalysisResult probeCookiePath(String host, String cookieName, String oldValue,
                                               TouchedPath touch, CookiesAndAuthConfig config) {
        HttpRequest sanitized = withoutAllAuthentication(touch.template, config);
        HttpRequestResponse controlRr = safeSend(sanitized);
        if (controlRr == null || controlRr.response() == null) return null;
        if (ResponseSimilarity.equivalent(touch.baseline, controlRr.response())) {
            return null; // this path doesn't actually depend on the cookie, skip
        }

        HttpRequestResponse probeRr = safeSend(withCookieValue(sanitized, cookieName, oldValue));
        if (probeRr == null || probeRr.response() == null) return null;
        if (!ResponseSimilarity.equivalent(touch.baseline, probeRr.response())) {
            return null; // old cookie no longer works, logout is real, nothing to report
        }

        HeaderFinding finding = new HeaderFinding(
            "Session cookie still accepted after being invalidated: " + cookieName,
            cookieName, oldValue,
            "Quimera detected a deletion Set-Cookie for '" + cookieName + "' (a logout) and replayed a " +
            "previously-visited request to this same path with the OLD, now-supposedly-invalidated value. " +
            "The response (HTTP " + probeRr.response().statusCode() + ", " + safeLen(probeRr.response().bodyToString()) +
            " bytes) closely resembles the ORIGINAL authenticated response to this path, and clearly differs " +
            "from a control request sent with no cookie at all, meaning the server still accepts this old " +
            "session. Confirmed via a live differential test (not a passive guess), replay the request in " +
            "Repeater with this old cookie value to verify by hand before reporting, then ensure logout " +
            "actually revokes the session server-side, not just asks the browser to forget the cookie.",
            "Cookie: " + cookieName + "=" + truncate(oldValue) + "  (previously invalidated)  ->  HTTP " +
                probeRr.response().statusCode(),
            Severity.MEDIUM, Confidence.FIRM, Category.COOKIE,
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html");

        return buildProbeResult(host, LABEL_COOKIE, probeRr, finding);
    }

    // ── Authorization: Bearer ────────────────────────────────────────────────

    /** Tracks Bearer rotation and starts a fresh history without treating rotation as logout. */
    private void recordBearerTouch(String host, String path, HttpRequestResponse rr) {
        String token = bearerToken(rr.request());
        if (token == null) return;

        CredentialHistory h = bearerHistories.computeIfAbsent(host, k -> new CredentialHistory());
        String previousValue;
        synchronized (h) {
            previousValue = h.lastValue;
            boolean changed = previousValue != null && !previousValue.equals(token);
            if (changed) {
                h.touches.clear(); // fresh session under the new token, keep baselines from mixing
            }
            h.lastValue = token;
            addTouch(h, path, rr.request(), rr.response());
        }
    }

    /** Fires the moment a request to a logout-shaped path succeeds while carrying a Bearer
     * token: no protocol signal exists for "this token is now invalid" the way a cookie
     * deletion gives, a URL-keyword guess is the only passive option here. */
    private List<UrlAnalysisResult> checkBearerLogout(String host, String path, HttpRequestResponse rr,
                                                       CookiesAndAuthConfig config) {
        List<UrlAnalysisResult> results = new ArrayList<>();
        if (!looksLikeLogoutPath(path)) return results;

        // A 404/5xx on a guessed logout path proves nothing, only trust a call that actually
        // looks like it succeeded (2xx/3xx, e.g. a redirect back to the login page).
        int status = rr.response().statusCode();
        if (status < 200 || status >= 400) return results;

        String token = bearerToken(rr.request());
        if (token == null) return results;

        invalidatedBearerTokens.computeIfAbsent(host, k -> ConcurrentHashMap.newKeySet());
        addBoundedToSet(invalidatedBearerTokens.get(host), token, MAX_INVALIDATED_BEARER_TOKENS);

        // Without this, every subsequent request that ALSO happens to match a logout keyword
        // (e.g. a logout confirmation page loading "/img/logout-icon.png") would re-fire the
        // whole touched-path probe burst again for the same already-detected token, unbounded.
        // The passive reuse check below has its own separate latch and keeps working regardless.
        if (!activeProbedBearerTokens.add(host + "|" + token)) return results;

        CredentialHistory hist = bearerHistories.get(host);
        if (hist == null) return results;
        List<TouchedPath> touches;
        synchronized (hist) {
            touches = new ArrayList<>(hist.touches.values());
        }
        for (TouchedPath t : touches) {
            UrlAnalysisResult r = probeBearerPath(host, token, t,
                    "Quimera detected a request to a logout-shaped path (matching /logout, /signout, ...) " +
                    "carrying this Bearer token.", config);
            if (r != null) results.add(r);
        }
        return results;
    }

    /** @param triggerReason human-readable account of WHY Quimera thinks the old token might be
     *                       invalid, the two callers have genuinely different evidence for that
     *                       (a token change vs. a logout-shaped URL), the finding text should say
     *                       which one actually applied here rather than always claiming the
     *                       stronger of the two. */
    private UrlAnalysisResult probeBearerPath(String host, String oldToken, TouchedPath touch,
                                               String triggerReason, CookiesAndAuthConfig config) {
        HttpRequest sanitized = withoutAllAuthentication(touch.template, config);
        HttpRequestResponse controlRr = safeSend(sanitized);
        if (controlRr == null || controlRr.response() == null) return null;
        if (ResponseSimilarity.equivalent(touch.baseline, controlRr.response())) {
            return null; // this path doesn't actually depend on the token, skip
        }

        HttpRequestResponse probeRr = safeSend(sanitized.withUpdatedHeader("Authorization", "Bearer " + oldToken));
        if (probeRr == null || probeRr.response() == null) return null;
        if (!ResponseSimilarity.equivalent(touch.baseline, probeRr.response())) {
            return null; // old token no longer works
        }

        HeaderFinding finding = new HeaderFinding(
            "Bearer token still accepted after being replaced: possible session management flaw",
            "Authorization", oldToken,
            triggerReason + " Quimera replayed a previously-visited request to that same path with the OLD " +
            "token forced back in. The response (HTTP " + probeRr.response().statusCode() + ", " +
            safeLen(probeRr.response().bodyToString()) + " bytes) closely resembles the ORIGINAL authenticated " +
            "response, and clearly differs from a control request sent with no Authorization header at all, " +
            "meaning the old token still works. Confirmed via a live differential test, replay the request in " +
            "Repeater with this old token to verify by hand before reporting. Bearer tokens have no protocol-" +
            "level revocation signal the way a cookie deletion gives, so if the app really did mean to end " +
            "this token's session, it needs to actively revoke it server-side (a blocklist, or short-lived " +
            "tokens with refresh), not just stop using it client-side.",
            "Authorization: Bearer " + truncate(oldToken) + "  (superseded)  ->  HTTP " +
                probeRr.response().statusCode(),
            Severity.MEDIUM, Confidence.FIRM, Category.AUTH,
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html");

        return buildProbeResult(host, LABEL_BEARER, probeRr, finding);
    }

    /** Passive fallback, no extra request needed: if a Bearer token already flagged as
     * invalidated by {@link #checkBearerLogout} shows up again in ANY later real traffic (not
     * just the touched-path history, which is bounded), and the server still responds 2xx, that
     * alone is worth flagging even without an active replay. Lower confidence than the active
     * probe findings, both "was this really a logout" AND "was this really still authenticated"
     * are heuristics here, no differential test against a control. */
    private List<UrlAnalysisResult> checkBearerReuse(String host, HttpRequestResponse rr) {
        List<UrlAnalysisResult> results = new ArrayList<>();
        String token = bearerToken(rr.request());
        if (token == null) return results;
        Set<String> invalidated = invalidatedBearerTokens.get(host);
        if (invalidated == null || !invalidated.contains(token)) return results;

        int status = rr.response().statusCode();
        if (status < 200 || status >= 300) return results;

        // Only latched once we know this observation actually produces a finding, a correctly-
        // REJECTED reuse attempt (401/403) must not consume the one-shot dedup, or a genuinely
        // vulnerable reuse seen later for the same token would be silently swallowed.
        String dedupeKey = host + "|" + token;
        if (!reportedStaleBearerReuse.add(dedupeKey)) return results;

        HeaderFinding finding = new HeaderFinding(
            "Bearer token still accepted after being replaced: possible session management flaw",
            "Authorization", token,
            "This exact Bearer token was previously superseded (either a different token replaced it on the " +
            "same host, or it was used in a request to a logout-shaped path), and is now being reused in a " +
            "normal request that got HTTP " + status + " instead of 401/403. Passive observation, not a " +
            "confirmed differential test: both \"was this token really meant to stop working\" and \"does this " +
            "response really mean the token still works\" (bare status-code heuristic) are unconfirmed, " +
            "verify by hand before reporting. If the app really did mean to end this token's session, it " +
            "needs to actively revoke it server-side, not just stop using it client-side.",
            "Authorization: Bearer " + truncate(token) + "  (seen again after being superseded)  ->  HTTP " + status,
            Severity.MEDIUM, Confidence.TENTATIVE, Category.AUTH,
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html");

        results.add(buildObservationResult(host, LABEL_BEARER_PASSIVE, rr, finding));
        return results;
    }

    // ── Shared: touch tracking, request building, comparison ────────────────────

    private static void addTouch(CredentialHistory h, String path, HttpRequest template, HttpResponse baseline) {
        h.touches.remove(path); // re-insert so recency ordering reflects the latest visit
        h.touches.put(path, new TouchedPath(template, baseline));
        while (h.touches.size() > MAX_TOUCHED_PATHS) {
            var it = h.touches.entrySet().iterator();
            it.next();
            it.remove();
        }
    }

    private static void addBoundedToSet(Set<String> set, String value, int max) {
        if (set.contains(value)) return;
        if (set.size() >= max) {
            var it = set.iterator();
            if (it.hasNext()) { it.next(); it.remove(); }
        }
        set.add(value);
    }

    private static boolean looksLikeLogoutPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String kw : LOGOUT_PATH_KEYWORDS) {
            if (lower.contains(kw)) return true;
        }
        return false;
    }

    static boolean cookieScopeMatches(String requestUrl, String cookieDomain,
                                      String cookiePath, boolean hostOnly) {
        try {
            URI uri = URI.create(requestUrl);
            String host = uri.getHost();
            if (host == null) return false;
            host = host.toLowerCase(Locale.ROOT);
            boolean domainMatch = hostOnly ? host.equals(cookieDomain)
                    : host.equals(cookieDomain) || host.endsWith("." + cookieDomain);
            if (!domainMatch) return false;
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) path = "/";
            if (path.equals(cookiePath)) return true;
            return path.startsWith(cookiePath)
                    && (cookiePath.endsWith("/") || (path.length() > cookiePath.length()
                    && path.charAt(cookiePath.length()) == '/'));
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static String attrValue(List<String> attrs, String prefix) {
        for (String attr : attrs) if (attr.startsWith(prefix)) return attr.substring(prefix.length()).trim();
        return null;
    }

    private static String bearerToken(HttpRequest request) {
        var auth = request.header("Authorization");
        if (auth == null || auth.value() == null) return null;
        String v = auth.value().trim();
        int space = v.indexOf(' ');
        if (space <= 0) return null;
        if (!v.substring(0, space).equalsIgnoreCase("Bearer")) return null;
        String token = v.substring(space + 1).trim();
        return token.isEmpty() ? null : token;
    }

    private static HttpRequest withCookieValue(HttpRequest template, String targetName, String newValueOrNullToRemove) {
        var cookieHeader = template.header("Cookie");
        String rebuilt = rebuildCookieHeader(cookieHeader != null ? cookieHeader.value() : "", targetName, newValueOrNullToRemove);
        return rebuilt.isEmpty() ? template.withRemovedHeader("Cookie") : template.withUpdatedHeader("Cookie", rebuilt);
    }

    private static String rebuildCookieHeader(String cookieHeader, String targetName, String newValueOrNullToRemove) {
        StringBuilder sb = new StringBuilder();
        for (String pair : cookieHeader.split(";")) {
            String trimmed = pair.trim();
            int eq = trimmed.indexOf('=');
            if (eq <= 0) continue;
            String name = trimmed.substring(0, eq).trim();
            if (name.equals(targetName)) {
                if (newValueOrNullToRemove == null) continue; // drop this pair entirely (the control)
                if (sb.length() > 0) sb.append("; ");
                sb.append(name).append('=').append(newValueOrNullToRemove);
                continue;
            }
            if (sb.length() > 0) sb.append("; ");
            sb.append(trimmed);
        }
        return sb.toString();
    }

    private HttpRequestResponse safeSend(HttpRequest req) {
        try {
            return api.http().sendRequest(req);
        } catch (Exception ex) {
            api.logging().logToError("[Quimera] Session invalidation probe request error: " + ex.getMessage());
            return null;
        }
    }

    static HttpRequest withoutAllAuthentication(HttpRequest request, CookiesAndAuthConfig config) {
        HttpRequest sanitized = request.withRemovedHeader("Authorization");
        for (String header : AuthHeaderAnalyzer.allApiKeyHeaders(config)) {
            sanitized = sanitized.withRemovedHeader(header);
        }
        var cookie = sanitized.header("Cookie");
        if (cookie == null || cookie.value() == null) return sanitized;
        StringBuilder kept = new StringBuilder();
        for (String pair : cookie.value().split(";")) {
            String trimmed = pair.trim();
            int eq = trimmed.indexOf('=');
            if (eq <= 0) continue;
            String name = trimmed.substring(0, eq).trim();
            String value = trimmed.substring(eq + 1).trim();
            boolean authCookie = CookieAnalyzer.nameLooksSensitive(name, config)
                    || !StructuredCookieJwtAnalyzer.extract(value).isEmpty();
            if (authCookie) continue;
            if (kept.length() > 0) kept.append("; ");
            kept.append(trimmed);
        }
        return kept.length() == 0
                ? sanitized.withRemovedHeader("Cookie")
                : sanitized.withUpdatedHeader("Cookie", kept.toString());
    }

    private static int safeLen(String s) { return s == null ? 0 : s.length(); }

    private static String safeUrl(HttpRequest request) {
        try { return request.url(); } catch (Exception ex) { return ""; }
    }

    private static String safeToString(Object httpMessage) {
        try { return httpMessage == null ? null : httpMessage.toString(); } catch (Exception ex) { return null; }
    }

    private static String truncate(String value) {
        return value.length() > 200 ? value.substring(0, 200) + "…" : value;
    }

    /** Builds the UrlAnalysisResult for a genuine active probe (a real new request Quimera just
     * sent), full re-analysis of that response's own headers plus the one finding this class
     * produced. */
    private UrlAnalysisResult buildProbeResult(String host, String label, HttpRequestResponse rr, HeaderFinding finding) {
        Map<String, String> headerMap = collectHeaders(rr);
        String url = safeUrl(rr.request());
        UrlAnalysisResult result = engine.analyze(url, headerMap, rr.response().statusCode(),
                rr.response().bodyToString(), rr.request().method());
        result.rawRequest       = safeToString(rr.request());
        result.rawResponse      = safeToString(rr.response());
        result.method           = rr.request().method();
        result.statusCode       = rr.response().statusCode();
        result.contentLength    = rr.response().body().length();
        result.probeLabel       = label;
        result.originalRequest  = rr.request();
        result.originalResponse = rr.response();
        return result.withExtraFindings(List.of(finding));
    }

    /** Builds the UrlAnalysisResult for a purely passive observation (checkBearerReuse): rr is
     * REAL traffic Quimera already saw via its normal passive path, not a new request, so this
     * skips re-running full header analysis (already happened once for this exact exchange) and
     * just carries the one new finding. Still needs a distinct probeLabel (not null) so its
     * rowKey doesn't collide with and silently overwrite the real captured row for this same
     * request in domainStore/CookiePanel. */
    private static UrlAnalysisResult buildObservationResult(String host, String label, HttpRequestResponse rr, HeaderFinding finding) {
        String url  = safeUrl(rr.request());
        String path = HeaderAnalysisEngine.extractPath(url);
        UrlAnalysisResult result = new UrlAnalysisResult(url, host, path, List.of(finding), Map.of());
        result.rawRequest       = safeToString(rr.request());
        result.rawResponse      = safeToString(rr.response());
        result.method           = rr.request().method();
        result.statusCode       = rr.response().statusCode();
        result.contentLength    = safeLen(rr.response().bodyToString());
        result.probeLabel       = label;
        result.originalRequest  = rr.request();
        result.originalResponse = rr.response();
        return result;
    }

    private static Map<String, String> collectHeaders(HttpRequestResponse rr) {
        Map<String, String> headerMap = new LinkedHashMap<>();
        rr.response().headers().forEach(h ->
                com.b3xal.headeranalyzer.util.HeaderMaps.addResponse(headerMap, h.name(), h.value()));
        return headerMap;
    }
}
