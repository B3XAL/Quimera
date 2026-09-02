package com.b3xal.headeranalyzer.browser;

import com.b3xal.headeranalyzer.analyzer.JwtAnalyzer;
import com.b3xal.headeranalyzer.analyzer.StructuredCookieJwtAnalyzer;
import com.b3xal.headeranalyzer.analyzer.WebStorageAnalyzer;
import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.util.JsonUtil;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The headline upgrade the browser bridge exists for: {@link com.b3xal.headeranalyzer.analyzer.WebStorageAnalyzer}
 * only ever sees response-body TEXT and has to guess whether a localStorage/sessionStorage call
 * actually stores something sensitive, capping every finding at FIRM/TENTATIVE and asking the
 * analyst to "verify in dev tools" (see that class's own javadoc). Here the browser extension has
 * already read the REAL runtime value, so the same known-SDK-signature/JWT/opaque-token judgment
 * calls land at CERTAIN instead, no guess involved.
 *
 * Deliberately reuses {@link JwtAnalyzer} and {@link WebStorageAnalyzer}'s exposed helpers rather
 * than re-implementing token classification, one methodology, two entry points (static body text
 * vs. real browser value).
 */
public final class BrowserStorageAnalyzer {

    private static final Pattern USER_IDENTIFIER_KEY = Pattern.compile(
            "(?i)^(?:user|account|customer|member|profile|subject)[_.-]?id$|^uid$");
    private static final Pattern EMAIL_KEY = Pattern.compile("(?i)^(?:e[_.-]?mail|emailAddress)$");
    private static final Pattern USERNAME_KEY = Pattern.compile(
            "(?i)^(?:user[_.-]?name|login[_.-]?name|screen[_.-]?name)$");
    private static final Pattern PHONE_KEY = Pattern.compile(
            "(?i)^(?:phone|phoneNumber|mobile|mobileNumber|telephone)$");
    private static final Pattern PERSON_NAME_KEY = Pattern.compile(
            "(?i)^(?:full[_.-]?name|display[_.-]?name|first[_.-]?name|last[_.-]?name|given[_.-]?name|family[_.-]?name)$");
    private static final Pattern UUID = Pattern.compile(
            "(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern EMAIL = Pattern.compile(
            "^[^\\s@]{1,64}@[^\\s@.]{1,63}(?:\\.[^\\s@.]{1,63})+$");
    private static final Pattern PHONE = Pattern.compile("^\\+?[0-9][0-9 ()-]{6,20}$");
    private static final Pattern HUMAN_NAME = Pattern.compile("^[\\p{L}][\\p{L}' -]{1,79}$");
    private static final Pattern USERNAME = Pattern.compile("^[\\p{L}0-9][\\p{L}0-9._@-]{2,79}$");

    private BrowserStorageAnalyzer() {}

    // No cookie-flag analysis here on purpose: Quimera's existing Set-Cookie-header-based
    // CookieAnalyzer already covers Secure/HttpOnly/SameSite/domain-scoping from proxied HTTP
    // traffic, the bridge is only for what that path can't see, Web Storage here, DOM in
    // BrowserDomAnalyzer.
    public static List<HeaderFinding> analyze(BrowserPayload payload, CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (config.webStorageCheckEnabled) {
            findings.addAll(analyzeStorage(payload.localStorage, "localStorage", config));
            findings.addAll(analyzeStorage(payload.sessionStorage, "sessionStorage", config));
        }
        if (config.jwtEnabled) {
            for (BrowserPayload.BrowserCookie cookie : payload.browserCookies) {
                if (cookie.name().isBlank() || cookie.value().isBlank()) continue;
                findings.addAll(StructuredCookieJwtAnalyzer.analyze(cookie.name(), cookie.value(),
                        "(Browser cookie)", config));
            }
        }
        return findings;
    }

    /** One VALUE, and every place it was seen within this one storage bucket (top-level key, or a
     * dotted/bracketed path inside a JSON blob at that key). keyContext is the nearest enclosing
     * PROPERTY name of the FIRST occurrence, used for the sensitive-key-name gate, kept from the
     * first sighting only, doesn't matter which if it repeats under several names, the check only
     * needs ANY of them to look sensitive. sdkKey is the first raw key this value was actually
     * stored under, needed for the known-SDK-signature match, which is a (key, value) pair check,
     * not value-alone. */
    private static final class ValueSighting {
        final List<String> paths = new ArrayList<>();
        String firstKeyContext;
        String sdkKey;
    }

    /** Same underlying secret repeated at multiple paths (very common: OIDC libraries mirroring
     * the same access token under two different fields of one JSON blob, e.g.
     * angular-auth-oidc-client's authnResult.access_token and authzData) used to produce one
     * finding PER occurrence, "the same finding 3 times" for one real secret. Mirrors the browser
     * extension's own content/engine.js mergeDuplicateFindings: collect every distinct VALUE and
     * everywhere it was seen FIRST, then build exactly one finding per distinct value with a
     * combined location, instead of building (and later trying to de-duplicate) one per sighting. */
    private static List<HeaderFinding> analyzeStorage(Map<String, String> dump, String api, CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (dump == null) return findings;

        LinkedHashMap<String, ValueSighting> sightings = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : dump.entrySet()) {
            String key = e.getKey();
            String value = e.getValue();
            if (value == null || value.isEmpty()) continue;
            recordSighting(sightings, value, key, key);

            String trimmed = value.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                try {
                    // Not a token itself, but plenty of OIDC/auth libraries (angular-auth-oidc-
                    // client, oidc-client-ts, MSAL, Auth0 SPA SDK) serialize their ENTIRE token
                    // response, access_token/id_token/refresh_token included, as one JSON blob
                    // under a single storage key whose own name and whose own raw value (it's
                    // JSON, not base64) both fail the checks below, hiding every field inside it.
                    // Mirrors the browser extension's own content/engine.js walkJsonForTokens.
                    walkJsonForValues(JsonUtil.parse(trimmed), key, key, sightings, 0);
                } catch (Exception ignored) {
                    // Not actually valid JSON, nothing to walk.
                }
            }
        }

        for (Map.Entry<String, ValueSighting> e : sightings.entrySet()) {
            String value = e.getKey();
            ValueSighting sighting = e.getValue();
            // label is title-friendly ("0-client-biportal.refresh_token", or just "found at 2
            // locations" when repeated), evidenceLoc is always the full api-qualified list, one
            // path or several, that's what actually goes in the evidence/description text.
            String label       = locationLabel(sighting.paths);
            String evidenceLoc = locationList(api, sighting.paths);

            if (JwtAnalyzer.looksLikeJwt(value)) {
                findings.add(jwtStorageFinding(api, label, evidenceLoc, value));
                // Real value, not a static-proximity guess: JwtAnalyzer's own CERTAIN findings
                // (alg:none, no-exp, ...) apply at full strength, no confidence cap needed.
                for (HeaderFinding jwtFinding : JwtAnalyzer.analyze(value, "(Browser: Web Storage)",
                        evidenceLoc + " (browser-confirmed value)", config)) {
                    findings.add(withStorageSeverityFloor(jwtFinding, api));
                }
                continue;
            }

            String sdkLabel = WebStorageAnalyzer.matchKnownSdkSignature(sighting.sdkKey + "=" + value);
            if (sdkLabel != null) {
                findings.add(new HeaderFinding(
                        "Known auth SDK session cache confirmed in " + api + ": " + sdkLabel,
                        "(Browser: " + api + ")", value,
                        "The browser extension read '" + evidenceLoc + "' directly from " + api + " on this page " +
                        "and its key format matches " + sdkLabel + "'s documented session-cache key. Unlike a " +
                        "static body-text guess, this is the real runtime value: " + sdkLabel + " really is " +
                        "caching session/token material here. Web Storage has no HttpOnly-equivalent " +
                        "protection, any XSS on this origin can read it directly.",
                        evidenceLoc + " matched known " + sdkLabel + " key format (browser-confirmed)",
                        // sessionStorage is scoped to this one tab/browsing context and dies with
                        // it, localStorage is shared across every tab of the origin and survives
                        // restarts, same exploitability (XSS reads it either way), narrower
                        // window, one severity tier down.
                        api.equals("sessionStorage") ? Severity.LOW : Severity.MEDIUM, Confidence.CERTAIN, Category.AUTH,
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"));
                continue;
            }
            // Deliberately no catch-all below this point for a value that isn't JSON either: a
            // blanket "Data stored in X: key" MEDIUM finding for every single key was tried and
            // reverted the same day, real-world use showed it floods both Quimera's own Headers
            // tab and (worse) Burp's native Issues tab with routine inventory noise for keys that
            // were never suspicious by any measure (A/B testing flags, feature toggles, ...). Only
            // the checks here (JWT shape, known auth-SDK signature, sensitive-key-name + opaque-
            // token shape, at any depth) are worth an analyst's attention as findings.
            // Identifiers are not authentication secrets, but a real user/account identifier
            // retained in browser storage is still privacy-relevant client-side state. Keep this
            // deliberately narrower than a generic "anything named *id" rule: userId/accountId
            // and a UUID-shaped value are strong independent signals, whereas componentId,
            // experimentId and arbitrary short numbers would create routine inventory noise.
            String identifierType = identifierType(sighting.firstKeyContext, value);
            if (identifierType != null) {
                findings.add(identifierFinding(api, label, evidenceLoc, value, identifierType));
                continue;
            }

            boolean sensitiveKey = sighting.firstKeyContext != null
                    && WebStorageAnalyzer.isSensitiveKeyName(sighting.firstKeyContext.toLowerCase(Locale.ROOT));
            if (sensitiveKey && WebStorageAnalyzer.looksLikeOpaqueToken(value)) {
                findings.add(opaqueTokenFinding(api, label, evidenceLoc, value));
            }
        }
        return findings;
    }

    /** Recursively walks a parsed JSON value, recording every string leaf's occurrence the same
     * way the flat top-level scan does. keyContext is the nearest enclosing PROPERTY name (not
     * array index), so an array of raw tokens under a sensitive key still gates correctly even
     * though a numeric index isn't itself a sensitive-looking name. depth is capped defensively,
     * JSON.parse-equivalent output can't have real cycles but a pathologically deep payload
     * shouldn't be allowed to make this expensive. */
    private static void walkJsonForValues(Object value, String path, String keyContext,
                                           Map<String, ValueSighting> sightings, int depth) {
        if (depth > 8 || value == null) return;
        if (value instanceof String s) {
            if (!s.isEmpty()) recordSighting(sightings, s, path, keyContext);
            return;
        }
        if (value instanceof List<?> list) {
            for (int i = 0; i < list.size(); i++) {
                walkJsonForValues(list.get(i), path + "[" + i + "]", keyContext, sightings, depth + 1);
            }
            return;
        }
        if (value instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String k = String.valueOf(entry.getKey());
                walkJsonForValues(entry.getValue(), path + "." + k, k, sightings, depth + 1);
            }
        }
    }

    private static void recordSighting(Map<String, ValueSighting> sightings, String value, String path, String keyContext) {
        ValueSighting sighting = sightings.computeIfAbsent(value, v -> new ValueSighting());
        sighting.paths.add(path);
        if (sighting.firstKeyContext == null) {
            sighting.firstKeyContext = keyContext;
            sighting.sdkKey = path;
        }
    }

    /** Title-friendly: the one path itself, or just "found at N locations" (never the full list,
     * that belongs in the evidence/description text via {@link #locationList}, not the title). */
    private static String locationLabel(List<String> paths) {
        return paths.size() == 1 ? paths.get(0) : "found at " + paths.size() + " locations";
    }

    /** Every path this value was seen at, api-qualified and comma-joined, for evidence/description
     * text: "sessionStorage.a.b" for one, "sessionStorage.a.b, sessionStorage.c.d" for several. */
    private static String locationList(String api, List<String> paths) {
        List<String> qualified = new ArrayList<>();
        for (String p : paths) qualified.add(api + "." + p);
        return String.join(", ", qualified);
    }

    /** label is the title-friendly location ({@link #locationLabel}), evidenceLoc is the full
     * api-qualified list ({@link #locationList}), both derived from the same set of paths this
     * one distinct value was seen at. */
    private static HeaderFinding opaqueTokenFinding(String api, String label, String evidenceLoc, String value) {
        return new HeaderFinding(
                "Session/auth token confirmed in " + api + ": " + label,
                "(Browser: " + api + ")", value,
                "The browser extension read the real value of " + evidenceLoc + " on this page: " +
                "a credential-shaped key holding an opaque, token-like value. Web Storage has no " +
                "HttpOnly-equivalent protection, any script on this page (including via XSS) can read " +
                "it directly, no separate bug needed beyond the XSS itself. " +
                (api.equals("localStorage") ? "localStorage also has no expiry and persists across " +
                "tabs and browser restarts." : ""),
                evidenceLoc + " = " + truncate(value) + " (browser-confirmed real value)",
                api.equals("sessionStorage") ? Severity.LOW : Severity.MEDIUM, Confidence.CERTAIN, Category.AUTH,
                "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html");
    }

    private static HeaderFinding jwtStorageFinding(String api, String label, String evidenceLoc, String value) {
        return new HeaderFinding(
                "JWT stored in " + api + ": " + label,
                "(Browser: " + api + ")", value,
                "The browser extension confirmed that " + evidenceLoc + " contains a JSON Web Token. " +
                "Web Storage has no HttpOnly-equivalent protection, so any script running on the origin, " +
                "including through XSS, can read and exfiltrate the token. " +
                (api.equals("localStorage")
                        ? "localStorage persists across tabs and browser restarts."
                        : "sessionStorage is limited to this browsing context, reducing persistence but not script access."),
                evidenceLoc + " = " + truncate(value) + " (browser-confirmed JWT value)",
                api.equals("sessionStorage") ? Severity.LOW : Severity.MEDIUM,
                Confidence.CERTAIN, Category.AUTH,
                "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html");
    }

    /** Every finding caused by browser storage inherits the storage exposure floor. Intrinsic
     * HIGH findings remain HIGH; weaker JWT inventory/claim findings are MEDIUM in persistent
     * localStorage and LOW in tab-scoped sessionStorage. */
    private static HeaderFinding withStorageSeverityFloor(HeaderFinding finding, String api) {
        Severity floor = api.equals("sessionStorage") ? Severity.LOW : Severity.MEDIUM;
        Severity severity = finding.severity.order < floor.order ? finding.severity : floor;
        if (severity == finding.severity) return finding;
        return new HeaderFinding(finding.issueName, finding.headerName, finding.headerValue,
                finding.description, finding.evidence, severity, finding.confidence,
                finding.category, finding.referenceUrl);
    }

    private static String identifierType(String key, String value) {
        if (key == null || value == null) return null;
        String k = key.trim();
        String v = value.trim();
        if (UUID.matcher(v).matches()) return USER_IDENTIFIER_KEY.matcher(k).matches()
                ? "user/account identifier" : "stable UUID identifier";
        if (EMAIL_KEY.matcher(k).matches() && EMAIL.matcher(v).matches()) return "email address";
        if (PHONE_KEY.matcher(k).matches() && PHONE.matcher(v).matches()) return "telephone number";
        if (PERSON_NAME_KEY.matcher(k).matches() && HUMAN_NAME.matcher(v).matches()) return "person name";
        if (USERNAME_KEY.matcher(k).matches() && USERNAME.matcher(v).matches()) return "username";
        return null;
    }

    private static HeaderFinding identifierFinding(String api, String label, String evidenceLoc,
                                                     String value, String identifierType) {
        return new HeaderFinding(
                "Identifying data exposed in " + api + ": " + label,
                "(Browser: " + api + ")", value,
                "The browser extension confirmed that " + evidenceLoc + " contains a " + identifierType + ". " +
                "This is not treated as an authentication secret, but scripts running on the origin " +
                "can read it and use it to identify or correlate the user. " +
                (api.equals("localStorage")
                        ? "localStorage persists across tabs and browser restarts, extending that exposure."
                        : "sessionStorage is limited to this browsing context, but remains readable by page scripts."),
                evidenceLoc + " = " + truncate(value) + " (browser-confirmed " + identifierType + ")",
                api.equals("sessionStorage") ? Severity.LOW : Severity.MEDIUM,
                Confidence.CERTAIN, Category.STORAGE,
                "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html");
    }

    private static String truncate(String value) {
        return value.length() > 500 ? value.substring(0, 500) + "… (" + value.length() + " chars total)" : value;
    }
}
