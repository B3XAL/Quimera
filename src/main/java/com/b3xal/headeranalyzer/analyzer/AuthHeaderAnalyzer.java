package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static com.b3xal.headeranalyzer.model.Confidence.*;
import static com.b3xal.headeranalyzer.model.Severity.*;

/**
 * Recognizes HTTP Basic Authentication and generic Bearer/API-key tokens (opaque, non-JWT), plus
 * tokens passed in the URL query string, "the other two thirds of auth recognition" alongside
 * cookies (CookieAnalyzer) and JWT (JwtAnalyzer). JWT-shaped values found in an Authorization
 * header, a cookie, or a query parameter are delegated to {@link JwtAnalyzer} for deeper claim
 * analysis rather than reported here as opaque.
 *
 * Same "recognition, not attack" scope as JwtAnalyzer: this only decodes/observes what's already
 * present in captured traffic, it never sends a modified or replayed request.
 */
public final class AuthHeaderAnalyzer {

    private AuthHeaderAnalyzer() {}

    private static final String[] API_KEY_HEADERS = {
        "X-Api-Key", "X-Auth-Token", "Api-Key", "X-Access-Token",
        "X-Algolia-API-Key", "X-Pendo-Integration-Key", "X-Cypress-Record-Key",
        "X-PW-AccessToken", "X-Api-Token", "X-TrackerToken", "Circle-Token",
        "Private-Token", "Job-Token", "X-Application-Key", "X-Auth-Key"
    };

    private static final Pattern QUERY_TOKEN_KEY = Pattern.compile(
        "(?i)^(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|id[_-]?token|" +
        "client[_-]?secret|session[_-]?id|sid|token|jwt|authorization)$");
    private static final Pattern QUERY_PASSWORD_KEY = Pattern.compile(
        "(?i)^(?:password|passwd|pwd|user[_-]?password|passphrase)$");

    /**
     * @param url             the request URL (scheme decides the HTTP-downgrade severity bump)
     * @param requestHeaders  REQUEST headers (not response), any casing, matched case-insensitively
     * @param config          from Settings (Cookies & Auth Rules), gates each individual check,
     *                        supplies the extra API-key-header/query-token-param lists, and is
     *                        passed straight through to any JwtAnalyzer delegation
     */
    public static List<HeaderFinding> analyze(String url, Map<String, String> requestHeaders,
                                               CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (requestHeaders == null) return findings;
        boolean plaintext = url != null && url.toLowerCase(Locale.ROOT).startsWith("http://");

        if (config.basicAuthEnabled || config.bearerEnabled) {
            String authorization = header(requestHeaders, "Authorization");
            if (authorization != null && !authorization.isBlank()) {
                findings.addAll(analyzeAuthorizationHeader(authorization, plaintext, config));
            }
        }

        String proxyAuthorization = header(requestHeaders, "Proxy-Authorization");
        if (proxyAuthorization != null && !proxyAuthorization.isBlank()) {
            findings.add(f(plaintext ? HIGH : INFORMATION, plaintext ? CERTAIN : FIRM,
                    "Proxy-Authorization", "Proxy authentication credentials observed",
                    "The request carries proxy credentials. This is an authentication inventory signal; on " +
                            "plaintext HTTP the credential is directly exposed on the network path.",
                    "Proxy-Authorization: " + proxyAuthorization, proxyAuthorization));
        }
        String dpop = header(requestHeaders, "DPoP");
        if (dpop != null && !dpop.isBlank()) {
            findings.add(f(INFORMATION, CERTAIN, "DPoP", "DPoP proof JWT observed",
                    "A DPoP proof accompanies this request, indicating sender-constrained OAuth token usage. " +
                            "Recorded as authentication inventory; the proof alone is not a vulnerability.",
                    "DPoP: " + dpop, dpop, "https://www.rfc-editor.org/rfc/rfc9449"));
            if (config.jwtEnabled && JwtAnalyzer.looksLikeJwt(dpop))
                findings.addAll(JwtAnalyzer.analyze(dpop, "DPoP", "DPoP proof", config));
        }

        if (config.apiKeyHeaderEnabled) {
            for (String h : allApiKeyHeaders(config)) {
                String value = header(requestHeaders, h);
                if (value != null && !value.isBlank() && !isObviousPlaceholder(h, value)) {
                    var provider = CredentialProviderCatalog.identify(h, url);
                    String technology = provider.map(CredentialProviderCatalog.Provider::technology)
                            .orElse(null);
                    String providerText = technology == null ? "" : " Technology hint: " + technology + ".";
                    String reference = provider.map(CredentialProviderCatalog.Provider::reference).orElse(null);
                    findings.add(f(plaintext ? HIGH : INFORMATION, plaintext ? CERTAIN : FIRM, h,
                        "API key observed in request header: " + h,
                        "The request carries an API key/token in the '" + h + "' header." +
                        (plaintext
                            ? " This request was sent over plaintext HTTP, so the key was transmitted in the " +
                              "clear and is directly interceptable by anyone on the network path."
                            : " Inventory finding, verify this key is scoped/rotatable and not a long-lived " +
                              "shared secret checked into a client-side build.") + providerText,
                        h + ": " + value + (technology == null ? "" : " | Technology hint: " + technology),
                        value, reference));
                }
            }
        }

        if (config.queryStringTokenEnabled) {
            findings.addAll(analyzeQueryString(url, config));
        }

        if (config.jwtEnabled || config.queryStringTokenEnabled) {
            String cookieHeader = header(requestHeaders, "Cookie");
            if (cookieHeader != null && !cookieHeader.isBlank()) {
                findings.addAll(analyzeCookieHeaderAuth(cookieHeader, config));
            }
        }

        return findings;
    }

    static List<String> allApiKeyHeaders(CookiesAndAuthConfig config) {
        List<String> all = new ArrayList<>(Arrays.asList(API_KEY_HEADERS));
        for (String h : config.extraApiKeyHeaders) if (!h.isBlank()) all.add(h.trim());
        return all;
    }

    /** The request's own Cookie header (name=value; name2=value2), not Set-Cookie, this confirms
     * the client is actually holding and re-sending a JWT-shaped cookie value, complementary to
     * whatever CookieAnalyzer already does with the flags on the Set-Cookie that issued it. */
    static List<HeaderFinding> analyzeCookieHeaderAuth(String cookieHeader, CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        for (String pair : cookieHeader.split(";")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) continue;
            String name  = pair.substring(0, eq).trim();
            String value = pair.substring(eq + 1).trim();
            if (config.jwtEnabled)
                findings.addAll(StructuredCookieJwtAnalyzer.analyze(name, value, "Cookie", config));
            if (config.queryStringTokenEnabled)
                findings.addAll(analyzeSensitiveUrlInCookie(name, value));
        }
        return findings;
    }

    private static final Pattern PASSWORD_FLOW_PATH = Pattern.compile(
            "(?i)(?:^|/)(?:confirm[-_]?password|reset[-_]?password|password[-_]?reset|" +
                    "forgot[-_]?password|recover[-_]?password|password[-_]?recovery|" +
                    "verify[-_]?password)(?:/|$)");
    private static final Pattern PASSWORD_FLOW_TOKEN_PARAM = Pattern.compile(
            "(?i)^(?:ticket|reset[-_]?token|confirmation[-_]?token|verification[-_]?token|" +
                    "recovery[-_]?token|code)$");

    /** Finds capability tokens carried inside a URL-valued cookie, e.g.
     * returnUrl=/confirm-password?...&ticket=opaque. Context is intentionally mandatory: generic
     * ticket/code parameters and identifiers such as ticketid/userid are not credentials. */
    static List<HeaderFinding> analyzeSensitiveUrlInCookie(String cookieName, String rawValue) {
        return analyzeSensitiveUrlInCookie(cookieName, rawValue, "Cookie");
    }

    static List<HeaderFinding> analyzeSensitiveUrlInCookie(String cookieName, String rawValue,
                                                            String sourceHeader) {
        String decoded = rawValue;
        for (int i = 0; i < 3; i++) {
            String next = urlDecode(decoded);
            if (next.equals(decoded)) break;
            decoded = next;
        }
        try {
            URI uri = URI.create(decoded);
            String path = uri.getPath();
            String query = uri.getRawQuery();
            if (path == null || query == null || !PASSWORD_FLOW_PATH.matcher(path).find()) return List.of();
            List<HeaderFinding> findings = new ArrayList<>();
            for (String item : query.split("&")) {
                int eq = item.indexOf('=');
                if (eq <= 0) continue;
                String parameter = urlDecode(item.substring(0, eq));
                String token = urlDecode(item.substring(eq + 1));
                if (!PASSWORD_FLOW_TOKEN_PARAM.matcher(parameter).matches()
                        || !looksLikePasswordFlowToken(token)) continue;
                findings.add(f(MEDIUM, FIRM, sourceHeader,
                        "Password recovery token embedded in Cookie: " + cookieName,
                        "The HTTP " + sourceHeader + " value for '" + cookieName +
                                "' contains a URL for a password confirmation " +
                                "or recovery flow with an opaque capability token in parameter '" + parameter + "'. " +
                                "If reusable, this token may authorize a security-sensitive account action. " +
                                "Verify expiry, single-use enforcement and binding to the intended account.",
                        sourceHeader + ": " + cookieName + " -> " + path +
                                " -> query parameter " + parameter + "=" + token,
                        token, "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html"));
            }
            return findings;
        } catch (IllegalArgumentException ignored) {
            return List.of();
        }
    }

    private static boolean looksLikePasswordFlowToken(String value) {
        if (value == null) return false;
        String trimmed = value.trim();
        if (trimmed.length() < 16 || trimmed.length() > 2048 || trimmed.matches(".*\\s+.*")) return false;
        String normalized = trimmed.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        return normalized.length() >= 16
                && !Set.of("placeholder", "changeme", "yourtoken", "resettoken", "confirmationtoken",
                        "verificationtoken", "example", "redacted", "masked").contains(normalized)
                && !normalized.matches("0{16,}") && !normalized.matches(".*(.)\\1{15,}.*");
    }

    private static List<HeaderFinding> analyzeAuthorizationHeader(String authorization, boolean plaintext,
                                                                    CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        String trimmed = authorization.trim();
        int space = trimmed.indexOf(' ');
        String scheme = space > 0 ? trimmed.substring(0, space) : "";
        String rest   = space > 0 ? trimmed.substring(space + 1).trim() : "";
        if (rest.isEmpty()) return findings;

        if (config.basicAuthEnabled && scheme.equalsIgnoreCase("Basic")) {
            // Basic is reversible encoding, but over HTTPS it is protected by TLS just like a
            // Bearer token or cookie. Presence alone is not a vulnerability; only report when
            // the credential actually crossed plaintext HTTP.
            if (!plaintext) return findings;
            String decodedUser = decodeBasicUsername(rest);
            findings.add(f(HIGH, CERTAIN, "Authorization",
                "HTTP Basic Authentication credentials sent over plaintext HTTP",
                "This request authenticates with HTTP Basic Authentication. Basic Auth base64-encodes " +
                "'username:password'; it is not encryption and is trivially reversible by anyone who sees " +
                "the header. This request used plaintext HTTP, so the credentials were directly interceptable " +
                "on the network path." +
                (decodedUser != null ? " Decoded username: '" + decodedUser + "'." : ""),
                "Authorization: Basic " + rest, rest));
            return findings;
        }

        if (config.bearerEnabled && scheme.equalsIgnoreCase("Bearer")) {
            if (config.jwtEnabled && JwtAnalyzer.looksLikeJwt(rest)) {
                findings.addAll(JwtAnalyzer.analyze(rest, "Authorization", "Authorization: Bearer", config));
            } else if (looksLikeJwe(rest)) {
                findings.add(f(INFORMATION, FIRM, "Authorization",
                        "JWE-shaped Bearer token observed",
                        "The Bearer value has the five-part compact JWE shape. Its encrypted claims cannot be " +
                                "inspected passively; recorded as authentication inventory.",
                        "Authorization: Bearer with five compact segments", rest));
            } else if (looksLikePaseto(rest)) {
                findings.add(f(INFORMATION, FIRM, "Authorization",
                        "PASETO-shaped Bearer token observed",
                        "The Bearer value uses a PASETO version/purpose prefix. Recorded as passive " +
                                "authentication inventory; Quimera does not perform cryptographic validation.",
                        "Authorization: Bearer with PASETO prefix", rest, "https://paseto.io/"));
            } else {
                findings.add(f(plaintext ? HIGH : INFORMATION, plaintext ? CERTAIN : FIRM, "Authorization",
                    "Bearer token observed",
                    "This request authenticates with an opaque (non-JWT) Bearer token." +
                    (plaintext
                        ? " This request was sent over plaintext HTTP, so the token was transmitted in the " +
                          "clear and is directly interceptable by anyone on the network path."
                        : " Inventory finding, no internal structure to analyze further (not a JWT)."),
                    "Authorization: Bearer " + rest, rest));
            }
            return findings;
        }
        if (scheme.equalsIgnoreCase("Digest") || scheme.equalsIgnoreCase("Negotiate")
                || scheme.equalsIgnoreCase("NTLM") || scheme.equalsIgnoreCase("Hawk")
                || scheme.equalsIgnoreCase("MAC") || scheme.equalsIgnoreCase("Token")
                || scheme.regionMatches(true, 0, "AWS4-HMAC-SHA256", 0, "AWS4-HMAC-SHA256".length())) {
            findings.add(f(plaintext ? HIGH : INFORMATION, plaintext ? CERTAIN : FIRM,
                    "Authorization", "Authentication scheme observed: " + scheme,
                    "The request uses the " + scheme + " Authorization scheme. Recorded as passive " +
                            "authentication inventory; presence alone is not a vulnerability." +
                            (plaintext ? " It was transmitted over plaintext HTTP." : ""),
                    "Authorization scheme: " + scheme, rest,
                    "https://github.com/CYS4srl/SensitiveDiscoverer"));
            return findings;
        }
        if (looksLikeJwe(rest)) {
            findings.add(f(INFORMATION, FIRM, "Authorization", "JWE-shaped authorization token observed",
                    "The authorization value has the five-part compact JWE shape. Its encrypted claims cannot " +
                            "be inspected passively; recorded as authentication inventory.",
                    "Authorization scheme: " + scheme + "; compact token has five segments", rest));
        } else if (looksLikePaseto(rest)) {
            findings.add(f(INFORMATION, FIRM, "Authorization", "PASETO-shaped authorization token observed",
                    "The authorization value uses a PASETO version/purpose prefix. Recorded as passive " +
                            "authentication inventory; Quimera does not attempt cryptographic validation.",
                    "Authorization scheme: " + scheme + "; PASETO prefix observed", rest,
                    "https://paseto.io/"));
        }
        return findings;
    }

    private static boolean looksLikeJwe(String value) {
        return value != null && value.split("\\.", -1).length == 5
                && value.matches("[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]*){4}");
    }

    private static boolean looksLikePaseto(String value) {
        return value != null && value.matches("(?i)^v[1-4]\\.(?:local|public)\\..+");
    }

    private static List<HeaderFinding> analyzeQueryString(String url, CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (url == null) return findings;
        String query;
        try {
            query = URI.create(url).getRawQuery();
        } catch (Exception ex) {
            return findings;
        }
        if (query == null || query.isEmpty()) return findings;

        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) continue;
            String key   = pair.substring(0, eq);
            String value = urlDecode(pair.substring(eq + 1));
            if (value.isEmpty()) continue;
            if (isObviousPlaceholder(key, value)) continue;

            // An AIza value is a provider-specific credential signature in its own right. Do not
            // require a conventional parameter name such as key/api_key: real front-end bundles
            // frequently place it under generic config/client/data parameters.
            boolean googleApiKey = value.matches("AIza[0-9A-Za-z_-]{35}");
            if (googleApiKey) {
                findings.add(f(MEDIUM, CERTAIN, "(URL query string)",
                        "Google API key exposed in URL query string",
                        "A structurally valid Google API key is present in URL parameter '" + key + "'. " +
                                "Quimera can validate it against bounded read-only Google endpoints. URLs " +
                                "are also retained in histories and logs and may leak through Referer.",
                        key + "=" + value + " | Provider: Google APIs", value,
                        "https://developers.google.com/maps/api-security-best-practices"));
            }

            if (QUERY_PASSWORD_KEY.matcher(key).matches()) {
                findings.add(f(HIGH, CERTAIN, "(URL query string)",
                        "Password passed in URL query string",
                        "The URL query parameter '" + key + "' carries a password/passphrase. URLs are " +
                                "routinely retained in browser history, server/proxy logs and monitoring " +
                                "systems, and can be exposed through Referer. Send credentials in a POST body " +
                                "over HTTPS instead of placing them in the URL.",
                        key + "=" + value, value,
                        "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"));
            }

            if (!googleApiKey && isTokenLikeQueryKey(key, url, config)) {
                boolean isClientSecret = key.equalsIgnoreCase("client_secret");
                var provider = CredentialProviderCatalog.identify(key, url);
                String technology = provider.map(CredentialProviderCatalog.Provider::technology)
                        .orElse("provider not identifiable from this parameter alone");
                String reference = provider.map(CredentialProviderCatalog.Provider::reference).orElse(null);
                findings.add(isClientSecret
                    ? f(HIGH, FIRM, "(URL query string)",
                        "OAuth client_secret passed in URL query string",
                        "The URL query parameter '" + key + "' appears to carry an OAuth client_secret, a " +
                        "confidential, APPLICATION-wide credential, not a per-user token. Query strings leak " +
                        "through browser history, server access logs, and the Referer header sent to " +
                        "third-party resources, exposing it lets an attacker impersonate this OAuth client " +
                        "entirely (mint tokens, register redirect URIs) rather than compromise a single user. " +
                        "client_secret must only ever be sent in the request body from a confidential " +
                        "(server-side) client, never in a URL.",
                        key + "=" + value, value, "https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1")
                    // TENTATIVE, not CERTAIN: the parameter NAME matching api_key/token/etc. is a
                    // heuristic, not proof this specific value is really a credential (could be a CSRF
                    // nonce, a pagination cursor named "token", ...), unlike the header-based findings
                    // above where the Authorization/X-Api-Key scheme itself is definitive.
                    : reference != null ? f(MEDIUM, TENTATIVE, "(URL query string)",
                        "Authentication token passed in URL query string",
                        "The URL query parameter '" + key + "' appears to carry an authentication token/API key. " +
                        "Query strings leak through browser history, server access logs, and the Referer header " +
                        "sent to third-party resources on the same page, regardless of HTTPS. Pass tokens in a " +
                        "header (Authorization) or the request body instead. Technology hint: " + technology + ".",
                        key + "=" + value + " | Technology hint: " + technology, value, reference)
                    : f(MEDIUM, TENTATIVE, "(URL query string)",
                        "Authentication token passed in URL query string",
                        "The URL query parameter '" + key + "' appears to carry an authentication token/API key. " +
                        "Query strings leak through browser history, server access logs, and the Referer header " +
                        "sent to third-party resources on the same page, regardless of HTTPS. Pass tokens in a " +
                        "header (Authorization) or the request body instead.",
                        key + "=" + value, value));
            }

            // JWT structural shape (3-part base64url decoding to alg/typ) is a much stronger
            // signal than the param name, check every value regardless of whether its key
            // matched the token-like-name heuristic above, a JWT under an unexpected param name
            // (?state=..., ?data=...) used to be silently skipped entirely.
            if (config.jwtEnabled && JwtAnalyzer.looksLikeJwt(value)) {
                findings.addAll(JwtAnalyzer.analyze(value, "(URL query string)",
                        "URL query parameter '" + key + "'", config));
            }
        }
        return findings;
    }

    private static boolean isTokenLikeQueryKey(String key, String url, CookiesAndAuthConfig config) {
        if (QUERY_TOKEN_KEY.matcher(key).matches()) return true;
        // Provider-specific names from the passive credential catalog (hapikey, branch_secret,
        // recordKey, conversationspasskey, wpe_apikey, Azure SAS sig, etc.). The URL supplies
        // provider context for otherwise-generic names such as just "key".
        if (CredentialProviderCatalog.isCredentialField(key, url)) return true;
        for (String extra : config.extraQueryTokenParams) {
            if (!extra.isBlank() && key.equalsIgnoreCase(extra.trim())) return true;
        }
        return false;
    }

    private static boolean isObviousPlaceholder(String key, String value) {
        String k = key.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        String v = value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        if (v.isEmpty() || v.equals(k)) return true;
        return List.of("authorizationcode", "accesstoken", "refreshtoken", "idtoken", "apikey",
                "clientsecret", "password", "passwd", "yourpassword", "yoursecret", "yourapikey",
                "yourtoken", "placeholder", "changeme", "example", "sample", "dummy", "test",
                "redacted", "masked", "xxxxxxxx")
                .contains(v)
                || v.matches("0{8,}") || v.matches(".*(.)\\1{7,}.*")
                || v.matches("(?:your|insert|enter|replace|example|sample|dummy|test).*(?:key|token|secret|password).*");
    }

    // ------ Helpers ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private static String header(Map<String, String> headers, String name) {
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey().equalsIgnoreCase(name)) return e.getValue();
        }
        return null;
    }

    private static String decodeBasicUsername(String base64) {
        try {
            String decoded = new String(Base64.getDecoder().decode(base64), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            return colon >= 0 ? decoded.substring(0, colon) : decoded;
        } catch (Exception ex) {
            return null;
        }
    }

    private static String urlDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            return s;
        }
    }

    private static HeaderFinding f(Severity sev, Confidence conf, String headerName,
                                    String issueName, String description, String evidence, String value) {
        return new HeaderFinding(issueName, headerName, value, description, evidence, sev, conf, Category.AUTH);
    }

    private static HeaderFinding f(Severity sev, Confidence conf, String headerName,
                                    String issueName, String description, String evidence, String value,
                                    String referenceUrl) {
        return new HeaderFinding(issueName, headerName, value, description, evidence, sev, conf, Category.AUTH, referenceUrl);
    }
}
