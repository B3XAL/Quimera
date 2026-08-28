package com.b3xal.headeranalyzer.browser;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.b3xal.headeranalyzer.util.JsonUtil;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the synthetic {@link HttpRequestResponse} shown wherever Quimera needs SOME evidence to
 * display for a browser-bridge finding: the request/response viewer panes under the Headers/
 * Cookies &amp; Auth logger ({@code UrlAnalysisResult#originalRequest}/{@code originalResponse}),
 * and the native Issues tab ({@link BrowserIssueReporter}). A browser-bridge finding has no real
 * HTTP transaction behind it (Web Storage, cookies, DOM signals aren't HTTP responses), those
 * panes would otherwise just render empty, indistinguishable from "nothing was captured" rather
 * than "there's nothing to capture here by design". Rather than leaving that blank, or lying about
 * it being real traffic, this renders the actual collected payload as a JSON response body (real
 * {@code Content-Type: application/json}, so Burp's own message editor applies its normal JSON
 * syntax highlighting/folding for free), the request/response viewer becomes a real, useful way
 * to browse what was found on the page.
 *
 * Deliberately does NOT repeat the finding list here (used to, as a plain-text "why" summary):
 * that's now the Advisory pane's job (decoded JWT claims, real dates, evidence, "want to dig
 * deeper?"), duplicating it here was pure noise, "too much info to read" was the direct user
 * complaint that led to this rewrite (2026-08-25). This body is raw collected DATA only, exactly
 * what the extension saw, nothing analyzed or explained.
 */
final class BrowserEvidence {

    private BrowserEvidence() {}

    private static final int MAX_BODY_CHARS = 100_000; // keep the Swing editor snappy on a huge page

    static HttpRequestResponse build(BrowserPayload payload) {
        String url = payload.href != null && !payload.href.isBlank() ? payload.href : payload.origin;
        HttpRequest request = safeRequestFromUrl(url, payload.host, payload.path);

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("_note", "Quimera browser bridge: synthetic snapshot, not real HTTP traffic. Collected " +
                "directly from the live page by the Quimera browser extension (Web Storage, credential-" +
                "shaped window globals). Cookie flags are NOT collected here, see Quimera's normal Set-" +
                "Cookie-header analysis on this site's proxied traffic instead. See the Advisory tab for " +
                "the actual finding(s), decoded and explained.");
        root.put("url", url);
        root.put("localStorage", payload.localStorage);
        root.put("sessionStorage", payload.sessionStorage);
        if (payload.dom != null && payload.dom.windowGlobals() != null && !payload.dom.windowGlobals().isEmpty()) {
            Map<String, String> globals = new LinkedHashMap<>();
            for (var g : payload.dom.windowGlobals()) globals.put(g.name(), g.value());
            root.put("windowGlobals", globals);
        }

        String bodyText = JsonUtil.write(root);
        if (bodyText.length() > MAX_BODY_CHARS) {
            bodyText = bodyText.substring(0, MAX_BODY_CHARS) + "\n... (truncated, " + bodyText.length() + " chars total)";
        }

        String raw = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n\r\n" + bodyText;
        HttpResponse response = HttpResponse.httpResponse(raw);
        return HttpRequestResponse.httpRequestResponse(request, response);
    }

    /** {@code HttpRequest.httpRequestFromUrl} throws on anything it can't parse as an absolute
     * http(s) URL (extension pages, {@code file://}, a malformed {@code href} the page's own JS
     * left in a weird state, ...). That used to propagate straight out of {@link #build}, which
     * {@link BrowserBridgeServer#recordResult} caught and silently logged, leaving
     * originalRequest/originalResponse both null and the Request/Response panes blank with no
     * indication why. Falls back through a synthesized http(s) URL from host/path, then a fixed
     * placeholder, so a request is always produced. */
    private static HttpRequest safeRequestFromUrl(String url, String host, String path) {
        if (url != null && !url.isBlank()) {
            try {
                return HttpRequest.httpRequestFromUrl(url);
            } catch (Exception ignored) {
                // fall through to the host/path reconstruction below
            }
        }
        if (host != null && !host.isBlank()) {
            String rebuilt = "https://" + host + (path != null && !path.isBlank() ? path : "/");
            try {
                return HttpRequest.httpRequestFromUrl(rebuilt);
            } catch (Exception ignored) {
                // fall through to the placeholder below
            }
        }
        return HttpRequest.httpRequestFromUrl("https://browser-bridge.invalid/unresolved-url");
    }

}
