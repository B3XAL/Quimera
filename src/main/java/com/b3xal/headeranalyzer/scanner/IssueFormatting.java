package com.b3xal.headeranalyzer.scanner;

import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.util.JwtDisplay;

/**
 * Shared native-{@code AuditIssue} formatting: detail HTML, remediation text, and the cookie-
 * issue-name simplification used to consolidate per-cookie findings into one Issues-tab entry.
 * Extracted out of {@link HeaderPassiveScanner} so a {@link HeaderFinding} is formatted
 * IDENTICALLY into Burp's Issues tab no matter which pipeline produced it, HTTP traffic via
 * {@code HeaderPassiveScanner} or a browser-extension snapshot via
 * {@code com.b3xal.headeranalyzer.browser.BrowserIssueReporter}. One finding, one format, one
 * remediation text, regardless of source.
 */
public final class IssueFormatting {

    public static final String EXTENSION_NAME = "Quimera";
    public static final String SOURCE_HTTP = "Passive HTTP analysis";
    public static final String SOURCE_COOKIES_AUTH = "Cookies & Auth traffic analysis";
    public static final String SOURCE_BROWSER = "Quimera browser extension bridge";

    private IssueFormatting() {}

    /**
     * Strip the per-cookie name suffix so all "Missing Secure flag" findings across different
     * cookies consolidate into one issue in the Scanner.
     * e.g. "Cookie 'sessionId': Missing Secure flag" -&gt; "Cookie: Missing Secure flag"
     */
    public static String simplifyIssue(String issueName) {
        if (issueName == null) return "Cookie issue";
        int colonIdx = issueName.indexOf(": ");
        if (colonIdx > 0 && issueName.startsWith("Cookie '")) {
            return "Cookie" + issueName.substring(colonIdx);
        }
        return issueName;
    }

    /** Compact, stable title for Burp's native Issue type column. Quimera's own UI keeps the
     * richer issueName; the native table needs a glanceable label, with the detail pane carrying
     * the full explanation and evidence. */
    public static String nativeTitle(HeaderFinding f) {
        String title = f.issueName == null ? "Quimera finding" : f.issueName.trim();
        title = title.replaceFirst("^Authentication secret embedded in client-visible response:\\s*",
                        "Exposed credential: ")
                .replace("Authentication token passed in URL query string", "Auth token in URL")
                .replace("OAuth client_secret passed in URL query string", "OAuth client secret in URL")
                .replace("Password passed in URL query string", "Password in URL")
                .replaceFirst("^API key observed in request header:\\s*(.+)$", "API key in $1")
                .replace("Content Security Policy", "CSP")
                .replace("Content-Security-Policy", "CSP")
                .replace("Strict-Transport-Security", "HSTS")
                .replace("client-visible response", "response")
                .replace(" observed in response body", " exposed")
                .replace(" observed in request body", " in request body")
                .replace("Authentication material", "Credentials")
                .replace("Potential ", "")
                .replaceAll("\\s+", " ").trim();
        return abbreviate(title, 72);
    }

    private static String abbreviate(String value, int max) {
        if (value.length() <= max) return value;
        // Preserve both ends: the tail often contains the distinguishing directive/header/token.
        // Keeping only the prefix could collapse two different long findings into one dedup key.
        int tailLength = Math.min(22, max / 3);
        int headLimit = max - tailLength - 2; // ellipsis plus following space
        int headEnd = value.lastIndexOf(' ', headLimit);
        if (headEnd < headLimit / 2) headEnd = headLimit;
        int tailStart = value.length() - tailLength;
        int nextSpace = value.indexOf(' ', tailStart);
        if (nextSpace >= 0 && nextSpace < value.length() - 4) tailStart = nextSpace + 1;
        return value.substring(0, headEnd).stripTrailing() + "… " + value.substring(tailStart).stripLeading();
    }

    public static String buildDetail(HeaderFinding f, String source) {
        // No <html><body> wrapper: Burp's AuditIssue detail is inserted into a document Burp
        // itself already owns (Dashboard, Issue Activity, generated reports), a nested <html><body>
        // here doesn't get parsed as markup in every one of those contexts, it shows up as literal
        // text instead. Inline tags (<b>/<br>/<code>) are still fine, only the outer wrapper isn't.
        StringBuilder sb = new StringBuilder();
        sb.append("<b>Extension:</b> ").append(EXTENSION_NAME).append("<br>");
        sb.append("<b>Source:</b> ").append(escHtml(source)).append("<br>");
        sb.append("<b>Severity:</b> ").append(f.severity.label).append("<br>");
        sb.append("<b>Confidence:</b> ").append(f.confidence.label).append("<br>");
        sb.append("<b>Header:</b> <code>").append(escHtml(f.headerName)).append("</code><br>");
        if (f.headerValue != null) {
            sb.append("<b>Value observed:</b> <code>").append(escHtml(f.headerValue)).append("</code><br>");
        } else {
            sb.append("<b>Header status:</b> absent<br>");
        }
        if (f.evidence != null && !f.evidence.isBlank()) {
            sb.append("<b>Evidence:</b>").append(codeBlock(f.evidence));
        }
        sb.append("<br>").append(escHtml(f.description));
        appendDecoded(sb, f.headerValue);
        if (f.referenceUrl != null && !f.referenceUrl.isBlank()) {
            sb.append("<br><br>Want to dig deeper? <a href=\"").append(escHtml(f.referenceUrl))
              .append("\">Read this</a>");
        }
        return sb.toString();
    }

    /** Same decoding Quimera's own Advisory pane shows (ui.DetailPanel), reused verbatim via
     * {@link JwtDisplay} so a JWT/JSON-carrying finding reads identically whether an analyst is
     * looking at it in Quimera's own tab or in Burp's native Issues tab, one format regardless of
     * which view happened to be open. No live theme to read here (unlike DetailPanel, which pulls
     * Burp's actual current colors), Burp's own Issue view isn't theme-aware to extensions, a
     * plain neutral light background reads fine either way. */
    private static void appendDecoded(StringBuilder sb, String headerValue) {
        if (headerValue == null || headerValue.isBlank()) return;
        JwtDisplay.Decoded decoded = JwtDisplay.decode(headerValue);
        if (decoded != null) {
            if (decoded.headerJson() == null && decoded.payloadJson() == null) return;
            sb.append("<br><br><b>Token</b>").append(codeBlock(headerValue));
            if (decoded.headerJson() != null) {
                sb.append("<br><b>Decoded token</b>").append(codeBlock(decoded.headerJson()));
            }
            if (decoded.payloadJson() != null) {
                sb.append("<br><b>Payload</b>").append(codeBlock(decoded.payloadJson()));
                if (!decoded.timestampLines().isEmpty()) {
                    sb.append("<br><b>Timestamps</b>").append(codeBlock(String.join("\n", decoded.timestampLines())));
                }
            }
            return;
        }
        String pretty = JwtDisplay.prettyJsonOrNull(headerValue);
        if (pretty != null) {
            sb.append("<br><br><b>Decoded value</b>").append(codeBlock(pretty));
        }
    }

    private static String codeBlock(String text) {
        return "<pre style=\"margin:4px 0;padding:6px;background:#f2f2f2;border:1px solid #ddd;" +
                "white-space:pre-wrap;word-break:break-word;font-family:monospace;font-size:11px;\">" +
                escHtml(text) + "</pre>";
    }

    public static String buildRemediation(HeaderFinding f) {
        return switch (f.category) {
            case INFORMATION_DISCLOSURE ->
                "Remove the '" + f.headerName + "' header from all server responses " +
                "to prevent leakage of technology stack information.";
            case SECURITY_MISSING ->
                "Add the '" + f.headerName + "' response header with a secure value. " +
                "Ensure it is present on all pages, including error pages.";
            case SECURITY_MISCONFIGURED ->
                "Review and correct the '" + f.headerName + "' header value. " +
                "Refer to the OWASP Secure Headers Project for recommended configurations.";
            case CSP ->
                "Review your Content-Security-Policy. " +
                "Use CSP Evaluator (csp-evaluator.withgoogle.com) to validate the policy.";
            case ADVISABLE ->
                "Consider adding the '" + f.headerName + "' header to improve security posture.";
            case COOKIE ->
                "Ensure all cookies set by the server include the Secure, HttpOnly, and SameSite=Strict " +
                "attributes unless cross-site delivery is explicitly required.";
            case CUSTOM ->
                "Review the '" + f.headerName + "' finding against your organisation's custom rule.";
            case ACTIVE ->
                "Re-test after remediation using Quimera's Active header scan to confirm the fix.";
            case AUTH ->
                "Review this token in the Cookies & Auth tab: use short-lived, properly-signed tokens, " +
                "transmit credentials/tokens only over HTTPS and in headers (never the URL), and confirm " +
                "server-side revocation exists for anything that doesn't expire quickly on its own.";
            case STORAGE ->
                "Move session/auth material out of Web Storage, IndexedDB, and CacheStorage into an " +
                "HttpOnly, Secure cookie instead, none of these client-side stores have an HttpOnly-" +
                "equivalent protection, so anything placed there is readable by any script on the page, " +
                "including via XSS.";
            case DOM ->
                "Fix the underlying rendered-DOM issue: add rel=\"noopener\" to target=_blank links, " +
                "validate event.origin in every postMessage listener before trusting event.data, scope " +
                "service workers as narrowly as possible, and serve forms/subresources exclusively over HTTPS.";
        };
    }

    public static String escHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
