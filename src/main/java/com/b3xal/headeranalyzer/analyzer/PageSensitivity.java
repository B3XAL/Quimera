package com.b3xal.headeranalyzer.analyzer;

import java.util.Locale;

/**
 * Cheap "is this a sensitive/critical page" heuristic, used by {@link HeaderAnalysisEngine} to
 * move a handful of findings' severity based on where they actually land. The same flat severity
 * for e.g. "Missing Clickjacking Protection" on a marketing page and on the login form doesn't
 * reflect real risk: clickjacking a marketing page achieves nothing, clickjacking a login form
 * (credential harvesting) or an account/payment action (UI redressing a state change) is a real
 * primitive. Grouped findings already show the WORST severity across every affected URL
 * ({@code LoggerPanel.IssueGroup#absorb}), so this doesn't lose coverage, it makes the headline
 * severity reflect the page that actually matters instead of diluting it flat across every page.
 *
 * Two independent, deliberately cheap signals, either one is enough:
 *   1. URL path keyword match (login/account/admin/checkout/...), catches the common case for free.
 *   2. A password `<input>` field in the response body, same {@code body.contains(...)} substring
 *      model {@link WebStorageAnalyzer} already uses, catches login/register/reset forms sitting
 *      behind a URL that doesn't hint at it (SPAs, "/app/12345"-style routes).
 *
 * This is a heuristic, not proof, both signals can miss (a sensitive page with neither a matching
 * URL nor a rendered password field, e.g. a JS-rendered SPA shell) or over-match (a support article
 * that happens to mention "password" in its URL). Every finding this feeds into keeps
 * Confidence.CERTAIN (the underlying fact, e.g. "header is absent", stays fully certain either way)
 * and states the matched signal in its evidence text, so the analyst can sanity-check the call
 * rather than trust it blindly.
 */
public final class PageSensitivity {

    private PageSensitivity() {}

    private static final String[] PATH_KEYWORDS = {
        "login", "signin", "sign-in", "log-in", "logon", "auth", "authenticate",
        "password", "passwd", "reset-password", "forgot-password",
        "register", "signup", "sign-up", "account", "profile", "settings",
        "admin", "dashboard", "checkout", "payment", "billing", "transfer",
        "wallet", "2fa", "mfa", "otp", "verify", "confirm", "sudo"
    };

    // Same safety cap as WebStorageAnalyzer: skip pathologically large bodies rather than doing
    // repeated contains() scans on them.
    private static final int MAX_BODY_LENGTH = 5_000_000;

    /**
     * Null when neither signal matches. Otherwise a short, human-readable explanation of which one
     * did, meant to be dropped straight into a finding's evidence text.
     */
    public static String sensitiveReason(String path, String body) {
        String keyword = matchedKeyword(path);
        if (keyword != null) return "URL path contains '" + keyword + "'";
        if (hasPasswordField(body)) return "response body contains a password input field";
        return null;
    }

    public static boolean isSensitive(String path, String body) {
        return sensitiveReason(path, body) != null;
    }

    private static String matchedKeyword(String path) {
        if (path == null || path.isEmpty()) return null;
        String lower = path.toLowerCase(Locale.ROOT);
        for (String kw : PATH_KEYWORDS) {
            if (lower.contains(kw)) return kw;
        }
        return null;
    }

    private static boolean hasPasswordField(String body) {
        if (body == null || body.isEmpty() || body.length() > MAX_BODY_LENGTH) return false;
        String lower = body.toLowerCase(Locale.ROOT);
        return lower.contains("type=\"password\"") || lower.contains("type='password'")
                || lower.contains("type=password");
    }
}
