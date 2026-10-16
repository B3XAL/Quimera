package com.b3xal.headeranalyzer.browser;

import com.b3xal.headeranalyzer.analyzer.JwtAnalyzer;
import com.b3xal.headeranalyzer.analyzer.WebStorageAnalyzer;
import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Window-global findings, none of these exist anywhere Quimera's proxy-based analysis can see: a
 * SPA populates window globals entirely in the browser, long after the HTTP response body
 * Quimera's HeaderAnalysisEngine parses was received.
 *
 * Scoped deliberately narrow: only credential/auth-shaped values (JWTs, opaque tokens on
 * sensitive-named globals). Insecure forms, generic DOM secrets and postMessage-without-origin
 * checks were tried here and removed, they have nothing to do with headers, auth or cookies, the
 * scope the user wants Quimera's browser-bridge avisos held to. The extension's own local engine
 * (content/engine.js) still detects and shows those standalone, in the extension's own popup,
 * this file only decides what Quimera-burp itself turns into an aviso.
 */
public final class BrowserDomAnalyzer {

    private BrowserDomAnalyzer() {}

    // Publishable-by-design key patterns, same exploitability-bar reasoning as
    // WebStorageAnalyzer/CookieAnalyzer: a match here should never read as a leaked secret.
    private static final Pattern GOOGLE_BROWSER_KEY = Pattern.compile("^AIza[0-9A-Za-z\\-_]{35}$");

    public static List<HeaderFinding> analyze(BrowserPayload payload, CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (payload.dom == null) return findings;

        findings.addAll(analyzeWindowGlobals(payload.dom.windowGlobals(), config));
        return findings;
    }

    // NOTE: target=_blank without rel=noopener was deliberately removed as a check. Every
    // current-generation browser (Chromium, Firefox, Safari) sets noopener implicitly for
    // target=_blank by default, so it fails Quimera's own exploitability bar (only report what's
    // exploitable against a real modern browser, not a spec-technically-true-but-blocked combo)
    // and was just flooding real targets with low-value noise on every rendered link.

    // NOTE: insecure forms ("Form submits over plain HTTP..."), generic DOM secrets ("Possible
    // secret in ...") and postMessage-without-origin-check were all tried here and removed: none
    // of them are headers, auth or cookie findings, the scope Quimera's browser-bridge avisos are
    // held to. Real-world use showed they read as unrelated noise mixed in with the header/auth
    // signal the bridge exists for. The extension itself later stopped collecting/sending that data
    // entirely (content/content.js, content/inject-mainworld.js, 2026-08-24), BrowserPayload no
    // longer even has a field for it. Do not re-add these as a blanket "DOM noise" category again.

    /** Check: sensitive-named window globals, JWT-shaped values get full JwtAnalyzer treatment. */
    private static List<HeaderFinding> analyzeWindowGlobals(List<BrowserPayload.WindowGlobal> globals,
                                                              CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (globals == null) return findings;
        for (var g : globals) {
            if (isPublicByDesign(g.value())) continue;
            if (JwtAnalyzer.looksLikeJwt(g.value())) {
                findings.addAll(JwtAnalyzer.analyze(g.value(), "(Browser: window global)",
                        "window." + g.name() + " (browser-confirmed value)", config));
                continue;
            }
            if (WebStorageAnalyzer.isSensitiveKeyName(g.name().toLowerCase(Locale.ROOT))
                    && WebStorageAnalyzer.looksLikeOpaqueToken(g.value())) {
                findings.add(new HeaderFinding(
                        "Sensitive-looking value on window global: " + g.name(),
                        "(Browser: window." + g.name() + ")", truncate(g.value()),
                        "A global JavaScript variable with a credential-like name holds an opaque, token-like " +
                        "value. Any script running on this page, including via XSS, can read it directly.",
                        "window." + g.name() + " = " + truncate(g.value()) + " (browser-confirmed real value)",
                        Severity.LOW, Confidence.FIRM, Category.AUTH));
            }
        }
        return findings;
    }

    private static boolean isPublicByDesign(String value) {
        return value != null && GOOGLE_BROWSER_KEY.matcher(value).matches();
    }

    private static String truncate(String value) {
        if (value == null) return "";
        return value.length() > 500 ? value.substring(0, 500) + "… (" + value.length() + " chars total)" : value;
    }
}
