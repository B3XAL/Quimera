package com.b3xal.headeranalyzer.browser;

import com.b3xal.headeranalyzer.util.JsonUtil;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A parsed snapshot posted by the Quimera browser extension to {@link BrowserBridgeServer}'s
 * {@code /quimera/ingest} endpoint. Plain immutable data holder, no logic, same spirit as
 * {@link com.b3xal.headeranalyzer.config.CookiesAndAuthConfig}, built once per request via
 * {@link #fromJson(Map)} using the project's existing dependency-free {@link JsonUtil}.
 *
 * Mirrors exactly what {@code content/content.js} in the extension collects, see that file's
 * {@code collect()} function for the JS-side shape this is parsing.
 */
public final class BrowserPayload {

    private static final int MAX_COLLECTION_ENTRIES = 500;
    private static final int MAX_STRING_LENGTH = 65_536;

    public final String origin;
    public final String href;
    public final String host;
    public final String path;
    public final String documentTitle;

    /** key -> value, may contain nulls if the browser's Storage.getItem returned null. */
    public final Map<String, String> localStorage;
    public final Map<String, String> sessionStorage;
    public final List<BrowserCookie> browserCookies;

    // postMessageListeners, and insecureForms/secretsInDom below, removed (2026-08-24): the
    // extension itself stopped collecting them (content/content.js, content/inject-mainworld.js),
    // none of them are headers/cookies/auth findings, see BrowserDomAnalyzer's own comment for why
    // Quimera never turned them into findings even back when the extension still sent them.
    public final DomSignals dom;

    public BrowserPayload(String origin, String href, String host, String path, String documentTitle,
                           Map<String, String> localStorage, Map<String, String> sessionStorage,
                           List<BrowserCookie> browserCookies, DomSignals dom) {
        this.origin = origin;
        this.href = href;
        this.host = host;
        this.path = path;
        this.documentTitle = documentTitle;
        this.localStorage = localStorage;
        this.sessionStorage = sessionStorage;
        this.browserCookies = browserCookies;
        this.dom = dom;
    }

    public record WindowGlobal(String name, String value) {}
    public record BrowserCookie(String name, String value, String domain, String path,
                                boolean secure, boolean httpOnly, String sameSite) {}

    public record DomSignals(List<WindowGlobal> windowGlobals) {}

    @SuppressWarnings("unchecked")
    public static BrowserPayload fromJson(Map<String, Object> m) {
        Map<String, String> localStorage = stringMap(m.get("localStorage"));
        Map<String, String> sessionStorage = stringMap(m.get("sessionStorage"));
        List<BrowserCookie> browserCookies = new ArrayList<>();
        for (Map<String, Object> cm : JsonUtil.objectList(m.get("browserCookies")).stream()
                .limit(MAX_COLLECTION_ENTRIES).toList()) {
            browserCookies.add(new BrowserCookie(
                    JsonUtil.str(cm, "name", ""), JsonUtil.str(cm, "value", ""),
                    JsonUtil.str(cm, "domain", ""), JsonUtil.str(cm, "path", "/"),
                    bool(cm.get("secure")), bool(cm.get("httpOnly")),
                    JsonUtil.str(cm, "sameSite", "")));
        }

        DomSignals dom = parseDom(m.get("dom") instanceof Map<?, ?> dm ? (Map<String, Object>) dm : Map.of());

        return new BrowserPayload(
                JsonUtil.str(m, "origin", ""), JsonUtil.str(m, "href", ""),
                JsonUtil.str(m, "host", ""), JsonUtil.str(m, "path", ""),
                JsonUtil.str(m, "documentTitle", ""),
                localStorage, sessionStorage, browserCookies, dom);
    }

    private static DomSignals parseDom(Map<String, Object> dm) {
        List<WindowGlobal> globals = new ArrayList<>();
        for (Map<String, Object> gm : JsonUtil.objectList(dm.get("windowGlobals")).stream()
                .limit(MAX_COLLECTION_ENTRIES).toList()) {
            globals.add(new WindowGlobal(JsonUtil.str(gm, "name", ""), JsonUtil.str(gm, "value", "")));
        }

        return new DomSignals(globals);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> stringMap(Object v) {
        Map<String, String> out = new LinkedHashMap<>();
        if (v instanceof Map<?, ?> m) {
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (out.size() >= MAX_COLLECTION_ENTRIES) break;
                out.put(limit(String.valueOf(e.getKey())),
                        e.getValue() == null ? null : limit(String.valueOf(e.getValue())));
            }
        }
        return out;
    }

    private static boolean bool(Object value) {
        return value instanceof Boolean b && b;
    }

    private static String limit(String value) {
        return value.length() <= MAX_STRING_LENGTH ? value : value.substring(0, MAX_STRING_LENGTH);
    }
}
