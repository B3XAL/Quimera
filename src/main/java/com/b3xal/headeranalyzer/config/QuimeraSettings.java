package com.b3xal.headeranalyzer.config;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.persistence.PersistedObject;

import java.util.*;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * All runtime-configurable settings for Quimera.
 * Thread-safe: the HTTP handler, scanner and UI all read/write this from different threads.
 * Persisted to the extension's project data so settings survive a Burp restart.
 */
public class QuimeraSettings {

    // ------ Defaults ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public static final List<String> DEFAULT_SKIP_EXTENSIONS = List.of(
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".avif",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp4", ".mp3", ".wav", ".ogg", ".webm",
        ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z",
        ".map", ".DS_Store"
    );

    public static final List<String> DEFAULT_SKIP_CONTENT_TYPES = List.of(
        "image/", "audio/", "video/", "font/",
        "application/octet-stream", "application/zip",
        "application/pdf", "application/x-font"
    );

    /**
     * Burp tools Quimera listens to passively on a fresh installation. Intruder and Extensions
     * are deliberately opt-in to avoid generated traffic and other extensions' control requests.
     */
    public static final Set<String> DEFAULT_ENABLED_TOOLS = Set.of(
            ToolType.PROXY.name(), ToolType.REPEATER.name(), ToolType.SCANNER.name(),
            ToolType.TARGET.name(), ToolType.BURP_AI.name()
    );

    /**
     * Conservative sources for request-derived Cookies & Auth analysis. Scanner, Intruder and
     * Extensions frequently generate synthetic tokens/URLs; Proxy, Repeater and Target/content
     * discovery are the useful high-signal sources. Response-derived Set-Cookie checks are not
     * restricted by this list.
     */
    public static final Set<String> DEFAULT_COOKIES_AUTH_TOOLS = Set.of(
            ToolType.PROXY.name(), ToolType.REPEATER.name(), ToolType.TARGET.name()
    );

    /**
     * User-editable "boring headers" list, same idea as header-guardian's: header NAMES the user
     * knows are their own (custom internal headers, an in-house gateway's tracing header, etc.)
     * and never wants reported, no matter what rule would otherwise fire on them. Empty by
     * default, this is per-user noise the built-in CDN allow-list (KnownInfrastructure) can't know
     * about ahead of time.
     */
    public static final List<String> DEFAULT_SUPPRESSED_HEADERS = List.of();

    /** "Extra" lists for Cookies & Auth Rules (Settings dialog): each ADDS to the matching
     * analyzer's own built-in list (tracking-cookie prefixes, session-cookie name keywords,
     * API-key header names, token-shaped query-string param names), never replaces it. Empty by
     * default, this is per-target customization the built-ins can't know about ahead of time. */
    public static final List<String> DEFAULT_EXTRA_LIST = List.of();

    // ------ State ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private volatile List<String> skipExtensions   = new ArrayList<>(DEFAULT_SKIP_EXTENSIONS);
    private volatile List<String> skipContentTypes = new ArrayList<>(DEFAULT_SKIP_CONTENT_TYPES);
    private volatile List<String> suppressedHeaders = new ArrayList<>(DEFAULT_SUPPRESSED_HEADERS);
    private volatile List<String> extraTrackingCookiePrefixes = new ArrayList<>(DEFAULT_EXTRA_LIST);
    private volatile List<String> extraSessionCookieKeywords  = new ArrayList<>(DEFAULT_EXTRA_LIST);
    private volatile List<String> extraApiKeyHeaders          = new ArrayList<>(DEFAULT_EXTRA_LIST);
    private volatile List<String> extraQueryTokenParams       = new ArrayList<>(DEFAULT_EXTRA_LIST);

    /** Burp tools whose traffic feeds passive analysis (by ToolType#name()). Configurable in Settings. */
    private volatile Set<String> enabledTools = new LinkedHashSet<>(DEFAULT_ENABLED_TOOLS);
    private volatile Set<String> cookiesAuthTools = new LinkedHashSet<>(DEFAULT_COOKIES_AUTH_TOOLS);

    /** Legacy persisted name: when true, the Quimera UI only displays in-scope results. */
    private volatile boolean restrictToScope = false;

    /** When true, "Analyze with Quimera" from the context menu refuses out-of-scope URLs. */
    private volatile boolean contextMenuRequireScope = false;

    // Active header scan probes (context menu "Active header scan" / bulk active scan)
    private volatile boolean activeScanOptionsProbe = true;  // OPTIONS + Origin reflection test
    private volatile boolean activeScanTraceProbe    = true;  // TRACE / XST test
    private volatile boolean activeScanHstsProbe     = true;  // HTTP→HTTPS downgrade test
    private volatile boolean activeScanWebDavProbe   = true;  // OPTIONS DAV/MS-Author-Via test

    /** When true, QuimeraHttpHandler fires the same active probes (CORS Origin battery, TRACE,
     * HSTS downgrade) automatically for every new URL it sees passively on intercepted proxy
     * traffic, not just when the user explicitly runs "Active header scan". Enabled by default;
     * each individual probe remains independently removable by the user. */
    private volatile boolean autoActiveScan = true;
    /** Optional third-party validation of exposed AIza keys. Enabled by default as part of the
     * active-probe set; the read-only Google calls may consume project quota. */
    private volatile boolean googleApiKeyProbeEnabled = true;

    /** Threshold (minutes) a session cookie or JWT's lifetime is compared against, in the Cookies
     * & Auth tab (CookieAnalyzer's Max-Age/Expires check, JwtAnalyzer's exp-iat check). Default one
     * hour, configurable since "too long" genuinely depends on the application. */
    public static final int DEFAULT_MAX_TOKEN_LIFETIME_MINUTES = 60;
    private volatile int maxTokenLifetimeMinutes = DEFAULT_MAX_TOKEN_LIFETIME_MINUTES;

    // Cookies & Auth Rules (Settings dialog): per-check on/off, all default true so nothing
    // currently reported goes silently quiet after this setting is introduced.
    private volatile boolean cookieFlagChecksEnabled   = true; // Secure/HttpOnly/SameSite/prefix violations
    private volatile boolean cookieLifetimeCheckEnabled = true; // long-lived session cookie
    private volatile boolean cookieTrackingSkipEnabled  = true; // skip known analytics/tracking cookies
    private volatile boolean jwtEnabled                = true; // master switch, JwtAnalyzer no-ops when off
    private volatile boolean jwtAlgNoneCheckEnabled     = true;
    private volatile boolean jwtNoExpiryCheckEnabled    = true;
    private volatile boolean jwtLifetimeCheckEnabled    = true;
    // Active JWT bypass testing (JwtActiveProbe): forges alg:none / bad-signature tokens and
    // replays the original request. Enabled by default as part of Auto Active Scan; the user can
    // opt it out independently without disabling the rest of the active scan.
    private volatile boolean jwtActiveProbeEnabled      = true;
    // Active session-invalidation testing (SessionInvalidationProbe): the moment a logout is
    // detected (an explicit cookie-deletion Set-Cookie, or a request to a logout-shaped URL
    // carrying a Bearer token), replays one request per recently-visited path with the OLD
    // credential to check whether the server still accepts it. Enabled by default as part of Auto
    // Active Scan and independently removable by the user.
    private volatile boolean sessionInvalidationProbeEnabled = true;
    private volatile boolean basicAuthEnabled           = true; // Authorization: Basic recognition
    private volatile boolean bearerEnabled              = true; // Authorization: Bearer recognition (opaque + JWT)
    private volatile boolean apiKeyHeaderEnabled        = true; // X-Api-Key-style header recognition
    private volatile boolean queryStringTokenEnabled    = true; // token/api_key in the URL query string
    private volatile boolean webStorageCheckEnabled     = true; // WebStorageAnalyzer: JWT/cookie/opaque-token in localStorage/sessionStorage

    // Browser Bridge: disabled and authenticated by default. Loopback alone is not an
    // authentication boundary: any local process and, depending on Private Network Access
    // policy, hostile web content can attempt to reach it.
    public static final int DEFAULT_BROWSER_BRIDGE_PORT = 8199;
    private volatile boolean browserBridgeEnabled      = false;
    private volatile int     browserBridgePort          = DEFAULT_BROWSER_BRIDGE_PORT;
    private volatile boolean browserBridgeTokenEnabled = true;
    private volatile String  browserBridgeToken         = "";

    private final PersistedObject persistence; // may be null

    public QuimeraSettings() { this(null); }

    public QuimeraSettings(PersistedObject persistence) {
        this.persistence = persistence;
        load();
        ensureBrowserBridgeToken();
    }

    // ------ Read ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public synchronized List<String> getSkipExtensions()    { return Collections.unmodifiableList(skipExtensions); }
    public synchronized List<String> getSkipContentTypes()  { return Collections.unmodifiableList(skipContentTypes); }
    public synchronized List<String> getSuppressedHeaders() { return Collections.unmodifiableList(suppressedHeaders); }
    public synchronized List<String> getExtraTrackingCookiePrefixes() { return Collections.unmodifiableList(extraTrackingCookiePrefixes); }
    public synchronized List<String> getExtraSessionCookieKeywords()  { return Collections.unmodifiableList(extraSessionCookieKeywords); }
    public synchronized List<String> getExtraApiKeyHeaders()          { return Collections.unmodifiableList(extraApiKeyHeaders); }
    public synchronized List<String> getExtraQueryTokenParams()       { return Collections.unmodifiableList(extraQueryTokenParams); }
    public synchronized Set<String>  getEnabledTools()      { return Collections.unmodifiableSet(enabledTools); }
    public boolean isToolEnabled(ToolType t)   { return enabledTools.contains(t.name()); }
    public synchronized Set<String> getCookiesAuthTools() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(cookiesAuthTools));
    }
    public boolean isCookiesAuthToolEnabled(ToolType t) {
        return t != null && cookiesAuthTools.contains(t.name());
    }
    /** Case-insensitive: true if the user has put this header name on the suppression list. */
    public synchronized boolean isHeaderSuppressed(String headerName) {
        if (headerName == null) return false;
        for (String h : suppressedHeaders) if (h.equalsIgnoreCase(headerName)) return true;
        return false;
    }
    public boolean isRestrictToScope()         { return restrictToScope; }
    public boolean isContextMenuRequireScope() { return contextMenuRequireScope; }
    public boolean isActiveScanOptionsProbe()  { return activeScanOptionsProbe; }
    public boolean isActiveScanTraceProbe()    { return activeScanTraceProbe; }
    public boolean isActiveScanHstsProbe()     { return activeScanHstsProbe; }
    public boolean isActiveScanWebDavProbe()   { return activeScanWebDavProbe; }
    public boolean isAutoActiveScan()          { return autoActiveScan; }
    public boolean isGoogleApiKeyProbeEnabled(){ return googleApiKeyProbeEnabled; }
    public int getMaxTokenLifetimeMinutes()    { return maxTokenLifetimeMinutes; }
    public boolean isCookieFlagChecksEnabled()    { return cookieFlagChecksEnabled; }
    public boolean isCookieLifetimeCheckEnabled() { return cookieLifetimeCheckEnabled; }
    public boolean isCookieTrackingSkipEnabled()  { return cookieTrackingSkipEnabled; }
    public boolean isJwtEnabled()                 { return jwtEnabled; }
    public boolean isJwtAlgNoneCheckEnabled()     { return jwtAlgNoneCheckEnabled; }
    public boolean isJwtNoExpiryCheckEnabled()    { return jwtNoExpiryCheckEnabled; }
    public boolean isJwtLifetimeCheckEnabled()    { return jwtLifetimeCheckEnabled; }
    public boolean isJwtActiveProbeEnabled()      { return jwtActiveProbeEnabled; }
    public boolean isSessionInvalidationProbeEnabled() { return sessionInvalidationProbeEnabled; }
    public boolean isBasicAuthEnabled()           { return basicAuthEnabled; }
    public boolean isBearerEnabled()              { return bearerEnabled; }
    public boolean isApiKeyHeaderEnabled()        { return apiKeyHeaderEnabled; }
    public boolean isQueryStringTokenEnabled()    { return queryStringTokenEnabled; }
    public boolean isWebStorageCheckEnabled()     { return webStorageCheckEnabled; }
    public boolean isBrowserBridgeEnabled()       { return browserBridgeEnabled; }
    public int     getBrowserBridgePort()         { return browserBridgePort; }
    public boolean isBrowserBridgeTokenEnabled()  { return browserBridgeTokenEnabled; }
    public String  getBrowserBridgeToken()        { return browserBridgeToken; }

    /** Builds a fresh, immutable snapshot of every Cookies & Auth Rules setting, for
     * CookieAnalyzer/JwtAnalyzer/AuthHeaderAnalyzer to consume in one parameter instead of a pile
     * of getters threaded through separately. */
    public synchronized CookiesAndAuthConfig cookiesAndAuthConfig() {
        return new CookiesAndAuthConfig(
                maxTokenLifetimeMinutes,
                cookieFlagChecksEnabled, cookieLifetimeCheckEnabled, cookieTrackingSkipEnabled,
                List.copyOf(extraTrackingCookiePrefixes), List.copyOf(extraSessionCookieKeywords),
                jwtEnabled, jwtAlgNoneCheckEnabled, jwtNoExpiryCheckEnabled, jwtLifetimeCheckEnabled,
                basicAuthEnabled, bearerEnabled, apiKeyHeaderEnabled, queryStringTokenEnabled,
                List.copyOf(extraApiKeyHeaders), List.copyOf(extraQueryTokenParams), webStorageCheckEnabled);
    }

    // ------ Write ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public synchronized void setSkipExtensions(List<String> exts)     { skipExtensions   = new ArrayList<>(exts); persist(); }
    public synchronized void setSkipContentTypes(List<String> types)  { skipContentTypes = new ArrayList<>(types); persist(); }
    public synchronized void setSuppressedHeaders(List<String> headers) { suppressedHeaders = new ArrayList<>(headers); persist(); }
    public synchronized void setExtraTrackingCookiePrefixes(List<String> v) { extraTrackingCookiePrefixes = new ArrayList<>(v); persist(); }
    public synchronized void setExtraSessionCookieKeywords(List<String> v)  { extraSessionCookieKeywords = new ArrayList<>(v); persist(); }
    public synchronized void setExtraApiKeyHeaders(List<String> v)          { extraApiKeyHeaders = new ArrayList<>(v); persist(); }
    public synchronized void setExtraQueryTokenParams(List<String> v)       { extraQueryTokenParams = new ArrayList<>(v); persist(); }
    public synchronized void setEnabledTools(Set<String> names)       { enabledTools = new LinkedHashSet<>(names); persist(); }
    public synchronized void setCookiesAuthTools(Set<String> names) {
        cookiesAuthTools = new LinkedHashSet<>(names);
        persist();
    }
    public void setRestrictToScope(boolean v)         { restrictToScope = v; persist(); }
    public void setContextMenuRequireScope(boolean v) { contextMenuRequireScope = v; persist(); }
    public void setActiveScanOptionsProbe(boolean v)  { activeScanOptionsProbe = v; persist(); }
    public void setActiveScanTraceProbe(boolean v)    { activeScanTraceProbe = v; persist(); }
    public void setActiveScanHstsProbe(boolean v)     { activeScanHstsProbe = v; persist(); }
    public void setActiveScanWebDavProbe(boolean v)   { activeScanWebDavProbe = v; persist(); }
    /**
     * Enables/disables unattended active scanning. On every explicit transition to ON, the JWT,
     * session-invalidation and exposed-Google-API-key probes are selected as the recommended Auto
     * Active Scan defaults. They remain independent switches afterwards, so the user can
     * immediately opt any one out without Auto Active Scan continually forcing it back on.
     */
    public synchronized void setAutoActiveScan(boolean v) {
        autoActiveScan = v;
        if (v) {
            jwtActiveProbeEnabled = true;
            sessionInvalidationProbeEnabled = true;
            googleApiKeyProbeEnabled = true;
        }
        persist();
    }
    public void setGoogleApiKeyProbeEnabled(boolean v) { googleApiKeyProbeEnabled = v; persist(); }
    /** Silently floors to 1 (a zero/negative threshold would flag every token, not a useful "off"). */
    public synchronized void setMaxTokenLifetimeMinutes(int minutes) {
        maxTokenLifetimeMinutes = Math.max(1, minutes);
        persist();
    }
    public void setCookieFlagChecksEnabled(boolean v)    { cookieFlagChecksEnabled = v; persist(); }
    public void setCookieLifetimeCheckEnabled(boolean v) { cookieLifetimeCheckEnabled = v; persist(); }
    public void setCookieTrackingSkipEnabled(boolean v)  { cookieTrackingSkipEnabled = v; persist(); }
    public void setJwtEnabled(boolean v)                 { jwtEnabled = v; persist(); }
    public void setJwtAlgNoneCheckEnabled(boolean v)     { jwtAlgNoneCheckEnabled = v; persist(); }
    public void setJwtNoExpiryCheckEnabled(boolean v)    { jwtNoExpiryCheckEnabled = v; persist(); }
    public void setJwtLifetimeCheckEnabled(boolean v)    { jwtLifetimeCheckEnabled = v; persist(); }
    public void setJwtActiveProbeEnabled(boolean v)      { jwtActiveProbeEnabled = v; persist(); }
    public void setSessionInvalidationProbeEnabled(boolean v) { sessionInvalidationProbeEnabled = v; persist(); }
    public void setBasicAuthEnabled(boolean v)           { basicAuthEnabled = v; persist(); }
    public void setBearerEnabled(boolean v)              { bearerEnabled = v; persist(); }
    public void setApiKeyHeaderEnabled(boolean v)        { apiKeyHeaderEnabled = v; persist(); }
    public void setQueryStringTokenEnabled(boolean v)    { queryStringTokenEnabled = v; persist(); }
    public void setWebStorageCheckEnabled(boolean v)     { webStorageCheckEnabled = v; persist(); }
    public void setBrowserBridgeEnabled(boolean v)       { browserBridgeEnabled = v; persist(); }
    /** Silently floors/ceils to a valid TCP port range rather than accepting garbage. */
    public synchronized void setBrowserBridgePort(int port) {
        browserBridgePort = Math.max(1, Math.min(65535, port));
        persist();
    }
    public void setBrowserBridgeTokenEnabled(boolean v)  { browserBridgeTokenEnabled = v; persist(); }
    public void setBrowserBridgeToken(String v)          { browserBridgeToken = v == null ? "" : v; persist(); }

    // ------ Filter ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * Returns false if this response should be skipped based on content-type or URL extension.
     */
    public synchronized boolean shouldAnalyze(String contentType, String url) {
        if (contentType != null && !contentType.isBlank()) {
            String ct = contentType.toLowerCase();
            for (String skip : skipContentTypes) {
                if (ct.startsWith(skip.toLowerCase()) || ct.contains(skip.toLowerCase())) return false;
            }
        }
        String path = url.toLowerCase().split("\\?")[0].split("#")[0];
        for (String ext : skipExtensions) {
            if (path.endsWith(ext.toLowerCase())) return false;
        }
        return true;
    }

    /** Restore defaults. */
    public synchronized void reset() {
        skipExtensions   = new ArrayList<>(DEFAULT_SKIP_EXTENSIONS);
        skipContentTypes = new ArrayList<>(DEFAULT_SKIP_CONTENT_TYPES);
        suppressedHeaders = new ArrayList<>(DEFAULT_SUPPRESSED_HEADERS);
        extraTrackingCookiePrefixes = new ArrayList<>(DEFAULT_EXTRA_LIST);
        extraSessionCookieKeywords  = new ArrayList<>(DEFAULT_EXTRA_LIST);
        extraApiKeyHeaders          = new ArrayList<>(DEFAULT_EXTRA_LIST);
        extraQueryTokenParams       = new ArrayList<>(DEFAULT_EXTRA_LIST);
        enabledTools      = new LinkedHashSet<>(DEFAULT_ENABLED_TOOLS);
        cookiesAuthTools  = new LinkedHashSet<>(DEFAULT_COOKIES_AUTH_TOOLS);
        restrictToScope = false;
        contextMenuRequireScope = false;
        activeScanOptionsProbe = true;
        activeScanTraceProbe = true;
        activeScanHstsProbe = true;
        activeScanWebDavProbe = true;
        autoActiveScan = true;
        googleApiKeyProbeEnabled = true;
        maxTokenLifetimeMinutes = DEFAULT_MAX_TOKEN_LIFETIME_MINUTES;
        cookieFlagChecksEnabled = true;
        cookieLifetimeCheckEnabled = true;
        cookieTrackingSkipEnabled = true;
        jwtEnabled = true;
        jwtAlgNoneCheckEnabled = true;
        jwtNoExpiryCheckEnabled = true;
        jwtLifetimeCheckEnabled = true;
        jwtActiveProbeEnabled = true;
        sessionInvalidationProbeEnabled = true;
        basicAuthEnabled = true;
        bearerEnabled = true;
        apiKeyHeaderEnabled = true;
        queryStringTokenEnabled = true;
        webStorageCheckEnabled = true;
        browserBridgeEnabled = false;
        browserBridgePort = DEFAULT_BROWSER_BRIDGE_PORT;
        browserBridgeTokenEnabled = true;
        browserBridgeToken = generateBrowserBridgeToken();
        persist();
    }

    // ------ Persistence ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private void load() {
        if (persistence == null) return;
        try {
            var exts = persistence.getStringList("skipExtensions");
            if (exts != null && !exts.isEmpty()) skipExtensions = toStringList(exts);
            var types = persistence.getStringList("skipContentTypes");
            if (types != null && !types.isEmpty()) skipContentTypes = toStringList(types);
            var suppressed = persistence.getStringList("suppressedHeaders");
            if (suppressed != null && !suppressed.isEmpty()) suppressedHeaders = toStringList(suppressed);
            var extraTracking = persistence.getStringList("extraTrackingCookiePrefixes");
            if (extraTracking != null && !extraTracking.isEmpty()) extraTrackingCookiePrefixes = toStringList(extraTracking);
            var extraSession = persistence.getStringList("extraSessionCookieKeywords");
            if (extraSession != null && !extraSession.isEmpty()) extraSessionCookieKeywords = toStringList(extraSession);
            var extraApiKeys = persistence.getStringList("extraApiKeyHeaders");
            if (extraApiKeys != null && !extraApiKeys.isEmpty()) extraApiKeyHeaders = toStringList(extraApiKeys);
            var extraQueryTokens = persistence.getStringList("extraQueryTokenParams");
            if (extraQueryTokens != null && !extraQueryTokens.isEmpty()) extraQueryTokenParams = toStringList(extraQueryTokens);
            var tools = persistence.getStringList("enabledTools");
            if (tools != null && !tools.isEmpty()) enabledTools = new LinkedHashSet<>(toStringList(tools));
            Boolean authToolsConfigured = persistence.getBoolean("cookiesAuthToolsConfigured");
            if (Boolean.TRUE.equals(authToolsConfigured)) {
                var authTools = persistence.getStringList("cookiesAuthTools");
                cookiesAuthTools = authTools == null
                        ? new LinkedHashSet<>()
                        : new LinkedHashSet<>(toStringList(authTools));
            }

            Boolean rts = persistence.getBoolean("restrictToScope");
            if (rts != null) restrictToScope = rts;
            Boolean cmrs = persistence.getBoolean("contextMenuRequireScope");
            if (cmrs != null) contextMenuRequireScope = cmrs;
            Boolean opt = persistence.getBoolean("activeScanOptionsProbe");
            if (opt != null) activeScanOptionsProbe = opt;
            Boolean trc = persistence.getBoolean("activeScanTraceProbe");
            if (trc != null) activeScanTraceProbe = trc;
            Boolean hsts = persistence.getBoolean("activeScanHstsProbe");
            if (hsts != null) activeScanHstsProbe = hsts;
            Boolean webdav = persistence.getBoolean("activeScanWebDavProbe");
            if (webdav != null) activeScanWebDavProbe = webdav;
            Boolean aas = persistence.getBoolean("autoActiveScan");
            if (aas != null) autoActiveScan = aas;
            Boolean gap = persistence.getBoolean("googleApiKeyProbeEnabled");
            if (gap != null) googleApiKeyProbeEnabled = gap;
            Integer maxLifetime = persistence.getInteger("maxTokenLifetimeMinutes");
            if (maxLifetime != null) maxTokenLifetimeMinutes = maxLifetime;

            Boolean cfc = persistence.getBoolean("cookieFlagChecksEnabled");
            if (cfc != null) cookieFlagChecksEnabled = cfc;
            Boolean clc = persistence.getBoolean("cookieLifetimeCheckEnabled");
            if (clc != null) cookieLifetimeCheckEnabled = clc;
            Boolean cts = persistence.getBoolean("cookieTrackingSkipEnabled");
            if (cts != null) cookieTrackingSkipEnabled = cts;
            Boolean jwtOn = persistence.getBoolean("jwtEnabled");
            if (jwtOn != null) jwtEnabled = jwtOn;
            Boolean jac = persistence.getBoolean("jwtAlgNoneCheckEnabled");
            if (jac != null) jwtAlgNoneCheckEnabled = jac;
            Boolean jnc = persistence.getBoolean("jwtNoExpiryCheckEnabled");
            if (jnc != null) jwtNoExpiryCheckEnabled = jnc;
            Boolean jlc = persistence.getBoolean("jwtLifetimeCheckEnabled");
            if (jlc != null) jwtLifetimeCheckEnabled = jlc;
            Boolean jap = persistence.getBoolean("jwtActiveProbeEnabled");
            if (jap != null) jwtActiveProbeEnabled = jap;
            Boolean sip = persistence.getBoolean("sessionInvalidationProbeEnabled");
            if (sip != null) sessionInvalidationProbeEnabled = sip;
            Boolean bae = persistence.getBoolean("basicAuthEnabled");
            if (bae != null) basicAuthEnabled = bae;
            Boolean ber = persistence.getBoolean("bearerEnabled");
            if (ber != null) bearerEnabled = ber;
            Boolean akh = persistence.getBoolean("apiKeyHeaderEnabled");
            if (akh != null) apiKeyHeaderEnabled = akh;
            Boolean qst = persistence.getBoolean("queryStringTokenEnabled");
            if (qst != null) queryStringTokenEnabled = qst;
            Boolean wsc = persistence.getBoolean("webStorageCheckEnabled");
            if (wsc != null) webStorageCheckEnabled = wsc;

            Boolean bbe = persistence.getBoolean("browserBridgeEnabled");
            if (bbe != null) browserBridgeEnabled = bbe;
            Integer bbp = persistence.getInteger("browserBridgePort");
            if (bbp != null) browserBridgePort = bbp;
            Boolean bbte = persistence.getBoolean("browserBridgeTokenEnabled");
            if (bbte != null) browserBridgeTokenEnabled = bbte;
            String bbt = persistence.getString("browserBridgeToken");
            if (bbt != null) browserBridgeToken = bbt;
        } catch (Exception ignored) {
            // Corrupt/missing persisted settings, fall back to defaults already set above.
        }
    }

    private void persist() {
        if (persistence == null) return;
        try {
            persistence.setStringList("skipExtensions", toPersistedList(skipExtensions));
            persistence.setStringList("skipContentTypes", toPersistedList(skipContentTypes));
            persistence.setStringList("suppressedHeaders", toPersistedList(suppressedHeaders));
            persistence.setStringList("extraTrackingCookiePrefixes", toPersistedList(extraTrackingCookiePrefixes));
            persistence.setStringList("extraSessionCookieKeywords", toPersistedList(extraSessionCookieKeywords));
            persistence.setStringList("extraApiKeyHeaders", toPersistedList(extraApiKeyHeaders));
            persistence.setStringList("extraQueryTokenParams", toPersistedList(extraQueryTokenParams));
            persistence.setStringList("enabledTools", toPersistedList(new ArrayList<>(enabledTools)));
            persistence.setStringList("cookiesAuthTools", toPersistedList(new ArrayList<>(cookiesAuthTools)));
            persistence.setBoolean("cookiesAuthToolsConfigured", true);

            persistence.setBoolean("restrictToScope", restrictToScope);
            persistence.setBoolean("contextMenuRequireScope", contextMenuRequireScope);
            persistence.setBoolean("activeScanOptionsProbe", activeScanOptionsProbe);
            persistence.setBoolean("activeScanTraceProbe", activeScanTraceProbe);
            persistence.setBoolean("activeScanHstsProbe", activeScanHstsProbe);
            persistence.setBoolean("activeScanWebDavProbe", activeScanWebDavProbe);
            persistence.setBoolean("autoActiveScan", autoActiveScan);
            persistence.setBoolean("googleApiKeyProbeEnabled", googleApiKeyProbeEnabled);
            persistence.setInteger("maxTokenLifetimeMinutes", maxTokenLifetimeMinutes);
            persistence.setBoolean("cookieFlagChecksEnabled", cookieFlagChecksEnabled);
            persistence.setBoolean("cookieLifetimeCheckEnabled", cookieLifetimeCheckEnabled);
            persistence.setBoolean("cookieTrackingSkipEnabled", cookieTrackingSkipEnabled);
            persistence.setBoolean("jwtEnabled", jwtEnabled);
            persistence.setBoolean("jwtAlgNoneCheckEnabled", jwtAlgNoneCheckEnabled);
            persistence.setBoolean("jwtNoExpiryCheckEnabled", jwtNoExpiryCheckEnabled);
            persistence.setBoolean("jwtLifetimeCheckEnabled", jwtLifetimeCheckEnabled);
            persistence.setBoolean("jwtActiveProbeEnabled", jwtActiveProbeEnabled);
            persistence.setBoolean("sessionInvalidationProbeEnabled", sessionInvalidationProbeEnabled);
            persistence.setBoolean("basicAuthEnabled", basicAuthEnabled);
            persistence.setBoolean("bearerEnabled", bearerEnabled);
            persistence.setBoolean("apiKeyHeaderEnabled", apiKeyHeaderEnabled);
            persistence.setBoolean("queryStringTokenEnabled", queryStringTokenEnabled);
            persistence.setBoolean("webStorageCheckEnabled", webStorageCheckEnabled);

            persistence.setBoolean("browserBridgeEnabled", browserBridgeEnabled);
            persistence.setInteger("browserBridgePort", browserBridgePort);
            persistence.setBoolean("browserBridgeTokenEnabled", browserBridgeTokenEnabled);
            persistence.setString("browserBridgeToken", browserBridgeToken);
        } catch (Exception ignored) {
            // Never let persistence errors break settings edits.
        }
    }

    private synchronized void ensureBrowserBridgeToken() {
        if (browserBridgeToken == null || browserBridgeToken.length() < 32) {
            browserBridgeToken = generateBrowserBridgeToken();
            persist();
        }
    }

    private static String generateBrowserBridgeToken() {
        byte[] token = new byte[32];
        new SecureRandom().nextBytes(token);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
    }

    private static burp.api.montoya.persistence.PersistedList<String> toPersistedList(List<String> src) {
        var list = burp.api.montoya.persistence.PersistedList.<String>persistedStringList();
        list.addAll(src);
        return list;
    }

    /**
     * Defensively converts a PersistedList&lt;String&gt; into a real java.util.ArrayList&lt;String&gt;.
     * Despite the generic type, elements coming back from Montoya's persistence layer are not
     * guaranteed to be actual java.lang.String instances at runtime (observed: an internal Burp
     * wrapper type), using them directly as String/CharSequence elsewhere (e.g. String.join)
     * throws ClassCastException. Converting via toString() here is the only safe way to consume them.
     */
    private static List<String> toStringList(List<String> raw) {
        List<String> out = new ArrayList<>(raw.size());
        for (Object o : raw) out.add(String.valueOf(o));
        return out;
    }
}
