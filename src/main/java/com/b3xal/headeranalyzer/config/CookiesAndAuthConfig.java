package com.b3xal.headeranalyzer.config;

import java.util.List;

/**
 * Everything {@code CookieAnalyzer}, {@code JwtAnalyzer} and {@code AuthHeaderAnalyzer} need to
 * know from Settings, bundled into one object instead of a pile of positional parameters.
 * {@link QuimeraSettings#cookiesAndAuthConfig()} builds a fresh instance from current state,
 * {@code HeaderAnalysisEngine} builds one per {@code analyze(...)} call and threads the same
 * instance into all three analyzers, edited live from the "Cookies & Auth Rules..." dialog
 * (Settings tab).
 *
 * Plain immutable data holder, no logic, same spirit as {@link com.b3xal.headeranalyzer.model.HeaderFinding}.
 * The "extra*" lists ADD to each analyzer's own built-in list, they never replace it.
 */
public final class CookiesAndAuthConfig {

    public final int maxLifetimeMinutes;

    public final boolean cookieFlagChecksEnabled;
    public final boolean cookieLifetimeCheckEnabled;
    public final boolean cookieTrackingSkipEnabled;
    public final List<String> extraTrackingPrefixes;
    public final List<String> extraSessionKeywords;

    public final boolean jwtEnabled;
    public final boolean jwtAlgNoneCheckEnabled;
    public final boolean jwtNoExpiryCheckEnabled;
    public final boolean jwtLifetimeCheckEnabled;

    public final boolean basicAuthEnabled;
    public final boolean bearerEnabled;
    public final boolean apiKeyHeaderEnabled;
    public final boolean queryStringTokenEnabled;
    public final List<String> extraApiKeyHeaders;
    public final List<String> extraQueryTokenParams;
    public final boolean webStorageCheckEnabled;

    public CookiesAndAuthConfig(int maxLifetimeMinutes,
                                 boolean cookieFlagChecksEnabled,
                                 boolean cookieLifetimeCheckEnabled,
                                 boolean cookieTrackingSkipEnabled,
                                 List<String> extraTrackingPrefixes,
                                 List<String> extraSessionKeywords,
                                 boolean jwtEnabled,
                                 boolean jwtAlgNoneCheckEnabled,
                                 boolean jwtNoExpiryCheckEnabled,
                                 boolean jwtLifetimeCheckEnabled,
                                 boolean basicAuthEnabled,
                                 boolean bearerEnabled,
                                 boolean apiKeyHeaderEnabled,
                                 boolean queryStringTokenEnabled,
                                 List<String> extraApiKeyHeaders,
                                 List<String> extraQueryTokenParams,
                                 boolean webStorageCheckEnabled) {
        this.maxLifetimeMinutes = maxLifetimeMinutes;
        this.cookieFlagChecksEnabled = cookieFlagChecksEnabled;
        this.cookieLifetimeCheckEnabled = cookieLifetimeCheckEnabled;
        this.cookieTrackingSkipEnabled = cookieTrackingSkipEnabled;
        this.extraTrackingPrefixes = extraTrackingPrefixes;
        this.extraSessionKeywords = extraSessionKeywords;
        this.jwtEnabled = jwtEnabled;
        this.jwtAlgNoneCheckEnabled = jwtAlgNoneCheckEnabled;
        this.jwtNoExpiryCheckEnabled = jwtNoExpiryCheckEnabled;
        this.jwtLifetimeCheckEnabled = jwtLifetimeCheckEnabled;
        this.basicAuthEnabled = basicAuthEnabled;
        this.bearerEnabled = bearerEnabled;
        this.apiKeyHeaderEnabled = apiKeyHeaderEnabled;
        this.queryStringTokenEnabled = queryStringTokenEnabled;
        this.extraApiKeyHeaders = extraApiKeyHeaders;
        this.extraQueryTokenParams = extraQueryTokenParams;
        this.webStorageCheckEnabled = webStorageCheckEnabled;
    }
}
