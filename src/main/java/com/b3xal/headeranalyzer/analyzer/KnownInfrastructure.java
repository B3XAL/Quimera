package com.b3xal.headeranalyzer.analyzer;

/**
 * Single source of truth for "this Server value identifies a CDN/PaaS, not the origin backend".
 *
 * The problem this solves: every info-disclosure header rule used to be a blanket ".*" match, so
 * a CDN identity header (Server: cloudflare, Server: AmazonS3) was flagged exactly like a real
 * origin-server disclosure (Server: Apache/2.4.41). CDN identity is not a vulnerability, revealing
 * the origin's actual software/version is. This regex is used as a NO_MATCH check on the Server
 * rule: values matching it are known infrastructure and get skipped, anything else still fires.
 *
 * Kept as one editable data point rather than scattered across HeaderRules, TechFingerprinter and
 * ReportPanel, so adding a newly-observed CDN string only needs a change here.
 */
public final class KnownInfrastructure {

    private KnownInfrastructure() {}

    /**
     * The alternation itself, without the anchors, factored out so HeaderRules' bare-vs-versioned
     * Server split (see Severity's version-escalation rule) can reuse it inside a negative
     * lookahead, "not one of these known CDN identities", alongside its own version-presence check.
     */
    public static final String CDN_SERVER_ALT =
            "cloudflare" +
            "|AmazonS3" +
            "|CloudFront" +
            "|Google Frontend" +
            "|gws" +
            "|Microsoft-Azure-Application-Gateway/.*" +
            "|Microsoft-Azure-HDInsight" +
            "|Vercel" +
            "|Netlify" +
            "|GitHub\\.com" +
            "|Fastly" +
            "|Varnish" +
            "|AkamaiGHost" +
            "|awselb/.*" +
            "|ATS/.*" +
            "|BunnyCDN.*" +
            "|Deno Deploy" +
            "|Render";

    /**
     * Anchored, case-insensitive. Matches bare CDN/PaaS/edge-proxy identity strings as sent in the
     * Server header, with or without a trailing version number, but NOT arbitrary origin software.
     * Deliberately conservative: an origin's real software (Apache, nginx, IIS, LiteSpeed, Caddy,
     * Kestrel, Tomcat, Jetty, Gunicorn, Werkzeug, Express...) is NOT on this list on purpose, only
     * the well-known "we ARE the CDN/edge, not the origin" identity strings are.
     */
    public static final String CDN_SERVER_REGEX = "(?i)^(" + CDN_SERVER_ALT + ")$";
}
