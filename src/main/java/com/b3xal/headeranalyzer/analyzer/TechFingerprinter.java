package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.TechFinding;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Offline technology/version fingerprinting from response headers. Goes beyond "this header is
 * present" (HeaderRules' information-disclosure rules) by actually parsing out the product name
 * and version string, so the Logger/Report can show a real inventory (e.g. "nginx 1.18.0",
 * "PHP 7.4.3") instead of just flagging that Server/X-Powered-By exist.
 *
 * No network calls, no CVE lookups, purely regex extraction from headers already in hand.
 */
public final class TechFingerprinter {

    private TechFingerprinter() {}

    // product/version pair, e.g. "nginx/1.18.0" or "Apache/2.4.41 (Ubuntu)"
    private static final Pattern PRODUCT_SLASH_VERSION =
            Pattern.compile("([A-Za-z][A-Za-z0-9._-]*)/([0-9][A-Za-z0-9._-]*)");

    // "WordPress 6.4.2", "Drupal 9"
    private static final Pattern PRODUCT_SPACE_VERSION =
            Pattern.compile("([A-Za-z][A-Za-z0-9._ -]*?)\\s+v?([0-9]+(?:\\.[0-9]+)*)");

    private static final Pattern BARE_VERSION = Pattern.compile("^[vV]?([0-9]+(?:\\.[0-9]+){0,4}.*)$");

    /**
     * headerName (lowercased) -> extraction strategy.
     */
    private interface Extractor { List<TechFinding> extract(String headerName, String value); }

    private static final Map<String, Extractor> STRATEGIES = new LinkedHashMap<>();

    static {
        // Headers that carry "Product/Version" pairs, possibly several separated by whitespace
        // (e.g. "Apache/2.4.41 (Unix) OpenSSL/1.1.1k PHP/7.4.20")
        Extractor slashPairs = (h, v) -> extractSlashPairs(h, v);
        STRATEGIES.put("server", slashPairs);
        STRATEGIES.put("via", slashPairs);
        STRATEGIES.put("x-powered-by", (h, v) -> {
            List<TechFinding> found = extractSlashPairs(h, v);
            if (!found.isEmpty()) return found;
            return List.of(new TechFinding(v.trim(), null, h, v));
        });

        // Headers whose value IS a bare version number for a known product
        STRATEGIES.put("x-aspnet-version",    bareVersionOf("ASP.NET"));
        STRATEGIES.put("x-aspnetmvc-version", bareVersionOf("ASP.NET MVC"));
        // x-powered-by-php/x-php-version removed: not real headers, see HeaderRules.java.

        // Headers with "Product Version" free text
        STRATEGIES.put("x-generator", (h, v) -> extractSpacedProductVersion(h, v));

        // Presence-only indicators, confirm a product/platform with no version data
        // x-powered-by-asp.net/x-powered-cms/x-cms-api removed: not real headers, see HeaderRules.java.
        presenceOnly("x-drupal-cache",       "Drupal");
        presenceOnly("x-drupal-dynamic-cache","Drupal");
        presenceOnly("x-wp-nonce",           "WordPress");
        presenceOnly("x-pingback",           "WordPress");
        presenceOnly("x-varnish",            "Varnish");
        presenceOnly("x-mod-pagespeed",      "Apache/Nginx mod_pagespeed");
        presenceOnly("x-litespeed-cache",    "LiteSpeed");
        presenceOnly("x-envoy-upstream-service-time", "Envoy");
        presenceOnly("cf-ray",               "Cloudflare");
        presenceOnly("x-amz-request-id",     "AWS");
        presenceOnly("x-amz-id-2",           "AWS (S3/CloudFront)");
        presenceOnly("x-azure-ref",          "Azure Front Door / CDN");
        presenceOnly("x-served-by",          "Fastly");
        presenceOnly("x-timer",              "Fastly");
        presenceOnly("x-owa-version",        "Microsoft Exchange OWA");
        presenceOnly("x-application-context",  "Spring Boot");
        presenceOnly("x-runtime",            "Ruby on Rails");
        STRATEGIES.put("x-framework", (h, v) -> extractSpacedProductVersion(h, v));

        // Real Joomla header (X-Powered-By-Joomla never existed), "Joomla! 3.9.2"-shaped, the "!"
        // breaks PRODUCT_SPACE_VERSION's character class so it needs its own small extractor.
        STRATEGIES.put("x-content-encoded-by", (h, v) -> {
            Matcher m = Pattern.compile("(?i)joomla!?\\s*([0-9][0-9.]*)").matcher(v);
            if (m.find()) return List.of(new TechFinding("Joomla", m.group(1), h, v));
            String s = v.trim();
            return s.isEmpty() ? List.of() : List.of(new TechFinding(s, null, h, v));
        });

        STRATEGIES.put("x-jenkins", bareVersionOf("Jenkins"));
        presenceOnly("x-jenkins-session",    "Jenkins");
        presenceOnly("x-elastic-product",    "Elasticsearch");
        presenceOnly("x-arequestid",         "Atlassian (Jira/Confluence)");
        presenceOnly("x-asen",               "Atlassian (Jira/Confluence)");
        presenceOnly("x-symfony-cache",      "Symfony");
        presenceOnly("x-newrelic-app-data",  "New Relic APM");

        // "Liferay Portal Community Edition 7.4.0 CE GA1 ..." has trailing text after the version
        // that PRODUCT_SPACE_VERSION's whole-string match can't account for, dedicated extractor.
        STRATEGIES.put("liferay-portal", (h, v) -> {
            Matcher m = Pattern.compile("Liferay Portal.*?([0-9]+(?:\\.[0-9]+)+)").matcher(v);
            if (m.find()) return List.of(new TechFinding("Liferay Portal", m.group(1), h, v));
            String s = v.trim();
            return s.isEmpty() ? List.of() : List.of(new TechFinding(s, null, h, v));
        });

        STRATEGIES.put("kbn-version", bareVersionOf("Kibana"));
        presenceOnly("kbn-name",             "Kibana");
    }

    private static void presenceOnly(String header, String product) {
        STRATEGIES.put(header, (h, v) -> List.of(new TechFinding(product, null, h, v)));
    }

    private static Extractor bareVersionOf(String product) {
        return (h, v) -> {
            Matcher m = BARE_VERSION.matcher(v.trim());
            if (m.matches()) return List.of(new TechFinding(product, m.group(1), h, v));
            return List.of(new TechFinding(product, null, h, v));
        };
    }

    private static List<TechFinding> extractSlashPairs(String header, String value) {
        List<TechFinding> out = new ArrayList<>();
        Matcher m = PRODUCT_SLASH_VERSION.matcher(value);
        while (m.find()) {
            out.add(new TechFinding(m.group(1), m.group(2), header, value));
        }
        return out;
    }

    private static List<TechFinding> extractSpacedProductVersion(String header, String value) {
        Matcher m = PRODUCT_SPACE_VERSION.matcher(value.trim());
        if (m.matches()) {
            return List.of(new TechFinding(m.group(1).trim(), m.group(2), header, value));
        }
        // No version found, still record the raw generator/CMS string as a product name
        String v = value.trim();
        if (!v.isEmpty()) return List.of(new TechFinding(v, null, header, value));
        return List.of();
    }

    /**
     * Scans all response headers and returns the de-duplicated technology findings.
     * headers keys are expected case-insensitively; caller should pass the same case-insensitive
     * map used elsewhere in the engine.
     */
    public static List<TechFinding> analyze(Map<String, String> headers) {
        List<TechFinding> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            String name = e.getKey();
            String value = e.getValue();
            if (value == null || value.isBlank()) continue;
            Extractor strat = STRATEGIES.get(name.toLowerCase(Locale.ROOT));
            if (strat == null) continue;
            for (TechFinding tf : strat.extract(name, value)) {
                if (seen.add(tf.key())) out.add(tf);
            }
        }
        return out;
    }
}
