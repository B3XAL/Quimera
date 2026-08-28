package com.b3xal.headeranalyzer.model;

/**
 * A single piece of technology fingerprint evidence extracted offline from a response header
 * (e.g. "nginx 1.18.0" parsed out of the Server header). Produced by TechFingerprinter.
 */
public class TechFinding {

    public final String product;       // e.g. "nginx", "PHP", "WordPress"
    public final String version;       // e.g. "1.18.0", null when only the product is known
    public final String sourceHeader;  // header name this was extracted from
    public final String rawValue;      // the raw header value, for evidence

    public TechFinding(String product, String version, String sourceHeader, String rawValue) {
        this.product      = product;
        this.version      = version;
        this.sourceHeader = sourceHeader;
        this.rawValue     = rawValue;
    }

    /** Stable key for de-duplication across URLs of the same host. */
    public String key() {
        return product.toLowerCase() + "|" + (version == null ? "" : version);
    }

    public String display() {
        return version != null ? product + " " + version : product;
    }

    @Override
    public String toString() {
        return display() + " (via " + sourceHeader + ")";
    }
}
