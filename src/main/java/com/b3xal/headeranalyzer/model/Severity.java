package com.b3xal.headeranalyzer.model;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import java.awt.Color;

/**
 * The 4 severity buckets every finding across the rule engine (HeaderRules, CookieAnalyzer,
 * CspAnalyzer, ActiveHeaderScanner, WebStorageAnalyzer) is assigned into. This is the single
 * canonical source of truth for what each bucket MEANS, grounded in CVSS v3.1 reasoning, every
 * severity value chosen anywhere in the engine should be justifiable against this table. There is
 * deliberately no numeric CVSS score or vector string stored anywhere in the codebase, CVSS is
 * used here purely as the internal methodology for choosing a bucket, not as displayed data.
 *
 * <pre>
 * Bucket       CVSS band    Typical vector pattern in this domain                         Example
 * HIGH         7.0-10.0     AV:N/AC:L/PR:N/UI:N + C:H (or S:C). A directly usable          CORS reflects origin + credentials;
 *                            primitive, no separate bug or user action needed.              live Symfony profiler URL in prod.
 * MEDIUM       4.0-6.9      Network-reachable but gated by ONE precondition: AC:H          Missing HSTS/CSP/XFO; CORS * / null;
 *                            (needs a MITM position) or UI:R (needs a victim), or needs      Apache/1.3.4; cookie missing
 *                            another sink to be exploitable. Also: an EXACT VERSION          Secure/HttpOnly.
 *                            string disclosed (narrows targeted-exploit search a lot), or
 *                            internal-infrastructure disclosure enabling a WAF/CDN bypass.
 * LOW          0.1-3.9      A defence-in-depth gap, or PRODUCT-FAMILY recon with no          Bare "Server: Apache" (no version);
 *                            version: helps an attack but needs chaining with something       missing SameSite; unsafe referrer policy.
 *                            else first.
 * INFORMATION  0.0          No exploitable vector beyond what default probing already        X-Cache, Via, Last-Modified.
 *                            gives an attacker: cache status, timing, timestamps, an IP
 *                            echo, a harmless deprecated header.
 * </pre>
 *
 * Two load-bearing rules derived from the table above, applied consistently across every
 * analyzer:
 * <ol>
 *   <li><b>Version escalation.</b> A header disclosing only a product/framework FAMILY name
 *       ("Apache", "Express") is LOW. The same header disclosing an exact VERSION string
 *       ("Apache/1.3.4", "PHP/8.1.2") escalates one bucket to MEDIUM. The justification is
 *       attacker effort/Attack-Complexity, not a per-version CVSS delta: an exact version
 *       collapses the attacker's targeted-exploit search regardless of which version it
 *       actually is. This is applied generically, with no per-product exceptions and no
 *       maintained table of "known old/EOL versions", Quimera is deliberately offline and does
 *       not do CVE lookups.</li>
 *   <li><b>Attack-enabler scoring.</b> A header/value that enables an entire attack class (CORS
 *       misconfiguration, missing CSP enabling XSS, missing HSTS enabling MITM downgrade,
 *       insecure cookie flags enabling session hijack) is scored by what that attack class
 *       actually grants under CVSS (AV/AC/PR/UI/S and the C/I/A impact triad), not by a flat
 *       "security header missing" label. See ActiveHeaderScanner's CORS origin-reflection tests
 *       (HIGH only when Access-Control-Allow-Credentials: true makes the primitive complete,
 *       MEDIUM otherwise) as the reference example of this reasoning applied correctly.</li>
 * </ol>
 */
public enum Severity {
    HIGH       (0, "High",        new Color(192,  57,  43), AuditIssueSeverity.HIGH),
    MEDIUM     (1, "Medium",      new Color(211, 127,   0), AuditIssueSeverity.MEDIUM),
    LOW        (2, "Low",         new Color( 39, 174,  96), AuditIssueSeverity.LOW),
    INFORMATION(3, "Information", new Color( 41, 128, 185), AuditIssueSeverity.INFORMATION);

    public final int order;
    public final String label;
    public final Color color;
    public final AuditIssueSeverity burpSeverity;

    Severity(int order, String label, Color color, AuditIssueSeverity burpSeverity) {
        this.order       = order;
        this.label       = label;
        this.color       = color;
        this.burpSeverity = burpSeverity;
    }

    public static Severity worst(Severity a, Severity b) {
        return a.order <= b.order ? a : b;
    }
}
