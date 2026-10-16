package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InfrastructureCookieCatalogTest {
    @Test
    void excludesAllDocumentedCatoFirewallPrefixesCaseInsensitively() {
        var config = new QuimeraSettings().cookiesAndAuthConfig();
        for (String name : new String[]{"cato_fw_inet", "CATO_FW_WAN_123", "cato_tls_cert_err",
                "fw_inet_42", "fw_wan", "tls_cert_err_example"}) {
            assertTrue(CookieAnalyzer.isInfrastructureCookie(name), name);
            assertTrue(CookieAnalyzer.analyze(name + "=opaque; Path=/", "example.test", config)
                    .isEmpty(), name);
            assertTrue(AuthHeaderAnalyzer.analyzeCookieHeaderAuth(name + "=opaque", config)
                    .isEmpty(), name);
        }
    }

    @Test
    void excludesOtherUnambiguousWafCookieFamilies() {
        for (String name : new String[]{"aws-waf-token", "__cf_bm", "cf_clearance",
                "cf_chl_rc_i", "ak_bmsc", "bm_sz", "_abck", "NSC_abcd"}) {
            assertTrue(CookieAnalyzer.isInfrastructureCookie(name), name);
        }
    }

    @Test
    void fingerprintsCatoFromBrowserOrHttpCookieEvidence() {
        var responseTech = TechFingerprinter.analyze(Map.of(
                "Set-Cookie", "cato_fw_inet=opaque; Path=/"));
        var requestTech = TechFingerprinter.analyzeRequest(Map.of(
                "Cookie", "ordinary=x; cato_fw_inet=opaque"));
        assertEquals("Cato Networks Internet Firewall", responseTech.get(0).product);
        assertEquals("Cato Networks Internet Firewall", requestTech.get(0).product);
    }
}
