package com.b3xal.headeranalyzer.analyzer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialBodyAnalyzerTest {

    @Test
    void ignoresLocalizedPasswordLabelsAsCredentialValues() {
        assertTrue(CredentialBodyAnalyzer.analyze(
                "{\"Passwd\":\"Contraseña\"}", "application/json", "response", null).isEmpty());
        assertTrue(CredentialBodyAnalyzer.analyze(
                "{\"Passwd\":\"contrasena\"}", "application/json", "response", null).isEmpty());
        assertTrue(CredentialBodyAnalyzer.analyze(
                "{\"Passwd\":\"ContraseÃ±a\"}", "application/json", "response", null).isEmpty());
    }

    @Test
    void stillReportsAnActualPasswordValue() {
        var findings = CredentialBodyAnalyzer.analyze(
                "{\"Passwd\":\"RealP4ssword-9382\"}", "application/json", "response", null);

        assertTrue(findings.stream().anyMatch(f ->
                f.issueName.startsWith("Authentication secret embedded")));
    }

    @Test
    void ignoresTemplateKeyAndMinifiedJavascriptExpression() {
        var findings = CredentialBodyAnalyzer.analyze(
                "var cfg={templateKey:\"+this.qh.sh+\",googleapis:\"enabled\"};",
                "text/javascript", "response", null);

        assertTrue(findings.stream().noneMatch(f -> f.issueName.contains("templateKey")));
    }

    @Test
    void ignoresPublicRecaptchaSiteKey() {
        var findings = CredentialBodyAnalyzer.analyze(
                "<div class=\"g-recaptcha\" data-sitekey=\"6LcPublicBrowserSiteKey123456789012345\"></div>" +
                        "<script src=\"https://www.google.com/recaptcha/api.js\"></script>",
                "text/html", "response", null);

        assertTrue(findings.isEmpty());
    }

    @Test
    void stillReportsRecaptchaSecretKey() {
        var findings = CredentialBodyAnalyzer.analyze(
                "var recaptcha={secretKey:\"RealServerSecret-938271645ABCxyz\",verify:" +
                        "\"https://www.google.com/recaptcha/api/siteverify\"};",
                "text/javascript", "response", null);

        assertTrue(findings.stream().anyMatch(f ->
                f.issueName.contains("secretKey")));
    }

    @Test
    void ignoresPublicCloudflareWebAnalyticsBeaconToken() {
        String html = "<script type=\"module\" " +
                "src=\"https://static.cloudflareinsights.com/beacon.min.js/v3d52b479\" " +
                "data-cf-beacon='{\"version\":\"2024.11.0\",\"token\":" +
                "\"ea5c909b68814400a4b39779edba5760\"}' crossorigin=\"anonymous\"></script>";

        assertTrue(CredentialBodyAnalyzer.analyze(
                html, "text/html", "response", null).isEmpty());
    }

    @Test
    void doesNotIgnoreSameTokenShapeOutsideCloudflareBeaconContext() {
        var findings = CredentialBodyAnalyzer.analyze(
                "var auth={token:\"ea5c909b68814400a4b39779edba5760\"};",
                "text/javascript", "response", null);

        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("token")));
    }
}
