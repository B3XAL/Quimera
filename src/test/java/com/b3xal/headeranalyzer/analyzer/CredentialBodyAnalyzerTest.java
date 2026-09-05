package com.b3xal.headeranalyzer.analyzer;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialBodyAnalyzerTest {

    @Test
    void ignoresNormalPasswordSubmittedInRequestBody() {
        assertTrue(CredentialBodyAnalyzer.analyze(
                "{\"password\":\"DasFeld19*\"}", "application/json", "request", null).isEmpty());
    }

    @Test
    void ignoresPasswordTranslationsInLocalizationResourcesWithoutLanguageAllowlist() {
        String translations = "{\"Password\":\"Kennwort\",\"Passwd\":\"密码\"," +
                "\"client_secret\":\"クライアントシークレット\"}";

        assertTrue(CredentialBodyAnalyzer.analyze(translations, "application/json", "response",
                null, "https://myaccount.mygtmotive.com/i18n/resources.json").isEmpty());
        assertTrue(CredentialBodyAnalyzer.analyze(translations, "application/json", "response",
                null, "https://example.test/LOCALES/es-ES.json").isEmpty());
    }

    @Test
    void stillFindsProviderSpecificSecretInsideLocalizationResource() {
        String body = "{\"Password\":\"Contraseña\",\"supportKey\":" +
                "\"GOCSPX-abcdefghijklmnopqrstuvwxyz12\"}";

        var findings = CredentialBodyAnalyzer.analyze(body, "application/json", "response",
                null, "https://example.test/i18n/resources.json");
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("Google OAuth client secret")));
    }

    @Test
    void ignoresLocalizedPasswordLabelsAsCredentialValues() {
        assertTrue(CredentialBodyAnalyzer.analyze(
                "{\"Passwd\":\"Contraseña\"}", "application/json", "response", null).isEmpty());
        assertTrue(CredentialBodyAnalyzer.analyze(
                "{\"Passwd\":\"contrasena\"}", "application/json", "response", null).isEmpty());
        assertTrue(CredentialBodyAnalyzer.analyze(
                "{\"Passwd\":\"ContraseÃ±a\"}", "application/json", "response", null).isEmpty());
        assertTrue(CredentialBodyAnalyzer.analyze(
                "{\"Password\":\"Contrasenya\"}", "application/json", "response", null).isEmpty());
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
    void detectsTwilioAccountSidByValueShapeAloneNoFieldNameNeeded() {
        // No suggestive field name at all, a bare match inside an error message/log line, exactly
        // the case a field-name-only catalog entry (CredentialProviderCatalog's own "Twilio") would
        // miss.
        var findings = CredentialBodyAnalyzer.analyze(
                "console.log('debug: AC0123456789abcdef0123456789abcdef failed lookup');",
                "text/javascript", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("Twilio Account SID")));
    }

    @Test
    void detectsOpenAiProjectKeyByValueShapeAlone() {
        // No suggestive field name: a bare value like this would otherwise be caught by the
        // named-assignment path instead (dedup would then hide the signature's own generic
        // issueName behind the field-specific one), this test is specifically about the
        // no-field-name-at-all case the signature list exists to cover.
        String key = "sk-proj-" + "abcdefghij".repeat(8);
        var findings = CredentialBodyAnalyzer.analyze(
                "console.log('startup token: " + key + " loaded');", "text/javascript", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("OpenAI project API key")));
    }

    @Test
    void detectsShopifyAccessTokenByValueShapeAlone() {
        var findings = CredentialBodyAnalyzer.analyze(
                "window.token = 'shpat_0123456789abcdef0123456789abcdef';",
                "text/javascript", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("Shopify access token")));
    }

    @Test
    void detectsNpmAccessTokenByValueShapeAlone() {
        String token = "npm_" + "abcdefghij".repeat(3) + "klmnop";
        var findings = CredentialBodyAnalyzer.analyze(
                "echo '//registry.npmjs.org/:_authToken=" + token + "'",
                "text/plain", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("npm access token")));
    }

    @Test
    void detectsDigitalOceanTokenByValueShapeAlone() {
        String token = "dop_v1_" + "0123456789abcdef".repeat(4);
        var findings = CredentialBodyAnalyzer.analyze(
                "console.log('startup token: " + token + " loaded');", "text/javascript", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("DigitalOcean personal access token")));
    }

    @Test
    void detectsDockerHubTokenByValueShapeAlone() {
        String token = "dckr_pat_" + "abcdefghij".repeat(3);
        var findings = CredentialBodyAnalyzer.analyze(
                "console.log('startup token: " + token + " loaded');", "text/javascript", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("Docker Hub access token")));
    }

    @Test
    void detectsPlanetScaleTokenByValueShapeAlone() {
        String token = "pscale_tkn_" + "abcdefghij".repeat(4);
        var findings = CredentialBodyAnalyzer.analyze(
                "console.log('startup token: " + token + " loaded');", "text/javascript", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("PlanetScale service token")));
    }

    @Test
    void detectsSentryAuthTokenByValueShapeAlone() {
        String token = "sntrys_" + "abcdefghij".repeat(4);
        var findings = CredentialBodyAnalyzer.analyze(
                "console.log('startup token: " + token + " loaded');", "text/javascript", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("Sentry auth token")));
    }

    @Test
    void detectsNotionIntegrationTokenByValueShapeAlone() {
        String token = "ntn_" + "abcdefghij".repeat(4);
        var findings = CredentialBodyAnalyzer.analyze(
                "console.log('startup token: " + token + " loaded');", "text/javascript", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("Notion integration token")));
    }

    @Test
    void detectsFigmaPersonalAccessTokenByValueShapeAlone() {
        String token = "figd_" + "abcdefghij".repeat(4);
        var findings = CredentialBodyAnalyzer.analyze(
                "console.log('startup token: " + token + " loaded');", "text/javascript", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("Figma personal access token")));
    }

    @Test
    void detectsCloudinaryUrlByValueShapeAlone() {
        var findings = CredentialBodyAnalyzer.analyze(
                "CLOUDINARY_URL=cloudinary://123456789012:abcdefghijklmnopqrst@mycloud",
                "text/plain", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("Cloudinary API URL")));
    }

    @Test
    void detectsOktaApiTokenOnlyWhenAnchoredToSswsScheme() {
        String rawToken = "00" + "abcdefghij".repeat(4);
        // The bare token alone (no "SSWS " scheme prefix) must NOT fire, it is far too generic
        // a shape (just "00" + 40 alnum chars) to safely flag without that anchor.
        assertTrue(CredentialBodyAnalyzer.analyze(
                "console.log('id: " + rawToken + "');", "text/javascript", "response", null)
                .stream().noneMatch(f -> f.issueName.contains("Okta API token")));

        var findings = CredentialBodyAnalyzer.analyze(
                "console.log('Authorization: SSWS " + rawToken + "');", "text/javascript", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("Okta API token")));
    }

    @Test
    void detectsDiscordWebhookUrlByValueShapeAlone() {
        String url = "https://discord.com/api/webhooks/123456789012345678/" + "abcdefghij".repeat(7);
        var findings = CredentialBodyAnalyzer.analyze(
                "fetch('" + url + "', {method:'POST'});", "text/javascript", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("Discord webhook URL")));
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
