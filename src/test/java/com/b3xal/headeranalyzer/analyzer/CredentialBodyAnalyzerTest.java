package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialBodyAnalyzerTest {

    @Test
    void treatsStructuredOAuthTokenEndpointResponseAsInformationalInventory() {
        String body = "{\"access_token\":\"opaque-access-token-123456\",\"refreshToken\":\"opaque-refresh-token-123456\"," +
                "\"token_type\":\"Bearer\",\"expires_in\":300,\"scope\":\"openid profile\"}";
        var findings = CredentialBodyAnalyzer.analyze(body, "application/json", "response", null,
                "https://example.test/api/oauth/token");

        assertTrue(findings.stream().anyMatch(f -> f.issueName.equals(
                "Authentication material observed in structured response body")));
        assertTrue(findings.stream().noneMatch(f -> f.issueName.startsWith(
                "Authentication secret embedded in client-visible response: refreshToken")));
    }

    @Test
    void recognizesCamelCaseExpirationMetadataAtTokenEndpoint() {
        String body = "{\"accessToken\":\"opaque-access-token-123456\",\"refreshToken\":\"opaque-refresh-token-123456\"," +
                "\"expiresInSeconds\":300}";
        var findings = CredentialBodyAnalyzer.analyze(body, "application/json", "response", null,
                "https://learner-portal.pre.example.test/api/oauth/token");

        assertTrue(findings.stream().anyMatch(f -> f.issueName.equals(
                "Authentication material observed in structured response body")));
        assertTrue(findings.stream().noneMatch(f -> f.issueName.startsWith(
                "Authentication secret embedded in client-visible response: refreshToken")));
    }

    @Test
    void recognizesCommonExpiryAliasesOnlyWithTheRequiredOAuthContext() {
        List<String> expiryFields = List.of("expires", "expires_in", "expiresIn", "expiresInSeconds",
                "refresh_expires_in", "refreshExpiresInSeconds", "expires_at", "expiresAt", "expiry",
                "expiration", "expirationTime", "validUntil");
        for (String expiryField : expiryFields) {
            String body = "{\"accessToken\":\"opaque-access-token-123456\",\"refreshToken\":\"opaque-refresh-token-123456\",\""
                    + expiryField + "\":300}";
            var findings = CredentialBodyAnalyzer.analyze(body, "application/json", "response", null,
                    "https://example.test/connect/token/");
            assertTrue(findings.stream().noneMatch(f -> f.issueName.startsWith(
                    "Authentication secret embedded in client-visible response: refreshToken")), expiryField);
        }
    }

    @Test
    void recognizesIsoExpirationAndTokenResponseWrapperWithoutPerfectJsonMimeType() {
        String body = "{\"data\":{\"access_token\":\"opaque-access-token-123456\","
                + "\"refresh_token\":\"opaque-refresh-token-123456\",\"expiresAt\":\"2026-10-14T13:33:44Z\"}}";
        var findings = CredentialBodyAnalyzer.analyze(body, "text/plain", "response", null,
                "https://example.test/oauth2/token");

        assertTrue(findings.stream().noneMatch(f -> f.issueName.startsWith(
                "Authentication secret embedded in client-visible response: refresh_token")));
    }

    @Test
    void doesNotTreatUnvalidatedExpiryTextAsOAuthMetadata() {
        String body = "{\"refreshToken\":\"opaque-refresh-token-123456\",\"expires\":\"eventually\"}";
        var findings = CredentialBodyAnalyzer.analyze(body, "application/json", "response", null,
                "https://example.test/api/oauth/token");

        assertTrue(findings.stream().anyMatch(f -> f.issueName.startsWith(
                "Authentication secret embedded in client-visible response: refreshToken")));
    }

    @Test
    void doesNotSuppressARefreshTokenOutsideTokenEndpointWithOnlyAnExpiryField() {
        String body = "{\"refreshToken\":\"opaque-refresh-token-123456\",\"expires\":300}";
        var findings = CredentialBodyAnalyzer.analyze(body, "application/json", "response", null,
                "https://example.test/api/profile");

        assertTrue(findings.stream().anyMatch(f -> f.issueName.startsWith(
                "Authentication secret embedded in client-visible response: refreshToken")));
    }

    @Test
    void tokenLookingPathAloneDoesNotSuppressRefreshTokenLeak() {
        String body = "{\"refreshToken\":\"opaque-refresh-token-123456\"}";
        var findings = CredentialBodyAnalyzer.analyze(body, "application/json", "response", null,
                "https://example.test/api/tokens");

        assertTrue(findings.stream().anyMatch(f -> f.issueName.startsWith(
                "Authentication secret embedded in client-visible response: refreshToken")));
    }

    @Test
    void oauthResponseShapeWithoutTokenEndpointPathIsStillRecognized() {
        String body = "{\"access_token\":\"opaque-access-token-123456\",\"refresh_token\":\"opaque-refresh-token-123456\"," +
                "\"token_type\":\"Bearer\",\"expires_in\":300}";
        var findings = CredentialBodyAnalyzer.analyze(body, "application/json", "response", null,
                "https://example.test/session/renew");

        assertTrue(findings.stream().noneMatch(f -> f.issueName.startsWith(
                "Authentication secret embedded in client-visible response: refresh_token")));
    }

    @Test
    void tokenEndpointDoesNotSuppressClientSecretAlongsideIssuedTokens() {
        String body = "{\"access_token\":\"opaque-access-token-123456\",\"refresh_token\":\"opaque-refresh-token-123456\"," +
                "\"token_type\":\"Bearer\",\"client_secret\":\"ActualClientSecret-938271\"}";
        var findings = CredentialBodyAnalyzer.analyze(body, "application/json", "response", null,
                "https://example.test/oauth2/token");

        assertTrue(findings.stream().anyMatch(f -> f.issueName.startsWith(
                "Authentication secret embedded in client-visible response: client_secret")));
    }

    @Test
    void htmlAtTokenEndpointDoesNotQualifyAsOAuthTokenResponse() {
        String body = "<script>var refreshToken = 'opaque-refresh-token-123456';</script>";
        var findings = CredentialBodyAnalyzer.analyze(body, "text/html", "response", null,
                "https://example.test/oauth/token");

        assertTrue(findings.stream().anyMatch(f -> f.issueName.startsWith(
                "Authentication secret embedded in client-visible response: refreshToken")));
    }

    @Test
    void ignoresCredentialShapedBytesInBinaryImages() {
        // This is the shape that triggered a native issue in a JPEG response. It is just an
        // arbitrary byte run when decoded as text, not evidence of a Telegram credential.
        String jpegBytesDecodedAsText = "456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz";

        assertTrue(CredentialBodyAnalyzer.analyze(jpegBytesDecodedAsText, "image/jpeg",
                "response", null).isEmpty());
    }

    @Test
    void stillScansTextualSvgResponses() {
        String accessKeyId = "AKIAA1B2C3D4E5F6G7H8";

        assertTrue(CredentialBodyAnalyzer.analyze("<svg><!-- " + accessKeyId + " --></svg>",
                "image/svg+xml", "response", null).stream().anyMatch(f ->
                f.issueName.equals("AWS access key ID observed in response body")));
    }

    @Test
    void detectsAwsAccessKeyIdInAnHtmlErrorPage() {
        String accessKeyId = "AKIAA1B2C3D4E5F6G7H8";
        String body = "<tr><td>EMAIL_HOST_USER</td><td><pre>" + accessKeyId + "</pre></td></tr>";

        var findings = CredentialBodyAnalyzer.analyze(body, "text/html", "response", null);

        var finding = findings.stream().filter(f ->
                f.issueName.equals("AWS access key ID observed in response body")).findFirst().orElseThrow();
        assertEquals("Response body match: " + accessKeyId, finding.evidence);
    }

    @Test
    void reportsAwsIamPublicKeyIdentifierAsInformationalNotAccessCredential() {
        String publicKeyIdentifier = "APKAJC6L55ANNKVLSMPQ";

        var findings = CredentialBodyAnalyzer.analyze(publicKeyIdentifier, "text/html", "response", null);

        var finding = findings.stream().filter(f -> f.issueName.equals(
                "AWS IAM public key identifier observed in response body")).findFirst().orElseThrow();
        assertEquals(Severity.INFORMATION, finding.severity);
        assertTrue(finding.description.contains("not an access key or authentication secret"));
        assertTrue(findings.stream().noneMatch(f -> f.issueName.equals(
                "AWS access key ID observed in response body")));
    }

    @Test
    void preservesEveryDistinctCredentialOfTheSameTypeInOneResponse() {
        String first = "AKIA1111222233334444";
        String second = "AKIAAAAABBBBCCCCDDDD";
        var findings = CredentialBodyAnalyzer.analyze(first + " " + second + " " + first,
                "text/html", "response", null);
        var aws = findings.stream().filter(f -> f.issueName.equals("AWS access key ID observed in response body"))
                .toList();
        assertEquals(2, aws.size());
        assertTrue(aws.stream().anyMatch(f -> f.headerValue.equals(first)));
        assertTrue(aws.stream().anyMatch(f -> f.headerValue.equals(second)));
    }

    @Test
    void preservesDistinctValuesUnderTheSameDebugSettingName() {
        String body = "&#x27;PASSWORD&#x27;: &#x27;FirstRealSecret-9427&#x27; " +
                "&#x27;PASSWORD&#x27;: &#x27;SecondRealSecret-1846&#x27;";
        var findings = CredentialBodyAnalyzer.analyze(body, "text/html", "response", null).stream()
                .filter(f -> f.issueName.contains("Authentication secret embedded")).toList();
        assertEquals(2, findings.size());
    }

    @Test
    void detectsServerLeakTriggeredByHeaderInfluenceProbe() {
        String accessKeyId = "AKIAA1B2C3D4E5F6G7H8";
        var engine = new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());

        var findings = engine.analyzeCredentialBodies("https://example.test/private.jsp",
                Map.of("Content-Type", "text/html"),
                Map.of(HeaderInfluenceProbe.MARKER_HEADER, "probe-marker"),
                "<pre>" + accessKeyId + "</pre>", "");

        assertTrue(findings.stream().anyMatch(f ->
                f.issueName.equals("AWS access key ID observed in response body")));
    }

    @Test
    void keepsResponseHeaderDisclosuresFromHeaderInfluenceProbeOnly() {
        var engine = new HeaderAnalysisEngine(new RuleStore(null), new QuimeraSettings());

        var result = engine.analyze("https://example.test/private.jsp",
                Map.of("Server", "nginx/1.24.0"),
                Map.of(HeaderInfluenceProbe.MARKER_HEADER, "probe-marker"),
                400, "<html><body>Bad host</body></html>", "GET", false);

        assertTrue(result.findings.stream().anyMatch(f ->
                f.category == com.b3xal.headeranalyzer.model.HeaderFinding.Category.INFORMATION_DISCLOSURE));
        assertTrue(result.findings.stream().noneMatch(f ->
                f.category != com.b3xal.headeranalyzer.model.HeaderFinding.Category.INFORMATION_DISCLOSURE));
    }

    @Test
    void googleApiKeyExposureIsInformationalWithOrWithoutFieldName() {
        String key = "AIza12345678901234567890123456789012345";
        for (String body : new String[]{"var api_key=\"" + key + "\";", "console.log('" + key + "');"}) {
            var findings = CredentialBodyAnalyzer.analyze(body, "text/javascript", "response", null);
            assertTrue(!findings.isEmpty());
            assertTrue(findings.stream().allMatch(f ->
                    f.severity == com.b3xal.headeranalyzer.model.Severity.INFORMATION));
        }
    }

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
                null, "https://myaccount.example.com/i18n/resources.json").isEmpty());
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
    void ignoresPublicRecaptchaKeyUnderCommonJavascriptConfigName() {
        var findings = CredentialBodyAnalyzer.analyze(
                "var google_recaptcha_key = \"6LcEXAMPLE0publicrecaptchasitekey0demo00\";",
                "text/javascript", "response", null);

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
    void detectsOnlyNonTrivialCredentialBearingBrokerConnectionUrls() {
        String redis = "rediss://service:Q7%40mV1x9Np2K@cache.internal:6380/0";
        String amqp = "amqps://worker:S3cur3%21QueueToken@mq.internal:5671/vhost";
        String mariadb = "mariadb://app:DbSecret-9821@db.internal:3306/app";
        var findings = CredentialBodyAnalyzer.analyze(redis + " " + amqp + " " + mariadb,
                "text/plain", "response", null);

        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("Redis credential-bearing")));
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("AMQP credential-bearing")));
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("database connection string")));
    }

    @Test
    void ignoresDocumentedOrShortBrokerConnectionUrlExamples() {
        String examples = "redis://user:password@host:6379/0 "
                + "redis://myuser:mypassword@localhost:6379/0 "
                + "amqp://user:pass@host:5672/vhost "
                + "redis://user:ShortPwd1@cache.example.test:6379/0";
        var findings = CredentialBodyAnalyzer.analyze(examples, "text/plain", "response", null);

        assertTrue(findings.stream().noneMatch(f -> f.issueName.contains("credential-bearing connection URL")));
    }

    @Test
    void detectsEscapedDebugSettingFromAnyFrameworkButIgnoresMaskedPassword() {
        String revealed = "&#x27;PASSWORD&#x27;: &#x27;DjangoDbSecret-9427&#x27;";
        var finding = CredentialBodyAnalyzer.analyze(revealed, "text/html", "response", null).stream()
                .filter(f -> f.issueName.contains("Authentication secret embedded")).findFirst().orElseThrow();
        assertEquals("Response body: " + revealed, finding.evidence);

        String masked = "&#x27;PASSWORD&#x27;: &#x27;********************&#x27;";
        assertTrue(CredentialBodyAnalyzer.analyze(masked, "text/html", "response", null).isEmpty());
    }

    @Test
    void detectsCredentialInGenericHtmlSettingsTableButNotOrdinarySettings() {
        String passwordRow = "<tr><th data-name=\"secret\">DATABASE_PASSWORD</th><td class=\"value\">" +
                "PhpInfoDbSecret-9427</td></tr>";
        var findings = CredentialBodyAnalyzer.analyze(passwordRow, "text/html", "response", null);
        assertTrue(findings.stream().anyMatch(f -> f.issueName.contains("DATABASE_PASSWORD")));

        String ordinaryRows = "<tr><td class=\"e\">DATABASE_HOST</td><td class=\"v\">db.internal</td></tr>" +
                "<tr><td class=\"e\">DATABASE_PORT</td><td class=\"v\">5432</td></tr>";
        assertTrue(CredentialBodyAnalyzer.analyze(ordinaryRows, "text/html", "response", null).isEmpty());
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
