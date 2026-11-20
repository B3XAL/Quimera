package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtPersonalDataTest {
    private final CookiesAndAuthConfig config = new QuimeraSettings().cookiesAndAuthConfig();

    @Test
    void reportsAllDirectPersonalDataInOneFinding() {
        String token = token(Map.of(
                "iss", "https://login.example.test/realms/app", "sub", "person-123", "tenant_id", "tenant-a",
                "name", "Alice Example", "given_name", "Alice", "family_name", "Example",
                "email", "alice@example.test", "phone_number", "+34600111222", "birthdate", "1990-06-15",
                "address", Map.of("street_address", "1 Main Street", "locality", "Madrid", "country", "ES")));

        var finding = JwtAnalyzer.analyze(token, "Authorization", "Authorization: Bearer", config).stream()
                .filter(f -> f.issueName.equals(JwtAnalyzer.PERSONAL_DATA_ISSUE)).findFirst().orElseThrow();
        assertEquals(com.b3xal.headeranalyzer.model.Severity.LOW, finding.severity);
        for (String path : List.of("$.name", "$.given_name", "$.family_name", "$.email", "$.phone_number", "$.birthdate", "$.address"))
            assertTrue(finding.evidence.contains(path), path);
        assertFalse(finding.evidence.contains("$.sub"));
        assertTrue(finding.evidence.contains("$.tenant_id [stable identifier] = \"tenant-a\""));
        assertTrue(finding.evidence.contains("alice@example.test"));
        assertTrue(finding.evidence.contains("Alice Example"));
        assertTrue(finding.description.contains("- given name\n"));
        assertTrue(finding.description.contains("- full name\n"));
        assertTrue(finding.description.contains("- family name\n"));
    }

    @Test
    void doesNotTreatTechnicalIdentifiersAndRolesAsPersonalDataByThemselves() {
        String token = token(Map.of("iss", "https://login.example.test", "sub", "person-123", "tenant_id", "a",
                "sid", "session", "jti", "request", "authorities", List.of("admin"), "scope", "read write"));
        assertTrue(JwtAnalyzer.analyze(token, "Authorization", "Authorization: Bearer", config).stream()
                .noneMatch(f -> f.issueName.equals(JwtAnalyzer.PERSONAL_DATA_ISSUE)));
    }

    @Test
    void inventoriesReadableIdentityAndTenantMetadataWhenNoPersonalDataExists() {
        String token = token(Map.of("tenant_id", "tenant-a", "user_id", "user-123", "realm", "customers"));

        var finding = JwtAnalyzer.analyze(token, "Authorization", "Authorization: Bearer", config).stream()
                .filter(f -> f.issueName.equals(JwtAnalyzer.IDENTITY_METADATA_ISSUE)).findFirst().orElseThrow();

        assertEquals(com.b3xal.headeranalyzer.model.Severity.INFORMATION, finding.severity);
        assertTrue(finding.evidence.contains("$.tenant_id [stable identifier] = \"tenant-a\""));
        assertTrue(finding.evidence.contains("$.user_id [stable identifier] = \"user-123\""));
        assertTrue(finding.evidence.contains("$.realm [stable identifier] = \"customers\""));
    }

    @Test
    void fingerprintsRenewedTokensForSameSubjectButSeparatesOtherSubjects() {
        String first = token(Map.of("iss", "https://login.example.test", "sub", "person-123", "email", "a@example.test", "iat", 1));
        String renewed = token(Map.of("iss", "https://login.example.test", "sub", "person-123", "email", "a@example.test", "iat", 2));
        String other = token(Map.of("iss", "https://login.example.test", "sub", "person-456", "email", "b@example.test"));
        assertEquals(JwtAnalyzer.privacySubjectFingerprint(first), JwtAnalyzer.privacySubjectFingerprint(renewed));
        assertNotEquals(JwtAnalyzer.privacySubjectFingerprint(first), JwtAnalyzer.privacySubjectFingerprint(other));
    }

    @Test
    void doesNotUseNamesAsDeduplicationIdentity() {
        String first = token(Map.of("name", "Alice Example", "email", "a@example.test"));
        String second = token(Map.of("name", "Alice Example", "email", "a@example.test"));
        assertNull(JwtAnalyzer.privacySubjectFingerprint(first));
        assertNull(JwtAnalyzer.privacySubjectFingerprint(second));
    }

    private static String token(Map<String, Object> claims) {
        String header = encode(Map.of("alg", "RS256", "typ", "JWT"));
        return header + "." + encode(claims) + ".signature";
    }

    private static String encode(Map<String, Object> value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(JsonUtil.write(value).getBytes(StandardCharsets.UTF_8));
    }
}
