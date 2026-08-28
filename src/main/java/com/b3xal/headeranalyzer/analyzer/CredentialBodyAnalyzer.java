package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.model.*;
import com.b3xal.headeranalyzer.util.JsonUtil;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Bounded passive auth-only body discovery, informed by SensitiveDiscoverer's section-aware,
 * high-specificity pattern methodology (Apache-2.0), reimplemented for Quimera. */
public final class CredentialBodyAnalyzer {
    private CredentialBodyAnalyzer() {}
    private static final int MAX_BODY = 2_000_000;
    private static final int MAX_NODES = 500;
    /** A real quoted JSON/JS property, or a real unquoted JS identifier, followed by an assignment.
     * The two branches are deliberately separate: making the key quotes optional interpreted UI
     * strings such as createElement("label", null, "Password:") as assignments. Group 4 is the
     * value; group 0 is the exact evidence Burp should highlight. */
    private static final Pattern EMBEDDED_NAMED_CREDENTIAL = Pattern.compile(
            "(?i)(?:\\\\?[\"']([A-Za-z_$][A-Za-z0-9_$ .-]{0,80})\\\\?[\"']|" +
            "(?<![\"'A-Za-z0-9_$])([A-Za-z_$][A-Za-z0-9_$.-]{0,80}))" +
            "\\s*[:=]\\s*\\\\?([\"'])([^\"'\\r\\n]{1,2048}?)\\\\?\\3");

    private record Signature(String name, Pattern pattern, String reference) {}
    private static final List<Signature> SIGNATURES = List.of(
            new Signature("AWS access key ID", Pattern.compile("(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{16}(?![A-Z0-9])"), "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html"),
            new Signature("Google API key", Pattern.compile("(?<![0-9A-Za-z_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"), "https://cloud.google.com/docs/authentication/api-keys"),
            new Signature("Google OAuth access token", Pattern.compile("(?<![0-9A-Za-z_-])ya29\\.[0-9A-Za-z_-]{32,128}(?![0-9A-Za-z_-])"), "https://developers.google.com/identity/protocols/oauth2"),
            new Signature("GitHub token", Pattern.compile("(?<![0-9A-Za-z_])(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,255})(?![0-9A-Za-z_])"), "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github"),
            new Signature("Slack token", Pattern.compile("(?<![0-9A-Za-z-])x(?:ox[psboare]|app)(?:-[A-Za-z0-9]{1,128}){1,5}(?![0-9A-Za-z-])"), "https://api.slack.com/authentication/token-types"),
            new Signature("Slack incoming webhook", Pattern.compile("https://hooks\\.(?:slack|slack-gov)\\.com/(?:services/)?[A-Za-z0-9_-]{6,}/[A-Za-z0-9_-]{6,}/[A-Za-z0-9_-]{16,}"), "https://api.slack.com/messaging/webhooks"),
            new Signature("Stripe secret/restricted key", Pattern.compile("(?<![0-9A-Za-z_])[sr]k_(?:live|test)_[0-9A-Za-z]{24,128}(?![0-9A-Za-z])"), "https://docs.stripe.com/keys"),
            new Signature("SendGrid API key", Pattern.compile("(?<![0-9A-Za-z_-])SG\\.[0-9A-Za-z_-]{22}\\.[0-9A-Za-z_-]{43}(?![0-9A-Za-z_-])"), "https://www.twilio.com/docs/sendgrid/api-reference/how-to-use-the-sendgrid-v3-api/authentication"),
            new Signature("Google OAuth client secret", Pattern.compile("(?<![0-9A-Za-z_-])GOCSPX-[0-9A-Za-z_-]{28}(?![0-9A-Za-z_-])"), "https://developers.google.com/identity/protocols/oauth2"),
            new Signature("GitLab access/deploy/runner token", Pattern.compile("(?<![0-9A-Za-z])(?:glpat|gloas|gldt|glrt|glrtr|glcbt|glptt|glft|glimt|glagent|glwt)-[0-9A-Za-z_-]{16,255}(?![0-9A-Za-z])"), "https://docs.gitlab.com/security/tokens/#token-prefixes"),
            new Signature("Private key material", Pattern.compile("(?s)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\\s\\\\rn]+[A-Za-z0-9+/=\\s\\\\rn]{80,8192}-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns"),
            new Signature("Credential-bearing database connection string", Pattern.compile("(?i)(?:mongodb(?:\\+srv)?|postgres(?:ql)?|mysql)://[^\\s:/?#]+:[^\\s@/?#]{4,}@[^\\s/]+"), "https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns"),
            new Signature("Square OAuth/client secret", Pattern.compile("(?<![0-9A-Za-z_-])sq0[a-z]{3}-[0-9A-Za-z_-]{22,43}(?![0-9A-Za-z_-])"), "https://developer.squareup.com/docs/build-basics/access-tokens"),
            new Signature("Square access token", Pattern.compile("(?<![0-9A-Za-z])EAAA[0-9A-Za-z]{60}(?![0-9A-Za-z])"), "https://developer.squareup.com/docs/build-basics/access-tokens"),
            new Signature("Telegram bot token", Pattern.compile("(?<![0-9A-Za-z_-])[0-9]{6,12}:[0-9A-Za-z_-]{30,50}(?![0-9A-Za-z_-])"), "https://core.telegram.org/bots/api#authorizing-your-bot"),
            new Signature("Mailchimp API key", Pattern.compile("(?<![0-9a-f])[0-9a-f]{32}-us[0-9]{1,2}(?![0-9A-Za-z])", Pattern.CASE_INSENSITIVE), "https://mailchimp.com/developer/marketing/guides/quick-start/"),
            new Signature("New Relic API key", Pattern.compile("(?<![0-9A-Za-z-])NRAK-[0-9A-Z]{20,40}(?![0-9A-Za-z])"), "https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/"),
            new Signature("Instagram access token", Pattern.compile("(?<![0-9A-Za-z])(?:IGQVJ|EAA)[0-9A-Za-z_-]{40,300}(?![0-9A-Za-z_-])"), "https://developers.facebook.com/docs/instagram-platform/instagram-api-with-instagram-login/business-login"),
            new Signature("Zapier catch-hook URL", Pattern.compile("https://hooks\\.zapier\\.com/hooks/catch/[0-9A-Za-z_-]+/[0-9A-Za-z_-]+/?"), "https://help.zapier.com/hc/en-us/articles/8496292548877"),
            new Signature("Microsoft Teams/Power Automate webhook", Pattern.compile("https://[^\\s\"']{0,180}(?:webhook\\.office\\.com|outlook\\.office\\.com/webhook|logic\\.azure\\.com/workflows/)[^\\s\"']{16,1800}", Pattern.CASE_INSENSITIVE), "https://learn.microsoft.com/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook"),
            new Signature("Azure Storage SAS URL", Pattern.compile("https://[^\\s\"']{1,1800}[?&](?:sv|sp|sr|se)=[^\\s\"']{0,1000}[&]sig=[0-9A-Za-z%+/_=-]{16,}", Pattern.CASE_INSENSITIVE), "https://learn.microsoft.com/azure/storage/common/storage-sas-overview")
    );

    public static List<HeaderFinding> analyze(String body, String contentType, String location,
                                               CookiesAndAuthConfig config) {
        if (body == null || body.isBlank() || body.length() > MAX_BODY) return List.of();
        List<HeaderFinding> findings = new ArrayList<>();
        Set<String> structured = new LinkedHashSet<>();
        String ct = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        String trimmed = body.trim();
        if (ct.contains("json") || trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try { walk(JsonUtil.parse(trimmed), "$", 0, new int[]{0}, structured, body); }
            catch (RuntimeException ignored) { }
        } else if (ct.contains("application/x-www-form-urlencoded")) {
            for (String pair : body.split("&")) {
                int eq = pair.indexOf('=');
                if (eq <= 0) continue;
                String key = decode(pair.substring(0, eq));
                String value = decode(pair.substring(eq + 1));
                if (CredentialProviderCatalog.isCredentialField(key, body)
                        && credentialValue(key, value)) structured.add(key);
            }
        }
        if (!structured.isEmpty()) {
            findings.add(new HeaderFinding("Authentication material observed in structured " + location + " body",
                    "(" + location + " body)", String.join(", ", structured),
                    "The " + location + " body contains non-empty credential-shaped values under explicit " +
                            "authentication fields. This is passive inventory, not a vulnerability by itself.",
                    "Credential fields: " + String.join(", ", structured), Severity.INFORMATION,
                    Confidence.FIRM, HeaderFinding.Category.AUTH,
                    "https://github.com/CYS4srl/SensitiveDiscoverer"));
        }
        Set<String> reportedFields = new LinkedHashSet<>();
        List<int[]> namedMatchRanges = new ArrayList<>();
        if (location.equals("response")) {
            Matcher named = EMBEDDED_NAMED_CREDENTIAL.matcher(body);
            while (named.find() && reportedFields.size() < 12) {
                String field = named.group(1) != null ? named.group(1) : named.group(2);
                String value = named.group(4).trim();
                if (!CredentialProviderCatalog.isCredentialField(field, body)
                        || !credentialValue(field, value)
                        || (isGenericField(field) && !isHighEntropy(value))
                        || (field.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "").equals("privatekey")
                            && !looksLikePrivateKey(value))
                        || !reportedFields.add(field.toLowerCase(Locale.ROOT))) continue;
                String completeMatch = named.group();
                namedMatchRanges.add(new int[]{named.start(), named.end()});
                String technology = technologyHint(field, value, body);
                findings.add(new HeaderFinding(
                        "Authentication secret embedded in client-visible response: " + field,
                        "(response body)", completeMatch,
                        "Client-visible JavaScript/HTML contains a non-placeholder value assigned to the " +
                                "authentication field '" + field + "'. Browser-delivered code cannot keep a " +
                                "shared credential confidential. Confirm whether this is merely a public " +
                                "identifier or an authentication secret, and rotate it if it grants access. " +
                                "Technology hint: " + technology + ".",
                        "Response body: " + completeMatch,
                        Severity.LOW, Confidence.FIRM, HeaderFinding.Category.AUTH,
                        referenceForTechnology(technology)));
            }
        }
        // A JSON response is both structurally parsed and textually matched. Keep the actionable,
        // highlightable assignment finding, not a second informational row for the same material.
        if (!reportedFields.isEmpty()) {
            findings.removeIf(f -> f.issueName.equals(
                    "Authentication material observed in structured response body"));
        }
        Set<String> seen = new HashSet<>();
        for (Signature signature : SIGNATURES) {
            Matcher matcher = signature.pattern.matcher(body);
            String signatureMatch = null;
            while (matcher.find()) {
                if (overlapsNamedMatch(matcher.start(), matcher.end(), namedMatchRanges)
                        || isProviderPlaceholder(matcher.group())) continue;
                signatureMatch = matcher.group();
                break;
            }
            if (signatureMatch == null || !seen.add(signature.name)) continue;
            findings.add(new HeaderFinding(signature.name + " observed in " + location + " body",
                    "(" + location + " body)", signatureMatch,
                    "A high-specificity credential format was found in the " + location + " body. Verify " +
                            "whether its presence is expected and whether the credential is scoped and rotatable.",
                    "Matched " + signature.name + " format", location.equals("response") ? Severity.LOW : Severity.INFORMATION,
                    Confidence.FIRM, HeaderFinding.Category.AUTH, signature.reference));
        }
        return findings;
    }

    private static void walk(Object node, String path, int depth, int[] visited, Set<String> out,
                             String body) {
        if (node == null || depth > 8 || visited[0]++ > MAX_NODES) return;
        if (node instanceof Map<?,?> map) {
            for (var entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                Object value = entry.getValue();
                String next = path + "." + key;
                if (CredentialProviderCatalog.isCredentialField(key, body) && value instanceof String s
                        && credentialValue(key, s)) out.add(next);
                walk(value, next, depth + 1, visited, out, body);
            }
        } else if (node instanceof List<?> list) {
            for (int i = 0; i < list.size(); i++)
                walk(list.get(i), path + "[" + i + "]", depth + 1, visited, out, body);
        }
    }

    private static boolean credentialValue(String value) {
        if (value == null) return false;
        String trimmed = value.trim();
        String v = trimmed.toLowerCase(Locale.ROOT);
        if (trimmed.length() < 8 || Set.of("null", "undefined", "false", "true", "password",
                "changeme", "redacted", "masked", "not-set", "not_set").contains(v)) return false;
        if (trimmed.matches("[*•xX]{4,}") || trimmed.matches("(?i)[<\\[]?(?:redacted|masked|hidden|secret|token|password)[>\\]]?")) return false;
        if (trimmed.matches("(?:\\$\\{[^}]+}|\\{\\{[^}]+}}|%[^%]+%|<%[^%]+%>)")) return false;
        String compact = trimmed.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        if (compact.matches("0{8,}") || compact.matches("(?:abc|012|123){3,}.*")
                || compact.contains("abcdefghijklmnopqrstuvwxyz")
                || compact.contains("0123456789abcdef") || compact.contains("deadbeef")
                || compact.matches(".*(.)\\1{7,}.*")
                || (compact.length() >= 8 && compact.chars().distinct().count() < 3)) return false;
        return true;
    }
    private static boolean credentialValue(String field, String value) {
        if (!credentialValue(value)) return false;
        String normalizedField = field.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        String normalizedValue = value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        // Explicitly public browser credentials are identifiers/capability-limited publishable
        // keys, not secrets. Reporting them in Secrets/Credentials creates unactionable noise.
        String trimmed = value.trim();
        if (trimmed.matches("(?i)pk_(?:live|test)_[0-9a-z]+")
                || (normalizedField.contains("mapbox") && trimmed.startsWith("pk."))) return false;
        if (normalizedValue.equals(normalizedField)) return false;
        if (Set.of("authorizationcode", "accesstoken", "refreshtoken", "apikey", "clientsecret",
                "password", "passwd", "yourpassword", "yoursecret", "yourclientsecret", "example",
                "placeholder", "changeme", "replace", "replacehere", "xxxxxxxx").contains(normalizedValue)) return false;
        return !normalizedValue.matches("(?:your|insert|enter|replace|example|sample|dummy|test).*(?:key|token|secret|password).*");
    }
    private static boolean isGenericField(String field) {
        String normalized = field.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        return normalized.equals("secret") || normalized.equals("token");
    }
    private static boolean isProviderPlaceholder(String match) {
        if (match.startsWith("-----BEGIN ")) return false;
        String lower = match.toLowerCase(Locale.ROOT);
        return lower.contains("placeholder") || lower.contains("example") || lower.contains("your_api")
                || lower.contains("your-token") || lower.contains("your_token")
                || lower.matches(".*x{8,}.*")
                || lower.matches(".*([a-z0-9])\\1{11,}.*")
                || lower.matches(".*:(?:password|passwd|secret|changeme|redacted)@.*");
    }
    private static boolean overlapsNamedMatch(int start, int end, List<int[]> ranges) {
        for (int[] range : ranges) if (start < range[1] && end > range[0]) return true;
        return false;
    }
    private static boolean looksLikePrivateKey(String value) {
        return Pattern.compile("(?s)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----" +
                "[\\s\\\\rn]+[A-Za-z0-9+/=\\s\\\\rn]{80,8192}" +
                "-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").matcher(value).find();
    }
    private static String technologyHint(String field, String value, String body) {
        String normalizedField = field.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        for (Signature signature : SIGNATURES) {
            if (signature.pattern.matcher(value).find()) return technologyForSignature(signature.name);
        }
        Optional<CredentialProviderCatalog.Provider> provider =
                CredentialProviderCatalog.identify(field, body);
        if (provider.isPresent()) return provider.get().technology();
        if (normalizedField.equals("clientsecret")) return "OAuth/OIDC client credential";
        if (normalizedField.contains("password") || normalizedField.equals("passwd")
                || normalizedField.equals("pwd")) return "Application authentication";
        if (normalizedField.contains("privatekey")) return "Public-key authentication";
        return "Generic API/authentication credential (provider not identifiable from this match)";
    }
    private static String technologyForSignature(String signatureName) {
        if (signatureName.startsWith("AWS")) return "Amazon Web Services IAM";
        if (signatureName.startsWith("Google")) return "Google APIs / OAuth";
        if (signatureName.startsWith("GitHub")) return "GitHub";
        if (signatureName.startsWith("GitLab")) return "GitLab";
        if (signatureName.startsWith("Slack")) return "Slack";
        if (signatureName.startsWith("Stripe")) return "Stripe";
        if (signatureName.startsWith("SendGrid")) return "Twilio SendGrid";
        if (signatureName.startsWith("Private key")) return "Public-key authentication";
        if (signatureName.startsWith("Credential-bearing database")) return "Database client connection";
        if (signatureName.startsWith("Square")) return "Square";
        if (signatureName.startsWith("Telegram")) return "Telegram Bot API";
        if (signatureName.startsWith("Mailchimp")) return "Mailchimp";
        if (signatureName.startsWith("New Relic")) return "New Relic";
        if (signatureName.startsWith("Instagram")) return "Instagram";
        if (signatureName.startsWith("Zapier")) return "Zapier webhook";
        if (signatureName.startsWith("Microsoft Teams")) return "Microsoft Teams webhook";
        if (signatureName.startsWith("Azure Storage")) return "Microsoft Azure Storage SAS";
        return signatureName;
    }
    private static String referenceForTechnology(String technology) {
        Optional<String> providerReference = CredentialProviderCatalog.referenceForTechnology(technology);
        if (providerReference.isPresent()) return providerReference.get();
        if (technology.startsWith("OpenAI")) return "https://platform.openai.com/docs/api-reference/authentication";
        if (technology.equals("Twilio")) return "https://www.twilio.com/docs/usage/secure-credentials";
        if (technology.startsWith("npm")) return "https://docs.npmjs.com/about-access-tokens/";
        if (technology.equals("GitHub")) return "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github";
        if (technology.equals("GitLab")) return "https://docs.gitlab.com/security/tokens/";
        if (technology.equals("Stripe")) return "https://docs.stripe.com/keys";
        if (technology.equals("Slack")) return "https://api.slack.com/authentication/token-types";
        if (technology.startsWith("Twilio SendGrid")) return "https://www.twilio.com/docs/sendgrid/api-reference/how-to-use-the-sendgrid-v3-api/authentication";
        if (technology.startsWith("Google Cloud")) return "https://cloud.google.com/iam/docs/keys-create-delete";
        if (technology.startsWith("Google")) return "https://cloud.google.com/docs/authentication/api-keys";
        if (technology.startsWith("Amazon")) return "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html";
        return "https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1";
    }
    /** Shannon entropy is only a gate for ambiguous generic field names. Explicit authentication
     * fields retain context authority, so a valid low-entropy value such as clientSecret=gtmotive
     * is not incorrectly discarded. */
    private static boolean isHighEntropy(String value) {
        if (value == null || value.length() < 16) return false;
        Map<Character, Integer> frequencies = new HashMap<>();
        for (int i = 0; i < value.length(); i++) frequencies.merge(value.charAt(i), 1, Integer::sum);
        double entropy = 0.0;
        for (int count : frequencies.values()) {
            double probability = (double) count / value.length();
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy >= 3.5;
    }
    private static String decode(String value) {
        try { return URLDecoder.decode(value, StandardCharsets.UTF_8); }
        catch (IllegalArgumentException ex) { return value; }
    }
}
