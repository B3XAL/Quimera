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
            new Signature("Azure Storage SAS URL", Pattern.compile("https://[^\\s\"']{1,1800}[?&](?:sv|sp|sr|se)=[^\\s\"']{0,1000}[&]sig=[0-9A-Za-z%+/_=-]{16,}", Pattern.CASE_INSENSITIVE), "https://learn.microsoft.com/azure/storage/common/storage-sas-overview"),
            // Four providers already carried in CredentialProviderCatalog by field-name/context
            // only (a suggestively-named field like "twilioAuthToken" was needed to flag them);
            // these add the same high-specificity value-shape detection the other signatures
            // above already have, so the bare secret is caught even embedded in a minified
            // variable or error message with no helpful field name nearby. Formats confirmed
            // against each vendor's own docs, and all four are separately listed as recognised
            // partner secret types in GitHub's own secret-scanning reference (confirms these are
            // real, standardized shapes, not something only Quimera looks for).
            new Signature("Twilio Account SID", Pattern.compile("(?<![0-9A-Za-z])AC[0-9a-fA-F]{32}(?![0-9A-Za-z])"), "https://www.twilio.com/docs/glossary/what-is-a-sid"),
            new Signature("OpenAI project API key", Pattern.compile("(?<![0-9A-Za-z_-])sk-proj-[A-Za-z0-9_-]{74,200}(?![0-9A-Za-z_-])"), "https://platform.openai.com/docs/api-reference/authentication"),
            new Signature("Shopify access token", Pattern.compile("(?<![0-9A-Za-z_])shp(?:at|ss|ca|ua)_[0-9A-Za-z]{32,64}(?![0-9A-Za-z_])"), "https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens"),
            new Signature("npm access token", Pattern.compile("(?<![0-9A-Za-z_])npm_[0-9A-Za-z]{36}(?![0-9A-Za-z_])"), "https://docs.npmjs.com/about-access-tokens/"),
            // Compared against TruffleHog's own detector list (884 providers, fetched from its
            // GitHub repo) at the user's request: these are the auth/identity-relevant and
            // commonly-web-embedded providers with a genuinely distinctive, safely-regexable
            // prefix that CredentialProviderCatalog didn't have at all before this pass. Each
            // format confirmed against the vendor's own docs (see individual reference URLs).
            new Signature("DigitalOcean personal access token", Pattern.compile("(?<![0-9A-Za-z_])dop_v1_[0-9a-f]{64}(?![0-9A-Za-z_])"), "https://docs.digitalocean.com/reference/api/create-personal-access-token/"),
            new Signature("Docker Hub access token", Pattern.compile("(?<![0-9A-Za-z_-])dckr_pat_[0-9A-Za-z_-]{20,80}(?![0-9A-Za-z_-])"), "https://docs.docker.com/security/access-tokens/"),
            new Signature("PlanetScale service token", Pattern.compile("(?<![0-9A-Za-z_-])pscale_tkn_[0-9A-Za-z]{40,60}(?![0-9A-Za-z_-])"), "https://planetscale.com/docs/concepts/planetscale-connect"),
            new Signature("Sentry auth token", Pattern.compile("(?<![0-9A-Za-z_-])sntrys_[0-9A-Za-z_-]{40,100}(?![0-9A-Za-z_-])"), "https://docs.sentry.io/account/auth-tokens/"),
            new Signature("Notion integration token", Pattern.compile("(?<![0-9A-Za-z_])(?:secret_[0-9A-Za-z]{43}|ntn_[0-9A-Za-z]{40,60})(?![0-9A-Za-z_])"), "https://developers.notion.com/docs/authorization"),
            new Signature("Figma personal access token", Pattern.compile("(?<![0-9A-Za-z_-])figd_[0-9A-Za-z_-]{35,50}(?![0-9A-Za-z_-])"), "https://developers.figma.com/docs/rest-api/personal-access-tokens/"),
            new Signature("Cloudinary API URL", Pattern.compile("cloudinary://[0-9]{10,20}:[0-9A-Za-z_-]{20,40}@[0-9a-z-]{2,60}"), "https://cloudinary.com/documentation/solution_overview"),
            // Anchored to the mandatory "SSWS " auth-scheme prefix (Okta's own documented
            // Authorization header format), not just the bare "00"+40-char token: without that
            // context, a value merely starting with "00" is far too common to safely flag alone.
            new Signature("Okta API token", Pattern.compile("(?<![0-9A-Za-z_-])SSWS\\s+00[0-9A-Za-z_-]{40}(?![0-9A-Za-z_-])"), "https://developer.okta.com/docs/guides/create-an-api-token/main/"),
            new Signature("Discord webhook URL", Pattern.compile("https://discord(?:app)?\\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z_-]{60,90}"), "https://discord.com/developers/docs/topics/oauth2")
    );

    public static List<HeaderFinding> analyze(String body, String contentType, String location,
                                               CookiesAndAuthConfig config) {
        return analyze(body, contentType, location, config, null);
    }

    public static List<HeaderFinding> analyze(String body, String contentType, String location,
                                               CookiesAndAuthConfig config, String sourceUrl) {
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
                        && credentialValue(key, value, body)) structured.add(key);
            }
        }
        // A password/access-token field in an HTTPS request body is ordinary authentication
        // transport, not a vulnerability or leak. The old INFORMATION inventory flooded login
        // endpoints (e.g. {"password":"..."}) and exposed submitted passwords in findings.
        // Keep structured-field reporting response-only; provider-specific high-confidence
        // signatures below remain independently detectable in either direction.
        boolean localizationResource = isLocalizationResource(sourceUrl);
        if (!structured.isEmpty() && location.equals("response") && !localizationResource) {
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
        if (location.equals("response") && !localizationResource) {
            Matcher named = EMBEDDED_NAMED_CREDENTIAL.matcher(body);
            while (named.find() && reportedFields.size() < 12) {
                String field = named.group(1) != null ? named.group(1) : named.group(2);
                String value = named.group(4).trim();
                if (!CredentialProviderCatalog.isCredentialField(field, body)
                        || !credentialValue(field, value, body)
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

    /** Localization dictionaries routinely use credential-shaped source keys with translated UI
     * labels as values: {"Password":"Contraseña"}. Classify by resource purpose instead of trying
     * to enumerate every translation in every language. Provider-specific signatures are scanned
     * later regardless, so a real high-specificity secret in such a file remains visible. */
    private static boolean isLocalizationResource(String sourceUrl) {
        if (sourceUrl == null || sourceUrl.isBlank()) return false;
        String path;
        try {
            path = java.net.URI.create(sourceUrl).getPath();
        } catch (RuntimeException ignored) {
            path = sourceUrl.split("[?#]", 2)[0];
        }
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT).replace('\\', '/');
        return lower.matches(".*/(?:i18n|l10n|locales?|translations?|languages?|lang)(?:/|$).*")
                || lower.matches(".*/(?:messages|strings|resources)(?:[._-][a-z]{2,}(?:-[a-z]{2,})?)?\\.json$");
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
                        && credentialValue(key, s, body)) out.add(next);
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
        // Some responses are decoded with the wrong legacy charset before reaching an extension
        // (UTF-8 "Contraseña" becomes "ContraseÃ±a"). Canonicalize that common mojibake for
        // placeholder/UI-label comparison only; retain the original value for actual credential
        // checks and evidence.
        String v = repairUtf8Mojibake(trimmed).toLowerCase(Locale.ROOT);
        if (trimmed.length() < 8 || Set.of("null", "undefined", "false", "true", "password",
                "passwd", "contraseña", "contrasena", "contrasenya", "changeme", "redacted", "masked",
                "not-set", "not_set").contains(v)) return false;
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

    private static String repairUtf8Mojibake(String value) {
        if (value == null || (!value.contains("Ã") && !value.contains("Â"))) return value;
        try {
            String repaired = new String(value.getBytes(StandardCharsets.ISO_8859_1),
                    StandardCharsets.UTF_8);
            // Only accept a repair that removed the tell-tale markers; arbitrary Unicode text
            // must not be transformed merely because it contains one of these characters.
            return !repaired.contains("Ã") && !repaired.contains("Â") ? repaired : value;
        } catch (RuntimeException ignored) {
            return value;
        }
    }
    private static boolean credentialValue(String field, String value, String context) {
        if (!credentialValue(value)) return false;
        String normalizedField = field.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        String normalizedValue = value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        // Cloudflare Web Analytics deliberately embeds this 32-hex site identifier in the public
        // data-cf-beacon snippet. It is not a Cloudflare API bearer token. Require the complete
        // official beacon context so real API tokens elsewhere remain visible.
        String contextLower = context == null ? "" : context.toLowerCase(Locale.ROOT);
        if (normalizedField.equals("token") && value.trim().matches("(?i)[0-9a-f]{32}")
                && contextLower.contains("data-cf-beacon")
                && contextLower.contains("static.cloudflareinsights.com/beacon.min.js")) return false;
        // reCAPTCHA site keys are deliberately embedded in client-side HTML/JavaScript. Google
        // distinguishes them from the server-side secret key, which must remain confidential.
        // Keep this exclusion narrow: both a site-key field and reCAPTCHA context are required;
        // secretKey and high-specificity credential signatures remain reportable.
        String bodyLower = contextLower;
        boolean recaptchaSiteKeyField = normalizedField.equals("sitekey")
                || normalizedField.equals("datasitekey")
                || normalizedField.equals("recaptchasitekey")
                || normalizedField.equals("grecaptchasitekey");
        if (recaptchaSiteKeyField && (normalizedField.contains("recaptcha")
                || bodyLower.contains("recaptcha"))) return false;
        // templateKey is a template/rendering identifier, not an authentication credential.
        // Minified expressions such as templateKey:"+this.qh.sh+" previously looked opaque
        // enough to pass the generic key heuristic and were incorrectly attributed to Google.
        // A real AIza/GOCSPX signature is still detected independently by SIGNATURES below.
        if (normalizedField.equals("templatekey")) return false;
        if (value.matches("(?is).*\\b(?:this|window|document)\\.[A-Za-z_$][A-Za-z0-9_$.]*.*"))
            return false;
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
        if (signatureName.startsWith("Twilio")) return "Twilio";
        if (signatureName.startsWith("OpenAI")) return "OpenAI API";
        if (signatureName.startsWith("Shopify")) return "Shopify";
        if (signatureName.startsWith("npm")) return "npm registry";
        if (signatureName.startsWith("DigitalOcean")) return "Digital Ocean";
        if (signatureName.startsWith("Docker Hub")) return "Docker Hub";
        if (signatureName.startsWith("PlanetScale")) return "PlanetScale";
        if (signatureName.startsWith("Sentry")) return "Sentry";
        if (signatureName.startsWith("Notion")) return "Notion";
        if (signatureName.startsWith("Figma")) return "Figma";
        if (signatureName.startsWith("Cloudinary")) return "Cloudinary";
        if (signatureName.startsWith("Okta")) return "Okta";
        if (signatureName.startsWith("Discord")) return "Discord";
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
