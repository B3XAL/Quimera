package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.config.CookiesAndAuthConfig;
import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;
import com.b3xal.headeranalyzer.util.JsonUtil;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static com.b3xal.headeranalyzer.model.Confidence.*;
import static com.b3xal.headeranalyzer.model.Severity.*;

/**
 * JWT recognition, modeled on the methodology of PortSwigger's json-web-tokens (token detection,
 * see {@link AuthHeaderAnalyzer} for where it looks) and jwt-scanner extensions (read directly from
 * source, see CREDITS.md), but deliberately RECOGNITION ONLY: structural validation, claim
 * inspection (algorithm, expiry), nothing that forges, strips, or replays a token. jwt-scanner's own
 * {@code checks/Checks.java} draws exactly this line, everything from CheckExpiredJwtAccepted
 * onward (signature stripping, alg confusion, JKU/JWK injection) actively replays/forges and has no
 * equivalent here, only its {@code CheckJwtExists}/{@code CheckAlg}/{@code CheckJwtHasExpiry}/
 * {@code CheckJwtExpired} shape survived the port.
 *
 * No JWT/JSON library dependency needed, base64url-decodes the header/payload segments by hand and
 * parses them with the project's existing {@link JsonUtil} (already used by RuleStore), the project
 * ships as a single dependency-free fat jar on purpose.
 */
public final class JwtAnalyzer {

    private JwtAnalyzer() {}

    private static final Pattern BASE64URL_SEGMENT = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Pattern EMAIL = Pattern.compile(
            "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$", Pattern.CASE_INSENSITIVE);
    private static final Pattern PHONE = Pattern.compile(
            "^(?:\\+[1-9][0-9]{7,14}|\\+?[0-9]{2,4}[ .()-][0-9 .()-]{5,18})$");
    private static final int MAX_CLAIM_DEPTH = 6;
    private static final int MAX_CLAIMS = 200;

    /**
     * Structural + decode check: exactly 3 base64url segments, and the first one decodes to JSON
     * containing 'alg' or 'typ'. Dot-count alone is too cheap (plenty of dotted strings would
     * match), requiring a real decoded JOSE header is what both reference extensions actually do
     * (attempt decode, catch failure) rather than trusting the shape alone.
     */
    public static boolean looksLikeJwt(String value) {
        if (value == null) return false;
        String[] parts = value.trim().split("\\.", -1);
        if (parts.length != 3) return false;
        if (parts[0].isEmpty() || parts[1].isEmpty()
                || !BASE64URL_SEGMENT.matcher(parts[0]).matches()
                || !BASE64URL_SEGMENT.matcher(parts[1]).matches()) return false;
        Map<String, Object> header = decodeSegment(parts[0]);
        if (header == null || !(header.containsKey("alg") || header.containsKey("typ"))) return false;
        if (!parts[2].isEmpty()) return BASE64URL_SEGMENT.matcher(parts[2]).matches();
        // Compact JWS with alg:none conventionally has an empty signature segment. Do not allow
        // that relaxed shape for any signed algorithm, otherwise arbitrary "header.payload."
        // strings would become JWT candidates and increase passive noise.
        return "none".equalsIgnoreCase(JsonUtil.str(header, "alg", ""));
    }

    /**
     * @param token               the raw JWT (three dot-separated segments)
     * @param headerName          where it was found, for the finding's headerName field (e.g.
     *                            "Authorization", "Cookie")
     * @param sourceLabel         human-readable description of where it was found, for evidence
     *                            text (e.g. "Authorization: Bearer", "Cookie: session")
     * @param config              from Settings (Cookies & Auth Rules), gates each individual check
     *                            and carries the exp-iat lifetime threshold
     */
    public static List<HeaderFinding> analyze(String token, String headerName, String sourceLabel,
                                               CookiesAndAuthConfig config) {
        List<HeaderFinding> findings = new ArrayList<>();
        if (!config.jwtEnabled) return findings;
        if (token == null) return findings;
        String[] parts = token.trim().split("\\.", -1);
        if (parts.length != 3) return findings;

        Map<String, Object> header  = decodeSegment(parts[0]);
        Map<String, Object> payload = decodeSegment(parts[1]);
        if (header == null || payload == null) return findings;

        String alg = JsonUtil.str(header, "alg", "unknown");
        String typ = JsonUtil.str(header, "typ", null);

        // JWT detected — inventory item. Claim NAMES only in the evidence, not values, avoid
        // dumping session identity/PII into a finding just to note that a token exists.
        String claimNames = String.join(", ", payload.keySet());
        findings.add(f(INFORMATION, CERTAIN, headerName,
            "JWT detected (" + sourceLabel + ")",
            "A JSON Web Token was observed in " + sourceLabel + ". Algorithm: " + alg +
            (typ != null ? ", type: " + typ : "") + ". Claims present: " +
            (claimNames.isEmpty() ? "(none)" : claimNames) + ". This is an inventory finding, not a " +
            "vulnerability by itself, see the other findings on this same token for actual issues.",
            sourceLabel + ": " + token, token));

        if (config.jwtAlgNoneCheckEnabled && alg.equalsIgnoreCase("none")) {
            findings.add(f(MEDIUM, FIRM, headerName,
                "Unsigned JWT observed (alg: none)",
                "This observed JWT declares 'alg: none' and therefore carries no JWS signature. That is a " +
                "suspicious authentication configuration, but observing a server-issued token does not prove " +
                "that an attacker-modified unsigned token would be accepted. Use Quimera's opt-in JWT active " +
                "probe to test acceptance before reporting an authentication bypass.",
                sourceLabel + ": " + token, token, "https://portswigger.net/web-security/jwt"));
        }

        // OWASP JWT Cheat Sheet: validate 'aud' (audience) and 'iss' (issuer) so a token issued
        // for one service can't be replayed against another that shares the same signing key.
        // Purely an inventory/hygiene note (INFORMATION, not a confirmed vuln): Quimera can only
        // see whether the CLAIM exists in the token, not whether the server actually enforces it,
        // plenty of single-service apps have no real need for either claim.
        boolean hasAud = payload.containsKey("aud");
        boolean hasIss = payload.containsKey("iss");
        if (!hasAud || !hasIss) {
            String missing = !hasAud && !hasIss ? "'aud' and 'iss'" : !hasAud ? "'aud'" : "'iss'";
            findings.add(f(INFORMATION, CERTAIN, headerName,
                "JWT missing audience/issuer claim",
                "This JWT has no " + missing + " claim. Without 'aud', a token issued for one service can be " +
                "replayed against any other service that trusts the same signing key/JWKS; without 'iss', a " +
                "relying party can't confirm which authority actually issued the token. Only actionable if " +
                "the server doesn't separately enforce this some other way, add " + missing + " if this token " +
                "is meant to be scoped to a specific service.",
                sourceLabel + ": " + token, token, "https://www.rfc-editor.org/rfc/rfc8725#section-3.9"));
        }

        Object expRaw = payload.get("exp");
        Object iatRaw = payload.get("iat");
        Object nbfRaw = payload.get("nbf");
        Double exp = numClaim(payload, "exp");
        Double iat = numClaim(payload, "iat");
        Double nbf = numClaim(payload, "nbf");
        long nowEpoch = System.currentTimeMillis() / 1000L;

        findings.addAll(temporalTypeFindings(token, headerName, sourceLabel,
                expRaw, iatRaw, nbfRaw));

        if (exp != null && iat != null && exp <= iat) {
            findings.add(f(LOW, CERTAIN, headerName,
                    "JWT expiration is not after issuance",
                    "The JWT has exp=" + formatEpoch(exp) + " and iat=" + formatEpoch(iat) +
                    ", so its declared expiration is at or before its issuance. This is internally " +
                    "inconsistent and commonly indicates a broken token-lifetime configuration.",
                    sourceLabel + ": exp=" + formatEpoch(exp) + ", iat=" + formatEpoch(iat), token));
        }
        if (exp != null && nbf != null && nbf > exp) {
            findings.add(f(LOW, CERTAIN, headerName,
                    "JWT not-before time is after expiration",
                    "The JWT has nbf=" + formatEpoch(nbf) + " after exp=" + formatEpoch(exp) +
                    ", leaving no valid time window in which the token should be accepted.",
                    sourceLabel + ": nbf=" + formatEpoch(nbf) + ", exp=" + formatEpoch(exp), token));
        }
        if (iat != null && iat > nowEpoch + 300) {
            findings.add(f(LOW, FIRM, headerName,
                    "JWT issuance time is in the future",
                    "The JWT's iat claim is more than five minutes in the future relative to when Quimera " +
                    "observed it. This can indicate clock skew or incorrect token validation/configuration.",
                    sourceLabel + ": iat=" + formatEpoch(iat) + ", observed=" + nowEpoch, token));
        }

        if (exp == null) {
            if (config.jwtNoExpiryCheckEnabled) {
                findings.add(f(LOW, FIRM, headerName,
                    "JWT has no expiration claim",
                    "This JWT has no 'exp' claim, so the token itself declares no expiration. Passive " +
                    "inspection cannot determine whether the server enforces a separate session timeout or " +
                    "revocation policy. If this is an authentication token, add a short, appropriate exp claim " +
                    "and verify server-side expiry rather than assuming indefinite acceptance from this finding.",
                    sourceLabel + ": " + token, token));
            }
        } else {
            long expEpoch = exp.longValue();
            if (expEpoch < nowEpoch) {
                findings.add(f(INFORMATION, FIRM, headerName,
                    "Expired JWT observed in traffic",
                    "This JWT's 'exp' claim is in the past relative to when Quimera observed it. Noted for " +
                    "completeness, this by itself isn't a vulnerability (could simply be stale Repeater/" +
                    "Proxy history), it's only actionable if the SERVER still accepts this specific token, " +
                    "which this passive check does not test.",
                    sourceLabel + ": " + token, token));
            } else if (config.jwtLifetimeCheckEnabled) {
                long baselineEpoch = iat != null ? iat.longValue() : nowEpoch;
                long lifetimeMinutes = (expEpoch - baselineEpoch) / 60;
                if (lifetimeMinutes > config.maxLifetimeMinutes) {
                    findings.add(f(MEDIUM, FIRM, headerName,
                        "JWT lifetime exceeds configured threshold",
                        "This JWT is valid for " + formatMinutes(lifetimeMinutes) + ", longer than the " +
                        formatMinutes(config.maxLifetimeMinutes) + " threshold configured in Settings " +
                        "(Cookies & Auth). A longer-lived token widens the exposure window if it's ever " +
                        "stolen. Adjust the threshold in Settings if this lifetime is intentional for this " +
                        "application, or shorten the token's actual lifetime server-side.",
                        sourceLabel + ": " + token, token));
                }
            }
        }

        findings.addAll(sensitiveClaimFindings(token, headerName, sourceLabel, payload));

        return findings;
    }

    private record SensitiveClaim(String path, String category, Object value, int risk) {}

    private static List<HeaderFinding> sensitiveClaimFindings(String token, String headerName,
                                                               String sourceLabel, Map<String, Object> payload) {
        List<SensitiveClaim> claims = new ArrayList<>();
        int[] visited = {0};
        collectSensitive(payload, "$", 0, visited, claims);
        if (claims.isEmpty()) return List.of();

        // A claim may match by both name and value (for example an `email` key containing an email
        // address). Keep one line per path, selecting the highest-risk classification.
        Map<String, SensitiveClaim> byPath = new java.util.LinkedHashMap<>();
        for (SensitiveClaim claim : claims) {
            SensitiveClaim old = byPath.get(claim.path);
            if (old == null || claim.risk > old.risk) byPath.put(claim.path, claim);
        }

        int maxRisk = byPath.values().stream().mapToInt(SensitiveClaim::risk).max().orElse(0);
        StringBuilder evidence = new StringBuilder(sourceLabel).append(" contains:\n");
        Set<String> categories = new LinkedHashSet<>();
        for (SensitiveClaim claim : byPath.values()) {
            categories.add(claim.category);
            evidence.append("- ").append(claim.path).append(" [").append(claim.category)
                    .append("] (value redacted)\n");
        }

        Severity severity = maxRisk >= 3 ? LOW : INFORMATION;
        Confidence confidence = maxRisk >= 3 ? FIRM : CERTAIN;
        String issue = maxRisk >= 3
                ? "JWT contains high-risk personal data or embedded secrets"
                : maxRisk == 2
                    ? "JWT contains privacy-sensitive claims"
                    : "JWT contains detailed authorization/profile claims";
        String description = "The JWT payload exposes " + String.join(", ", categories) +
                " data in readable claims. A signed JWS provides integrity, not confidentiality: anyone who " +
                "obtains the token can decode these values. Confirm every claim is required by the recipient " +
                "and remove unnecessary personal, financial, identifier, authorization, or secret material. " +
                "The evidence lists complete claim values as configured; avoid exporting it beyond the " +
                "authorized assessment.";
        return List.of(f(severity, confidence, headerName, issue, description,
                evidence.toString().trim(), token,
                "https://www.rfc-editor.org/rfc/rfc7519#section-12"));
    }

    private static void collectSensitive(Object node, String path, int depth, int[] visited,
                                         List<SensitiveClaim> out) {
        if (node == null || depth > MAX_CLAIM_DEPTH || visited[0]++ >= MAX_CLAIMS) return;
        if (node instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                Object value = entry.getValue();
                String childPath = path + "." + key;
                classifyClaim(key, childPath, value, out);
                collectSensitive(value, childPath, depth + 1, visited, out);
            }
        } else if (node instanceof List<?> list) {
            for (int i = 0; i < list.size(); i++) {
                collectSensitive(list.get(i), path + "[" + i + "]", depth + 1, visited, out);
            }
        } else if (node instanceof String) {
            // Array string leaves have no property name to classify, but strong self-validating
            // formats (email, E.164-ish phone, DNI/NIE checksum, IBAN mod-97, Luhn PAN) remain
            // meaningful. Reuse the value-only half of classifyClaim with an empty key.
            classifyClaim("", path, node, out);
        }
    }

    private static void classifyClaim(String rawKey, String path, Object value, List<SensitiveClaim> out) {
        String key = normalizeKey(rawKey);
        String string = value instanceof String s ? s.trim() : null;

        if (containsAny(key, "password", "passwd", "clientsecret", "apisecret", "apikey",
                "privatekey", "credential", "secret")) {
            out.add(new SensitiveClaim(path, "embedded secret", value, 3));
            return;
        }
        if (containsAny(key, "dni", "nif", "nie", "passport", "ssn", "socialsecurity",
                "nationalid", "taxid", "fiscalid")) {
            out.add(new SensitiveClaim(path, "official identifier", value, 3));
            return;
        }
        if (containsAny(key, "iban", "bankaccount") || key.equals("pan") || key.contains("cardnumber")) {
            if (string == null || isValidIban(string) || isValidLuhn(string)) {
                out.add(new SensitiveClaim(path, "financial data", value, 3));
            }
            return;
        }
        if (containsAny(key, "email", "phonenumber", "mobile", "telephone", "address",
                "birthdate", "dateofbirth", "firstname", "lastname", "givenname", "familyname")
                || key.equals("name") || key.equals("username")) {
            out.add(new SensitiveClaim(path, "identity/contact", value, 2));
            return;
        }
        if (containsAny(key, "roles", "groups", "permissions", "authorities") || key.equals("scope")) {
            out.add(new SensitiveClaim(path, "authorization context", value, 1));
            return;
        }

        // Custom claim name, but a strong value format still reveals what it contains. Checksums
        // avoid treating every random identifier-looking string as official/financial data.
        if (string != null) {
            if (EMAIL.matcher(string).matches() || PHONE.matcher(string).matches()) {
                out.add(new SensitiveClaim(path, "identity/contact", value, 2));
            } else if (isValidSpanishId(string)) {
                out.add(new SensitiveClaim(path, "official identifier", value, 3));
            } else if (isValidIban(string) || isValidLuhn(string)) {
                out.add(new SensitiveClaim(path, "financial data", value, 3));
            }
        }
    }

    private static List<HeaderFinding> temporalTypeFindings(String token, String headerName,
                                                             String sourceLabel, Object exp,
                                                             Object iat, Object nbf) {
        List<HeaderFinding> findings = new ArrayList<>();
        addInvalidNumericDate(findings, token, headerName, sourceLabel, "exp", exp);
        addInvalidNumericDate(findings, token, headerName, sourceLabel, "iat", iat);
        addInvalidNumericDate(findings, token, headerName, sourceLabel, "nbf", nbf);
        return findings;
    }

    private static void addInvalidNumericDate(List<HeaderFinding> findings, String token,
                                               String headerName, String sourceLabel,
                                               String name, Object value) {
        if (value == null || value instanceof Number) return;
        findings.add(f(LOW, CERTAIN, headerName,
                "JWT " + name + " claim has an invalid type",
                "The JWT's '" + name + "' claim must be a NumericDate, but the observed value is " +
                "not numeric. Validators may reject it or process it inconsistently.",
                sourceLabel + ": " + name + "=" + JsonUtil.write(value), token));
    }

    private static String normalizeKey(String key) {
        return key.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }

    private static boolean containsAny(String value, String... needles) {
        for (String needle : needles) if (value.contains(needle)) return true;
        return false;
    }

    private static boolean isValidSpanishId(String raw) {
        String value = raw.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]", "");
        if (!value.matches("(?:[0-9]{8}|[XYZ][0-9]{7})[A-Z]")) return false;
        char prefix = value.charAt(0);
        String digits = switch (prefix) {
            case 'X' -> "0" + value.substring(1, 8);
            case 'Y' -> "1" + value.substring(1, 8);
            case 'Z' -> "2" + value.substring(1, 8);
            default -> value.substring(0, 8);
        };
        String letters = "TRWAGMYFPDXBNJZSQVHLCKE";
        return letters.charAt(Integer.parseInt(digits) % 23) == value.charAt(8);
    }

    private static boolean isValidIban(String raw) {
        String iban = raw.toUpperCase(Locale.ROOT).replaceAll("\\s", "");
        if (!iban.matches("[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}")) return false;
        String rearranged = iban.substring(4) + iban.substring(0, 4);
        int remainder = 0;
        for (int i = 0; i < rearranged.length(); i++) {
            char c = rearranged.charAt(i);
            String digits = Character.isDigit(c) ? String.valueOf(c) : String.valueOf(c - 'A' + 10);
            for (int j = 0; j < digits.length(); j++) remainder = (remainder * 10 + digits.charAt(j) - '0') % 97;
        }
        return remainder == 1;
    }

    private static boolean isValidLuhn(String raw) {
        String digits = raw.replaceAll("[ -]", "");
        if (!digits.matches("[0-9]{13,19}")) return false;
        int sum = 0;
        boolean twice = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int n = digits.charAt(i) - '0';
            if (twice && (n *= 2) > 9) n -= 9;
            sum += n;
            twice = !twice;
        }
        return sum % 10 == 0;
    }

    private static String formatEpoch(Double value) {
        return String.valueOf(value.longValue());
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private static Map<String, Object> decodeSegment(String segment) {
        try {
            Object parsed = JsonUtil.parse(base64UrlDecode(segment));
            return parsed instanceof Map<?, ?> m ? (Map<String, Object>) m : null;
        } catch (Exception ex) {
            return null;
        }
    }

    private static String base64UrlDecode(String segment) {
        StringBuilder padded = new StringBuilder(segment);
        int rem = padded.length() % 4;
        if (rem == 2) padded.append("==");
        else if (rem == 3) padded.append('=');
        else if (rem == 1) throw new IllegalArgumentException("Invalid base64url segment length");
        byte[] bytes = Base64.getUrlDecoder().decode(padded.toString());
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static Double numClaim(Map<String, Object> m, String key) {
        Object v = m.get(key);
        return v instanceof Number n ? n.doubleValue() : null;
    }

    private static String formatMinutes(long minutes) {
        if (minutes < 60) return minutes + "m";
        long hours = minutes / 60;
        if (hours < 48) return hours + "h";
        return (hours / 24) + "d";
    }

    private static HeaderFinding f(Severity sev, Confidence conf, String headerName,
                                    String issueName, String description, String evidence, String value) {
        return new HeaderFinding(issueName, headerName, value, description, evidence, sev, conf, Category.AUTH);
    }

    private static HeaderFinding f(Severity sev, Confidence conf, String headerName,
                                    String issueName, String description, String evidence, String value,
                                    String referenceUrl) {
        return new HeaderFinding(issueName, headerName, value, description, evidence, sev, conf, Category.AUTH, referenceUrl);
    }
}
