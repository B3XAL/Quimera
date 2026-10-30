package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding;
import com.b3xal.headeranalyzer.model.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Conservative response-header inventory for explicit identity, tenant, authorization and IdP
 * metadata. This intentionally does not infer meaning from generic identifiers or tracing IDs. */
final class IdentityMetadataAnalyzer {
    private IdentityMetadataAnalyzer() {}

    private enum Kind {
        IDENTITY("Identity metadata exposed in response header", "identity metadata"),
        TENANCY("Tenant or organization metadata exposed in response header", "tenant or organization metadata"),
        AUTHORIZATION("Authorization context exposed in response header", "authorization context"),
        IDENTITY_PROVIDER("Identity-provider metadata exposed in response header", "identity-provider metadata");

        final String issue, label;
        Kind(String issue, String label) { this.issue = issue; this.label = label; }
    }

    private static final Set<String> IDENTITY = Set.of(
            "userid", "xuserid", "accountid", "xaccountid", "customerid", "xcustomerid",
            "memberid", "xmemberid", "employeeid", "xemployeeid", "principalid", "xprincipalid",
            "authenticateduser", "xauthenticateduser", "xauthuser", "useremail", "xuseremail",
            "username", "xusername");
    private static final Set<String> TENANCY = Set.of(
            "tenant", "xtenant", "tenantid", "xtenantid", "organization", "xorganization",
            "organizationid", "xorganizationid", "orgid", "xorgid", "workspaceid", "xworkspaceid",
            "projectid", "xprojectid", "companyid", "xcompanyid", "realm", "xrealm",
            "namespace", "xnamespace");
    private static final Set<String> AUTHORIZATION = Set.of(
            "roles", "xroles", "userroles", "xuserroles", "authorities", "xauthorities",
            "permissions", "xpermissions", "entitlements", "xentitlements", "groups", "xgroups",
            "usergroups", "xusergroups", "authscopes", "xauthscopes", "oauthscopes", "xoauthscopes");
    private static final Set<String> IDENTITY_PROVIDER = Set.of(
            "clientid", "xclientid", "authclientid", "xauthclientid", "identityprovider",
            "xidentityprovider", "idp", "xidp", "authprovider", "xauthprovider");
    private static final Set<String> PLACEHOLDERS = Set.of("null", "undefined", "unknown", "none", "n/a",
            "redacted", "masked", "hidden", "not-set", "not_set");

    static List<HeaderFinding> analyzeResponseHeaders(Map<String, String> responseHeaders,
                                                       Map<String, String> requestHeaders) {
        if (responseHeaders == null || responseHeaders.isEmpty()) return List.of();
        List<HeaderFinding> findings = new ArrayList<>();
        for (Map.Entry<String, String> entry : responseHeaders.entrySet()) {
            String name = entry.getKey();
            String value = entry.getValue();
            Kind kind = kindFor(name);
            if (kind == null || !reportableValue(value) || reflectedRequestValue(name, value, requestHeaders)) continue;
            String observed = value.trim();
            findings.add(new HeaderFinding(kind.issue, name, observed,
                    "The response includes explicit " + kind.label + ". This is an informational " +
                            "inventory finding, not a vulnerability by itself; it can be useful when reviewing " +
                            "unnecessary client-visible identity data, tenant isolation, or authorization design.",
                    name + ": " + observed, Severity.INFORMATION, Confidence.CERTAIN,
                    HeaderFinding.Category.INFORMATION_DISCLOSURE));
        }
        return findings;
    }

    private static Kind kindFor(String headerName) {
        if (headerName == null) return null;
        String normalized = headerName.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
        if (IDENTITY.contains(normalized)) return Kind.IDENTITY;
        if (TENANCY.contains(normalized)) return Kind.TENANCY;
        if (AUTHORIZATION.contains(normalized)) return Kind.AUTHORIZATION;
        return IDENTITY_PROVIDER.contains(normalized) ? Kind.IDENTITY_PROVIDER : null;
    }

    private static boolean reportableValue(String value) {
        if (value == null) return false;
        String trimmed = value.trim();
        return !trimmed.isEmpty() && trimmed.length() <= 2_048
                && !PLACEHOLDERS.contains(trimmed.toLowerCase(Locale.ROOT));
    }

    private static boolean reflectedRequestValue(String responseName, String responseValue,
                                                 Map<String, String> requestHeaders) {
        if (requestHeaders == null || requestHeaders.isEmpty() || responseName == null) return false;
        for (Map.Entry<String, String> entry : requestHeaders.entrySet()) {
            if (responseName.equalsIgnoreCase(entry.getKey()) && responseValue.trim().equals(
                    entry.getValue() == null ? "" : entry.getValue().trim())) return true;
        }
        return false;
    }
}
