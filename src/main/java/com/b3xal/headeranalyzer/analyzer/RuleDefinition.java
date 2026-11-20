package com.b3xal.headeranalyzer.analyzer;

import com.b3xal.headeranalyzer.model.Confidence;
import com.b3xal.headeranalyzer.model.HeaderFinding.Category;
import com.b3xal.headeranalyzer.model.Severity;

import java.util.*;

/**
 * Serializable, editable form of a {@link HeaderRule}. This is what the Rules tab shows/edits
 * and what gets persisted to disk; {@link #toHeaderRule()} converts it into the immutable
 * runtime object the analysis engine actually evaluates.
 */
public class RuleDefinition {

    public String id;                 // stable identifier, survives edits
    public String headerName;
    public boolean enabled = true;
    public boolean builtin = false;   // true = shipped default, seeded from HeaderRules.all()

    public boolean mandatory = false;
    public String missingIssueName;
    public String missingDescription;
    public Severity missingSeverity;
    public Confidence missingConfidence;
    public Category missingCategory;
    public String missingReferenceUrl;

    public final List<CheckDefinition> checks = new ArrayList<>();

    public RuleDefinition() {
        this.id = UUID.randomUUID().toString();
    }

    public static class CheckDefinition {
        public String regex = "";
        public FieldCheck.TriggerOn triggerOn = FieldCheck.TriggerOn.MATCH;
        public String issueName = "";
        public String description = "";
        public Severity severity = Severity.LOW;
        public Confidence confidence = Confidence.FIRM;
        public Category category = Category.CUSTOM;
        public String referenceUrl;

        public CheckDefinition() {}

        public CheckDefinition(String regex, FieldCheck.TriggerOn triggerOn, String issueName,
                                String description, Severity severity, Confidence confidence,
                                Category category) {
            this.regex       = regex;
            this.triggerOn   = triggerOn;
            this.issueName   = issueName;
            this.description = description;
            this.severity    = severity;
            this.confidence  = confidence;
            this.category    = category;
        }

        FieldCheck toFieldCheck() {
            return new FieldCheck(regex, triggerOn, issueName, description, severity, confidence, category,
                    referenceUrl);
        }

        static CheckDefinition fromFieldCheck(FieldCheck fc) {
            CheckDefinition definition = new CheckDefinition(fc.regex, fc.triggerOn, fc.issueName,
                    fc.description, fc.severity, fc.confidence, fc.category);
            definition.referenceUrl = fc.referenceUrl;
            return definition;
        }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("regex", regex);
            m.put("triggerOn", triggerOn.name());
            m.put("issueName", issueName);
            m.put("description", description);
            m.put("severity", severity.name());
            m.put("confidence", confidence.name());
            m.put("category", category.name());
            m.put("referenceUrl", referenceUrl);
            return m;
        }

        static CheckDefinition fromMap(Map<String, Object> m) {
            CheckDefinition c = new CheckDefinition();
            c.regex       = str(m, "regex", "");
            c.triggerOn   = FieldCheck.TriggerOn.valueOf(str(m, "triggerOn", "MATCH"));
            c.issueName   = str(m, "issueName", "");
            c.description = str(m, "description", "");
            c.severity    = Severity.valueOf(str(m, "severity", "LOW"));
            c.confidence  = Confidence.valueOf(str(m, "confidence", "FIRM"));
            c.category    = Category.valueOf(str(m, "category", "CUSTOM"));
            c.referenceUrl = str(m, "referenceUrl", null);
            return c;
        }
    }

    // ------ Conversion to/from the immutable engine rule ------------------------------------------------------------------------------------

    public HeaderRule toHeaderRule() {
        List<FieldCheck> fcs = new ArrayList<>();
        for (CheckDefinition c : checks) fcs.add(c.toFieldCheck());
        return new HeaderRule(headerName, mandatory, missingIssueName, missingDescription,
                missingSeverity, missingConfidence, missingCategory, fcs, missingReferenceUrl);
    }

    public static RuleDefinition fromHeaderRule(HeaderRule hr, boolean builtin) {
        RuleDefinition rd = new RuleDefinition();
        rd.headerName        = hr.headerName;
        rd.builtin            = builtin;
        rd.mandatory          = hr.mandatory;
        rd.missingIssueName   = hr.missingIssueName;
        rd.missingDescription = hr.missingDescription;
        rd.missingSeverity    = hr.missingSeverity;
        rd.missingConfidence  = hr.missingConfidence;
        rd.missingCategory    = hr.missingCategory;
        rd.missingReferenceUrl = hr.missingReferenceUrl;
        for (FieldCheck fc : hr.checks) rd.checks.add(CheckDefinition.fromFieldCheck(fc));
        return rd;
    }

    // ------ JSON (de)serialization ---------------------------------------------------------------------------------------------------------------------------------------------------------

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("headerName", headerName);
        m.put("enabled", enabled);
        m.put("builtin", builtin);
        m.put("mandatory", mandatory);
        m.put("missingIssueName", missingIssueName);
        m.put("missingDescription", missingDescription);
        m.put("missingSeverity", missingSeverity != null ? missingSeverity.name() : null);
        m.put("missingConfidence", missingConfidence != null ? missingConfidence.name() : null);
        m.put("missingCategory", missingCategory != null ? missingCategory.name() : null);
        m.put("missingReferenceUrl", missingReferenceUrl);
        List<Object> checkMaps = new ArrayList<>();
        for (CheckDefinition c : checks) checkMaps.add(c.toMap());
        m.put("checks", checkMaps);
        return m;
    }

    @SuppressWarnings("unchecked")
    public static RuleDefinition fromMap(Map<String, Object> m) {
        RuleDefinition rd = new RuleDefinition();
        rd.id                 = str(m, "id", UUID.randomUUID().toString());
        rd.headerName         = str(m, "headerName", "");
        rd.enabled            = bool(m, "enabled", true);
        rd.builtin            = bool(m, "builtin", false);
        rd.mandatory          = bool(m, "mandatory", false);
        rd.missingIssueName   = str(m, "missingIssueName", null);
        rd.missingDescription = str(m, "missingDescription", null);
        String sev = str(m, "missingSeverity", null);
        rd.missingSeverity    = sev != null ? Severity.valueOf(sev) : null;
        String conf = str(m, "missingConfidence", null);
        rd.missingConfidence  = conf != null ? Confidence.valueOf(conf) : null;
        String cat = str(m, "missingCategory", null);
        rd.missingCategory    = cat != null ? Category.valueOf(cat) : null;
        rd.missingReferenceUrl = str(m, "missingReferenceUrl", null);
        Object checksObj = m.get("checks");
        if (checksObj instanceof List<?> list) {
            for (Object o : list) {
                if (o instanceof Map<?, ?> cm) rd.checks.add(CheckDefinition.fromMap((Map<String, Object>) cm));
            }
        }
        return rd;
    }

    private static String str(Map<String, Object> m, String key, String def) {
        Object v = m.get(key);
        return v instanceof String s ? s : def;
    }

    private static boolean bool(Map<String, Object> m, String key, boolean def) {
        Object v = m.get(key);
        return v instanceof Boolean b ? b : def;
    }
}
