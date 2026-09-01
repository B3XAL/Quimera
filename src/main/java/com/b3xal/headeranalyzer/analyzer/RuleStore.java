package com.b3xal.headeranalyzer.analyzer;

import burp.api.montoya.persistence.PersistedObject;
import com.b3xal.headeranalyzer.util.JsonUtil;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Single source of truth for header/cookie detection rules.
 *
 * Seeds itself from {@link HeaderRules#all()} on first run (tagged builtin=true), then persists
 * the full rule set (builtin + user-created) to the extension's project data as JSON so edits
 * survive a Burp restart / extension reload. {@link HeaderAnalysisEngine} reads
 * {@link #effectiveRules()} on every analysis pass, so rule changes apply to new traffic immediately.
 */
public final class RuleStore {

    private static final String PERSIST_KEY = "quimera.rules.json";
    private static final String VERSION_KEY = "quimera.rules.version";

    private final PersistedObject persistence; // may be null (persistence unavailable / tests)
    private final List<RuleDefinition> rules = new CopyOnWriteArrayList<>();

    public RuleStore(PersistedObject persistence) {
        this.persistence = persistence;
        load();
    }

    // ------ Read ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public List<RuleDefinition> all() {
        return List.copyOf(rules);
    }

    /** Rules currently enabled, converted to the immutable objects the engine evaluates. */
    public List<HeaderRule> effectiveRules() {
        List<HeaderRule> out = new ArrayList<>();
        for (RuleDefinition rd : rules) {
            if (rd.enabled) {
                try { out.add(rd.toHeaderRule()); }
                catch (Exception ignored) { /* skip malformed custom rule rather than crash analysis */ }
            }
        }
        return out;
    }

    public Optional<RuleDefinition> byId(String id) {
        return rules.stream().filter(r -> r.id.equals(id)).findFirst();
    }

    // ------ Write ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public synchronized void add(RuleDefinition rd) {
        rules.add(rd);
        persist();
    }

    public synchronized void update(RuleDefinition updated) {
        for (int i = 0; i < rules.size(); i++) {
            if (rules.get(i).id.equals(updated.id)) { rules.set(i, updated); break; }
        }
        persist();
    }

    public synchronized void setEnabled(String id, boolean enabled) {
        byId(id).ifPresent(r -> r.enabled = enabled);
        persist();
    }

    public synchronized void delete(String id) {
        rules.removeIf(r -> r.id.equals(id) && !r.builtin);
        persist();
    }

    /** Restores the shipped default rule set, discarding all custom rules and edits. */
    public synchronized void resetToDefaults() {
        rules.clear();
        seedDefaults();
        persist();
    }

    // ------ Import / export ------------------------------------------------------------------------------------------------------------------------------------------------------------------

    public String exportJson() {
        List<Object> arr = new ArrayList<>();
        for (RuleDefinition rd : rules) arr.add(rd.toMap());
        return JsonUtil.write(arr);
    }

    /** Replaces the entire rule set with the contents of an exported JSON document. */
    public synchronized void importJson(String json) {
        List<Map<String, Object>> maps = JsonUtil.objectList(JsonUtil.parse(json));
        List<RuleDefinition> imported = new ArrayList<>();
        for (Map<String, Object> m : maps) imported.add(RuleDefinition.fromMap(m));
        if (imported.isEmpty()) throw new IllegalArgumentException("No rules found in file.");
        rules.clear();
        rules.addAll(imported);
        persist();
    }

    // ------ Persistence ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    private void load() {
        String json = null;
        try {
            if (persistence != null) json = persistence.getString(PERSIST_KEY);
        } catch (Exception ex) {
            // Persistence lookup itself failed (e.g. ephemeral/unsaved project), this must never
            // propagate out of the constructor, or the whole extension fails to initialize and
            // NOTHING gets registered (looks identical to "the extension just doesn't work").
            json = null;
        }
        if (json == null || json.isBlank()) {
            seedDefaults();
            persist();
            return;
        }
        try {
            List<Map<String, Object>> maps = JsonUtil.objectList(JsonUtil.parse(json));
            for (Map<String, Object> m : maps) rules.add(RuleDefinition.fromMap(m));
            if (rules.isEmpty()) seedDefaults();
        } catch (Exception ex) {
            // Corrupt persisted data, fall back to defaults rather than failing to load.
            rules.clear();
            seedDefaults();
        }

        if (persistedVersion() < HeaderRules.RULES_VERSION) {
            syncBuiltinsToLatest();
            persist();
        }
    }

    private void seedDefaults() {
        for (HeaderRule hr : HeaderRules.all()) {
            rules.add(RuleDefinition.fromHeaderRule(hr, true));
        }
    }

    /**
     * Re-seeds every builtin=true rule from the jar's current {@link HeaderRules#all()}, so a
     * jar update actually takes effect on an existing Burp project instead of being shadowed by
     * whatever was persisted on first run (see {@link HeaderRules#RULES_VERSION}). Each rule's
     * enabled/disabled toggle is preserved by matching on headerName; user-added custom rules
     * (builtin=false) are left completely untouched.
     */
    private void syncBuiltinsToLatest() {
        Map<String, Boolean> enabledByHeader = new HashMap<>();
        for (RuleDefinition rd : rules) {
            if (rd.builtin) enabledByHeader.put(rd.headerName, rd.enabled);
        }

        List<RuleDefinition> custom = new ArrayList<>();
        for (RuleDefinition rd : rules) {
            if (!rd.builtin) custom.add(rd);
        }

        rules.clear();
        for (HeaderRule hr : HeaderRules.all()) {
            RuleDefinition rd = RuleDefinition.fromHeaderRule(hr, true);
            rd.enabled = enabledByHeader.getOrDefault(hr.headerName, true);
            rules.add(rd);
        }
        rules.addAll(custom);
    }

    private int persistedVersion() {
        if (persistence == null) return HeaderRules.RULES_VERSION; // no persistence: nothing stale to sync
        try {
            String v = persistence.getString(VERSION_KEY);
            return v == null || v.isBlank() ? 0 : Integer.parseInt(v.trim());
        } catch (Exception ex) {
            return 0;
        }
    }

    private void persist() {
        if (persistence == null) return;
        try {
            persistence.setString(PERSIST_KEY, exportJson());
            persistence.setString(VERSION_KEY, String.valueOf(HeaderRules.RULES_VERSION));
        }
        catch (Exception ignored) { /* never let persistence errors break rule editing */ }
    }
}
