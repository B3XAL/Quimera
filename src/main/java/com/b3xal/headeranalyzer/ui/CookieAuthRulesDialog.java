package com.b3xal.headeranalyzer.ui;

import burp.api.montoya.core.ToolType;
import com.b3xal.headeranalyzer.config.QuimeraSettings;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Modeless "Cookies & Auth Rules" dialog, opened from Settings. Everything CookieAnalyzer,
 * JwtAnalyzer and AuthHeaderAnalyzer hardcode (which checks run, and the built-in tracking-cookie/
 * session-keyword/API-key-header/query-token-param lists) lives here as live, per-check on/off
 * toggles plus "add your own on top of the built-ins" lists, so none of it needs a code change to
 * adapt to a specific target. A dedicated dialog rather than more inline Settings sections: this is
 * 11 checkboxes + 4 editable lists + the lifetime threshold, too much to stack into the
 * already multi-section Settings tab (same reasoning that gave Collaborator its own dialog).
 */
public final class CookieAuthRulesDialog extends JDialog {

    private final QuimeraSettings settings;

    // Request-derived auth/token analysis only. Response Set-Cookie checks remain source-agnostic.
    private final Map<ToolType, JCheckBox> authToolChecks = new LinkedHashMap<>();

    // ------ Cookies ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    private final JCheckBox cookieFlagChecksChk = new JCheckBox("Secure / HttpOnly / SameSite / __Secure-/__Host- prefix checks");
    private final JCheckBox cookieLifetimeChk   = new JCheckBox("Long-lived session cookie check (Max-Age / Expires vs. threshold below)");
    private final JCheckBox cookieTrackingSkipChk = new JCheckBox("Skip known tracking/analytics cookies (GA, Meta, Hotjar, Cloudflare, Matomo, ...)");
    private final JTextArea extraTrackingArea = new JTextArea(4, 24);
    private final JTextArea extraSessionArea  = new JTextArea(4, 24);

    // ------ JWT ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    private final JCheckBox jwtEnabledChk    = new JCheckBox("JWT recognition (master switch, disables all JWT checks below)");
    private final JCheckBox jwtAlgNoneChk    = new JCheckBox("Flag alg: none (unsigned token accepted)");
    private final JCheckBox jwtNoExpiryChk   = new JCheckBox("Flag missing exp claim (token never expires)");
    private final JCheckBox jwtLifetimeChk   = new JCheckBox("Flag lifetime exceeding threshold (exp - iat, see below)");
    private final JCheckBox jwtActiveProbeChk = new JCheckBox(
            "ACTIVE: automatically test alg:none + bad-signature bypass on every distinct JWT seen (sends forged requests, OFF by default)");

    // ------ Other tokens ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    private final JCheckBox basicAuthChk     = new JCheckBox("HTTP Basic Authentication recognition");
    private final JCheckBox bearerChk        = new JCheckBox("Authorization: Bearer recognition (opaque + JWT)");
    private final JCheckBox apiKeyHeaderChk  = new JCheckBox("API-key header recognition (X-Api-Key, X-Auth-Token, ...)");
    private final JCheckBox queryStringChk   = new JCheckBox("Token-in-URL-query-string recognition");
    private final JCheckBox webStorageChk    = new JCheckBox("localStorage/sessionStorage recognition (JWT, cookie duplication, known SDK signatures, opaque tokens)");
    private final JTextArea extraApiKeyHeadersArea = new JTextArea(4, 24);
    private final JTextArea extraQueryParamsArea   = new JTextArea(4, 24);

    // ------ Shared lifetime threshold ------------------------------------------------------------------------------------------------------------------------------------
    private final JSpinner maxLifetimeSpinner =
            new JSpinner(new SpinnerNumberModel(QuimeraSettings.DEFAULT_MAX_TOKEN_LIFETIME_MINUTES, 1, 100_000, 5));

    private final JLabel statusLabel = new JLabel(" ");

    public CookieAuthRulesDialog(Window owner, QuimeraSettings settings) {
        super(owner, "Quimera - Cookies & Auth Rules", ModalityType.MODELESS);
        this.settings = settings;
        build();
        loadFromSettings();
        setSize(680, 740);
        setLocationRelativeTo(owner);
    }

    private void build() {
        JPanel root = new JPanel();
        root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
        root.setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));

        // Plain wrapping JTextArea, not an HTML JLabel: Burp's look-and-feel sets the Swing
        // "html.disable" UIManager flag process-wide (same lesson already learned in LoggerPanel/
        // CookiePanel's tooltips), so a <html>...</html>-wrapped JLabel here rendered the raw tag
        // characters to the user instead of wrapping anything.
        JTextArea intro = new JTextArea("Security checks are enabled by default. Choose which high-signal Burp traffic " +
                "sources may feed request credentials, or add your own entries on top of the built-in lists.");
        intro.setEditable(false);
        intro.setFocusable(false);
        intro.setOpaque(false);
        intro.setLineWrap(true);
        intro.setWrapStyleWord(true);
        intro.setAlignmentX(Component.LEFT_ALIGNMENT);
        intro.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        intro.setFont(intro.getFont().deriveFont(11f));
        intro.setForeground(new Color(110, 120, 135));
        root.add(intro);
        root.add(vgap(12));

        root.add(sectionLabel("Traffic sources for request auth/token analysis"));
        JTextArea sourceDesc = new JTextArea(
                "Only these Burp sources feed URL tokens, Authorization/API-key/JWT request checks " +
                "and credential correlation. Response Set-Cookie security checks still run for every " +
                "enabled source. Defaults: Proxy, Repeater and Target / Discovery; Scanner, Intruder " +
                "and Extensions stay off to avoid probe noise.");
        sourceDesc.setEditable(false);
        sourceDesc.setFocusable(false);
        sourceDesc.setOpaque(false);
        sourceDesc.setLineWrap(true);
        sourceDesc.setWrapStyleWord(true);
        sourceDesc.setAlignmentX(Component.LEFT_ALIGNMENT);
        sourceDesc.setMaximumSize(new Dimension(Integer.MAX_VALUE, 58));
        sourceDesc.setFont(sourceDesc.getFont().deriveFont(11f));
        sourceDesc.setForeground(new Color(110, 120, 135));
        root.add(sourceDesc);
        JPanel sourceGrid = new JPanel(new GridLayout(0, 3, 8, 4));
        sourceGrid.setAlignmentX(Component.LEFT_ALIGNMENT);
        // Keep the meaningful HTTP sources explicit and in a predictable order. In particular,
        // Repeater must remain visible next to Proxy: it is one of the three high-signal defaults,
        // while iterating the whole enum made the useful choices easy to miss among Burp internals.
        for (ToolType tool : List.of(ToolType.PROXY, ToolType.REPEATER, ToolType.TARGET,
                ToolType.INTRUDER, ToolType.SCANNER, ToolType.EXTENSIONS)) {
            String label = tool == ToolType.TARGET ? tool.toolName() + " / Discovery" : tool.toolName();
            JCheckBox check = new JCheckBox(label);
            authToolChecks.put(tool, check);
            sourceGrid.add(check);
        }
        sourceGrid.setMaximumSize(new Dimension(Integer.MAX_VALUE, sourceGrid.getPreferredSize().height));
        root.add(sourceGrid);
        root.add(vgap(16));

        root.add(sectionLabel("Cookies"));
        addChk(root, cookieFlagChecksChk);
        addChk(root, cookieLifetimeChk);
        addChk(root, cookieTrackingSkipChk);
        root.add(vgap(6));
        root.add(listRow("Extra tracking-cookie name prefixes to also skip (one per line):", extraTrackingArea));
        root.add(vgap(6));
        root.add(listRow("Extra session/auth-cookie name keywords (one per line, gates the lifetime check):", extraSessionArea));
        root.add(vgap(16));

        root.add(sectionLabel("JWT"));
        addChk(root, jwtEnabledChk);
        addChk(root, jwtAlgNoneChk);
        addChk(root, jwtNoExpiryChk);
        addChk(root, jwtLifetimeChk);
        root.add(vgap(6));
        jwtActiveProbeChk.setForeground(new Color(180, 95, 0));
        addChk(root, jwtActiveProbeChk);
        JLabel jwtActiveProbeDesc = new JLabel(
                "Unlike every check above, this sends real forged-authentication requests at the target " +
                "(once per distinct token, automatically, the instant this is on). Also toggled together with " +
                "Settings' Auto Active Scan switch. Confirm you're authorized to test this target.");
        jwtActiveProbeDesc.setAlignmentX(Component.LEFT_ALIGNMENT);
        jwtActiveProbeDesc.setFont(jwtActiveProbeDesc.getFont().deriveFont(11f));
        jwtActiveProbeDesc.setForeground(new Color(110, 120, 135));
        root.add(jwtActiveProbeDesc);
        root.add(vgap(16));

        root.add(sectionLabel("Other tokens"));
        addChk(root, basicAuthChk);
        addChk(root, bearerChk);
        addChk(root, apiKeyHeaderChk);
        addChk(root, queryStringChk);
        addChk(root, webStorageChk);
        root.add(vgap(6));
        root.add(listRow("Extra API-key header names to also recognize (one per line):", extraApiKeyHeadersArea));
        root.add(vgap(6));
        root.add(listRow("Extra URL query-string parameter names to also treat as tokens (one per line):", extraQueryParamsArea));
        root.add(vgap(16));

        root.add(sectionLabel("Shared lifetime threshold"));
        JPanel lifetimeRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        lifetimeRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        lifetimeRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        lifetimeRow.add(new JLabel("Flag session cookies/JWTs whose lifetime exceeds:"));
        lifetimeRow.add(maxLifetimeSpinner);
        lifetimeRow.add(new JLabel("minutes"));
        root.add(lifetimeRow);
        JLabel lifetimeDesc = new JLabel("Used by both the cookie long-lifetime check and the JWT lifetime check above. Default 60 (1 hour).");
        lifetimeDesc.setAlignmentX(Component.LEFT_ALIGNMENT);
        lifetimeDesc.setFont(lifetimeDesc.getFont().deriveFont(11f));
        lifetimeDesc.setForeground(new Color(110, 120, 135));
        root.add(lifetimeDesc);
        root.add(vgap(16));

        JButton applyBtn = new JButton("Apply");
        JButton closeBtn = new JButton("Close");
        applyBtn.addActionListener(e -> apply());
        closeBtn.addActionListener(e -> setVisible(false));
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC, 11f));
        statusLabel.setForeground(Color.GRAY);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        btnRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        btnRow.add(applyBtn);
        btnRow.add(closeBtn);
        btnRow.add(statusLabel);
        root.add(btnRow);

        setLayout(new BorderLayout());
        add(new JScrollPane(root), BorderLayout.CENTER);
    }

    private void addChk(JPanel root, JCheckBox chk) {
        chk.setAlignmentX(Component.LEFT_ALIGNMENT);
        root.add(chk);
    }

    private JPanel listRow(String label, JTextArea area) {
        JPanel p = new JPanel(new BorderLayout());
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 90));
        p.add(new JLabel(label), BorderLayout.NORTH);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        p.add(new JScrollPane(area), BorderLayout.CENTER);
        return p;
    }

    private static JLabel sectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 12f));
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setBorder(BorderFactory.createEmptyBorder(6, 0, 6, 0));
        return l;
    }

    private static Component vgap(int h) { return Box.createRigidArea(new Dimension(0, h)); }

    /** Re-reads current Settings into every field, called on construction and again each time the
     * dialog is reopened (it's lazily created once and reused, so without this a "Reset to
     * Defaults" in the main Settings tab wouldn't be reflected here until Burp restarts). */
    public void loadFromSettings() {
        Set<String> enabledAuthTools = settings.getCookiesAuthTools();
        authToolChecks.forEach((tool, check) -> check.setSelected(enabledAuthTools.contains(tool.name())));

        cookieFlagChecksChk.setSelected(settings.isCookieFlagChecksEnabled());
        cookieLifetimeChk.setSelected(settings.isCookieLifetimeCheckEnabled());
        cookieTrackingSkipChk.setSelected(settings.isCookieTrackingSkipEnabled());
        extraTrackingArea.setText(String.join("\n", settings.getExtraTrackingCookiePrefixes()));
        extraSessionArea.setText(String.join("\n", settings.getExtraSessionCookieKeywords()));

        jwtEnabledChk.setSelected(settings.isJwtEnabled());
        jwtAlgNoneChk.setSelected(settings.isJwtAlgNoneCheckEnabled());
        jwtNoExpiryChk.setSelected(settings.isJwtNoExpiryCheckEnabled());
        jwtLifetimeChk.setSelected(settings.isJwtLifetimeCheckEnabled());
        jwtActiveProbeChk.setSelected(settings.isJwtActiveProbeEnabled());

        basicAuthChk.setSelected(settings.isBasicAuthEnabled());
        bearerChk.setSelected(settings.isBearerEnabled());
        apiKeyHeaderChk.setSelected(settings.isApiKeyHeaderEnabled());
        queryStringChk.setSelected(settings.isQueryStringTokenEnabled());
        webStorageChk.setSelected(settings.isWebStorageCheckEnabled());
        extraApiKeyHeadersArea.setText(String.join("\n", settings.getExtraApiKeyHeaders()));
        extraQueryParamsArea.setText(String.join("\n", settings.getExtraQueryTokenParams()));

        maxLifetimeSpinner.setValue(settings.getMaxTokenLifetimeMinutes());
    }

    private void apply() {
        Set<String> enabledAuthTools = new LinkedHashSet<>();
        authToolChecks.forEach((tool, check) -> {
            if (check.isSelected()) enabledAuthTools.add(tool.name());
        });
        settings.setCookiesAuthTools(enabledAuthTools);

        settings.setCookieFlagChecksEnabled(cookieFlagChecksChk.isSelected());
        settings.setCookieLifetimeCheckEnabled(cookieLifetimeChk.isSelected());
        settings.setCookieTrackingSkipEnabled(cookieTrackingSkipChk.isSelected());
        settings.setExtraTrackingCookiePrefixes(splitLines(extraTrackingArea.getText()));
        settings.setExtraSessionCookieKeywords(splitLines(extraSessionArea.getText()));

        settings.setJwtEnabled(jwtEnabledChk.isSelected());
        settings.setJwtAlgNoneCheckEnabled(jwtAlgNoneChk.isSelected());
        settings.setJwtNoExpiryCheckEnabled(jwtNoExpiryChk.isSelected());
        settings.setJwtLifetimeCheckEnabled(jwtLifetimeChk.isSelected());
        settings.setJwtActiveProbeEnabled(jwtActiveProbeChk.isSelected());

        settings.setBasicAuthEnabled(basicAuthChk.isSelected());
        settings.setBearerEnabled(bearerChk.isSelected());
        settings.setApiKeyHeaderEnabled(apiKeyHeaderChk.isSelected());
        settings.setQueryStringTokenEnabled(queryStringChk.isSelected());
        settings.setWebStorageCheckEnabled(webStorageChk.isSelected());
        settings.setExtraApiKeyHeaders(splitLines(extraApiKeyHeadersArea.getText()));
        settings.setExtraQueryTokenParams(splitLines(extraQueryParamsArea.getText()));

        settings.setMaxTokenLifetimeMinutes((Integer) maxLifetimeSpinner.getValue());
        statusLabel.setText("Applied.");
    }

    private static List<String> splitLines(String text) {
        List<String> out = new ArrayList<>();
        for (String line : text.split("\\r?\\n")) {
            String t = line.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }
}
