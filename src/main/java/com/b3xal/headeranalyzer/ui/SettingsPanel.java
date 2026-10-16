package com.b3xal.headeranalyzer.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import com.b3xal.headeranalyzer.config.QuimeraSettings;

import static com.b3xal.headeranalyzer.ui.render.ScrollUtil.scrollPane;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.BooleanSupplier;

/**
 * Settings tab: what Quimera listens to passively, how captured results are displayed,
 * what the active scan probes do, and which file/content-type skip lists apply.
 */
public final class SettingsPanel extends JPanel {

    private final MontoyaApi api;
    private final QuimeraSettings settings;
    private final Runnable onApplied; // fired after every successful Apply, lets QuimeraTab react (e.g. the Report-tab easter egg)
    private final Runnable onBrowserBridgeApplied; // fired after Browser Bridge dialog Apply, restarts the bridge server
    private final BooleanSupplier browserBridgeRunning; // reads the bridge server's real bound-socket state
    private CollaboratorDialog collaboratorDialog; // lazily created, reused across opens
    private CookieAuthRulesDialog cookieAuthRulesDialog; // lazily created, reused across opens
    private BrowserBridgeDialog browserBridgeDialog; // lazily created, reused across opens
    /** Prevents programmatic UI refreshes from looking like a user deliberately switched Auto
     * Active Scan on, which would re-enable probes they had individually opted out of. */
    private boolean syncingAutoActiveScan;

    private final JTextArea skipExtArea = new JTextArea(6, 30);
    private final JTextArea skipCtArea  = new JTextArea(6, 30);
    private final JTextArea suppressedHeadersArea = new JTextArea(4, 30);

    private final java.util.Map<ToolType, JCheckBox> toolChecks = new java.util.LinkedHashMap<>();
    private final JCheckBox restrictScopeChk    = new JCheckBox("Restrict automatic analysis to Burp scope");
    private final JCheckBox contextMenuScopeChk = new JCheckBox("Also require Burp scope for explicit active context-menu actions");

    private final JCheckBox autoActiveScanChk = new JCheckBox("Enable auto active scan");
    private final JLabel autoActiveScanBadge  = new JLabel();
    private final JCheckBox optionsProbeChk = new JCheckBox("OPTIONS + Origin reflection (CORS misconfiguration test)");
    private final JCheckBox traceProbeChk   = new JCheckBox("TRACE method probe (Cross-Site Tracing / XST)");
    private final JCheckBox hstsProbeChk    = new JCheckBox("HTTP→HTTPS downgrade probe (HSTS enforcement check)");
    private final JCheckBox webDavProbeChk  = new JCheckBox("OPTIONS WebDAV probe (DAV/MS-Author-Via disclosure)");
    private final JCheckBox googleApiProbeChk = new JCheckBox(
            "Probe exposed Google API keys once per unique key (read-only; may consume quota)");
    // Independent of autoActiveScanChk (see QuimeraHttpHandler#responseReceived, it's its own
    // separate `if`, not nested under isAutoActiveScan()), same mirrored setting as
    // CookieAuthRulesDialog's own jwtActiveProbeChk, surfaced here too since this is where an
    // analyst actually looks for "what does active scanning do", not the Cookie/Auth rules editor.
    private final JCheckBox headerInfluenceProbeChk = new JCheckBox(
            "Header reflection / response control / disclosure (separate worker; GET/HEAD, 2xx/3xx)");
    private final JSpinner headerInfluenceDelay = new JSpinner(new SpinnerNumberModel(333, 250, Integer.MAX_VALUE, 50));
    private final JCheckBox jwtProbeChk = new JCheckBox("JWT active probe (forge alg:none / bad-signature tokens)");
    private final JCheckBox sessionProbeChk = new JCheckBox("Session invalidation probe (replay stale cookie/Bearer token after logout)");
    private final JCheckBox externalEvidenceArchiveChk = new JCheckBox("Store full finding evidence in a local external archive");
    private final JTextField externalEvidenceDirectory = new JTextField();

    private final JLabel statusLabel = new JLabel(" ");
    /** Kept outside the scroll pane: saving must remain available after navigating a long form. */
    private final JButton applyBtn = new JButton("Apply");
    private final JButton resetBtn = new JButton("Reset to Defaults");
    private Color normalApplyForeground;
    private boolean loadingSettings;

    public SettingsPanel(MontoyaApi api, QuimeraSettings settings, Runnable onApplied) {
        this(api, settings, onApplied, () -> {}, () -> false);
    }

    public SettingsPanel(MontoyaApi api, QuimeraSettings settings, Runnable onApplied,
                          Runnable onBrowserBridgeApplied, BooleanSupplier browserBridgeRunning) {
        super(new BorderLayout());
        this.api        = api;
        this.settings   = settings;
        this.onApplied  = onApplied;
        this.onBrowserBridgeApplied = onBrowserBridgeApplied;
        this.browserBridgeRunning = browserBridgeRunning;
        build();
        loadFromSettings();
    }

    private void build() {
        JPanel root = new JPanel();
        root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
        root.setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));

        root.add(sectionLabel("Passive listening, which Burp tools feed Quimera"));
        JPanel toolsGrid = new JPanel(new GridLayout(0, 3, 8, 4));
        toolsGrid.setAlignmentX(LEFT_ALIGNMENT);
        for (ToolType t : ToolType.values()) {
            JCheckBox cb = new JCheckBox(t.toolName());
            toolChecks.put(t, cb);
            toolsGrid.add(cb);
        }
        toolsGrid.setMaximumSize(new Dimension(Integer.MAX_VALUE, toolsGrid.getPreferredSize().height));
        root.add(toolsGrid);
        root.add(vgap(6));
        restrictScopeChk.setAlignmentX(LEFT_ALIGNMENT);
        contextMenuScopeChk.setAlignmentX(LEFT_ALIGNMENT);
        restrictScopeChk.setToolTipText("Ignores out-of-scope passive traffic and unattended probes. "
                + "Explicit active actions remain available unless the option below is enabled.");
        contextMenuScopeChk.setToolTipText("Blocks request-sending actions started explicitly from Quimera's context menu outside Burp scope.");
        root.add(restrictScopeChk);
        root.add(contextMenuScopeChk);
        root.add(vgap(16));

        root.add(sectionLabel("Active header scan, probes run by \"Active header scan\" / bulk active scan / auto-scan below"));
        root.add(buildAutoActiveScanCallout());
        root.add(vgap(10));
        optionsProbeChk.setAlignmentX(LEFT_ALIGNMENT);
        traceProbeChk.setAlignmentX(LEFT_ALIGNMENT);
        hstsProbeChk.setAlignmentX(LEFT_ALIGNMENT);
        webDavProbeChk.setAlignmentX(LEFT_ALIGNMENT);
        jwtProbeChk.setAlignmentX(LEFT_ALIGNMENT);
        sessionProbeChk.setAlignmentX(LEFT_ALIGNMENT);
        googleApiProbeChk.setAlignmentX(LEFT_ALIGNMENT);
        root.add(optionsProbeChk);
        root.add(traceProbeChk);
        root.add(hstsProbeChk);
        root.add(webDavProbeChk);
        root.add(jwtProbeChk);
        root.add(sessionProbeChk);
        root.add(googleApiProbeChk);
        headerInfluenceProbeChk.setAlignmentX(LEFT_ALIGNMENT);
        root.add(headerInfluenceProbeChk);
        JPanel influenceLimits = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        influenceLimits.setAlignmentX(LEFT_ALIGNMENT);
        influenceLimits.add(new JLabel("Header probe delay (ms):"));
        influenceLimits.add(headerInfluenceDelay);
        influenceLimits.add(new JLabel("Runs only with auto-scan; full catalogue, enable only when needed"));
        root.add(influenceLimits);
        root.add(vgap(16));

        root.add(sectionLabel("Evidence archive (optional, local only)"));
        externalEvidenceArchiveChk.setAlignmentX(LEFT_ALIGNMENT);
        externalEvidenceArchiveChk.setToolTipText("Keeps full request/response evidence outside the Burp project. "
                + "The selected folder can contain cookies, tokens and other sensitive data.");
        root.add(externalEvidenceArchiveChk);
        JPanel archiveRow = new JPanel(new BorderLayout(6, 0));
        archiveRow.setAlignmentX(LEFT_ALIGNMENT);
        archiveRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        externalEvidenceDirectory.setEditable(false);
        externalEvidenceDirectory.setToolTipText("Choose a local folder. Quimera creates a separate subfolder for this Burp project.");
        JButton chooseArchiveDirectory = new JButton("Choose folder...");
        chooseArchiveDirectory.addActionListener(e -> chooseExternalEvidenceDirectory());
        archiveRow.add(externalEvidenceDirectory, BorderLayout.CENTER);
        archiveRow.add(chooseArchiveDirectory, BorderLayout.EAST);
        root.add(archiveRow);
        JLabel archiveNotice = new JLabel("Disabled by default. No network or additional installation; only finding-bearing exchanges are archived.");
        archiveNotice.setFont(archiveNotice.getFont().deriveFont(11f));
        archiveNotice.setForeground(new Color(110, 120, 135));
        archiveNotice.setAlignmentX(LEFT_ALIGNMENT);
        root.add(archiveNotice);
        root.add(vgap(16));

        root.add(sectionLabel("Skip list, responses excluded from passive analysis"));
        JPanel skipRow = new JPanel(new GridLayout(1, 2, 12, 0));
        skipRow.setAlignmentX(LEFT_ALIGNMENT);
        skipRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 130));

        JPanel extPanel = new JPanel(new BorderLayout());
        extPanel.add(new JLabel("File extensions to skip (one per line):"), BorderLayout.NORTH);
        skipExtArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        extPanel.add(scrollPane(skipExtArea), BorderLayout.CENTER);

        JPanel ctPanel = new JPanel(new BorderLayout());
        ctPanel.add(new JLabel("Content-Type prefixes to skip (one per line):"), BorderLayout.NORTH);
        skipCtArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        ctPanel.add(scrollPane(skipCtArea), BorderLayout.CENTER);

        skipRow.add(extPanel);
        skipRow.add(ctPanel);
        root.add(skipRow);
        root.add(vgap(16));

        root.add(sectionLabel("Suppressed headers, your own known-noisy headers, never reported as findings"));
        JPanel suppressedPanel = new JPanel(new BorderLayout());
        suppressedPanel.setAlignmentX(LEFT_ALIGNMENT);
        suppressedPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 90));
        suppressedPanel.add(new JLabel("Header names to never report (one per line, e.g. an in-house gateway trace header):"), BorderLayout.NORTH);
        suppressedHeadersArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        suppressedPanel.add(scrollPane(suppressedHeadersArea), BorderLayout.CENTER);
        root.add(suppressedPanel);
        root.add(vgap(16));

        root.add(sectionLabel("Cookies & Auth"));
        JPanel cookieAuthRow = new JPanel(new BorderLayout(8, 0));
        cookieAuthRow.setAlignmentX(LEFT_ALIGNMENT);
        cookieAuthRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        JLabel cookieAuthDesc = new JLabel("Which cookie/JWT/Basic-Auth/Bearer/API-key checks run, the session/token lifetime "
                + "threshold, and your own additions to the built-in lists.");
        cookieAuthDesc.setFont(cookieAuthDesc.getFont().deriveFont(11f));
        cookieAuthDesc.setForeground(new Color(110, 120, 135));
        JButton cookieAuthBtn = new JButton("Cookies & Auth Rules...");
        cookieAuthBtn.addActionListener(e -> openCookieAuthRulesDialog());
        cookieAuthRow.add(cookieAuthDesc, BorderLayout.CENTER);
        cookieAuthRow.add(cookieAuthBtn, BorderLayout.EAST);
        root.add(cookieAuthRow);
        root.add(vgap(16));

        root.add(sectionLabel("Browser Bridge"));
        JPanel browserBridgeRow = new JPanel(new BorderLayout(8, 0));
        browserBridgeRow.setAlignmentX(LEFT_ALIGNMENT);
        browserBridgeRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        JLabel browserBridgeDesc = new JLabel("Loopback server the Quimera browser extension talks to: on/off, "
                + "port and required pairing token.");
        browserBridgeDesc.setFont(browserBridgeDesc.getFont().deriveFont(11f));
        browserBridgeDesc.setForeground(new Color(110, 120, 135));
        JButton browserBridgeBtn = new JButton("Browser Bridge...");
        browserBridgeBtn.addActionListener(e -> openBrowserBridgeDialog());
        browserBridgeRow.add(browserBridgeDesc, BorderLayout.CENTER);
        browserBridgeRow.add(browserBridgeBtn, BorderLayout.EAST);
        root.add(browserBridgeRow);
        root.add(vgap(16));

        root.add(sectionLabel("Out-of-band interaction analysis"));
        JPanel collabRow = new JPanel(new BorderLayout(8, 0));
        collabRow.setAlignmentX(LEFT_ALIGNMENT);
        collabRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        JLabel collabDesc = new JLabel("Quimera never sends OOB requests itself. Generate a payload (optional) and check "
                + "what's already arrived, however it was triggered.");
        collabDesc.setFont(collabDesc.getFont().deriveFont(11f));
        collabDesc.setForeground(new Color(110, 120, 135));
        JButton collabBtn = new JButton("Collaborator...");
        collabBtn.addActionListener(e -> openCollaboratorDialog());
        collabRow.add(collabDesc, BorderLayout.CENTER);
        collabRow.add(collabBtn, BorderLayout.EAST);
        root.add(collabRow);
        root.add(vgap(16));

        applyBtn.addActionListener(e -> apply());
        resetBtn.addActionListener(e -> {
            settings.reset();
            loadFromSettings();
            statusLabel.setText("Restored defaults.");
        });
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC, 11f));
        statusLabel.setForeground(Color.GRAY);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        btnRow.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(210, 210, 210)));
        btnRow.add(applyBtn);
        btnRow.add(resetBtn);
        btnRow.add(statusLabel);
        add(scrollPane(root), BorderLayout.CENTER);
        add(btnRow, BorderLayout.SOUTH);
        normalApplyForeground = applyBtn.getForeground();
        installDirtyTracking();
    }

    /**
     * Deliberately loud, not just another checkbox in a list: this is the one setting that makes
     * Quimera send real extra requests at the target on its own, unattended, for every URL it
     * sees, worth a second look before flipping it. A bordered, tinted callout with a live ON/OFF
     * badge (updates the instant the checkbox is clicked, before "Apply") makes that state
     * impossible to miss or mistake for "just more config".
     */
    private JPanel buildAutoActiveScanCallout() {
        boolean dark = api.userInterface().currentTheme() == burp.api.montoya.ui.Theme.DARK;
        Color accent  = dark ? new Color(255, 176, 32)  : new Color(196, 118, 0);
        Color bg      = dark ? new Color(59, 47, 15)    : new Color(255, 244, 214);
        Color border  = dark ? new Color(133, 97, 23)   : new Color(230, 190, 110);

        JPanel callout = new JPanel();
        callout.setLayout(new BoxLayout(callout, BoxLayout.Y_AXIS));
        callout.setAlignmentX(LEFT_ALIGNMENT);
        callout.setOpaque(true);
        callout.setBackground(bg);
        callout.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(border, 2),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)));
        callout.setMaximumSize(new Dimension(Integer.MAX_VALUE, 185));

        JPanel headerRow = new JPanel(new BorderLayout());
        headerRow.setOpaque(false);
        headerRow.setAlignmentX(LEFT_ALIGNMENT);

        JLabel title = new JLabel("AUTO ACTIVE SCAN");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 13f));
        title.setForeground(accent);
        headerRow.add(title, BorderLayout.WEST);

        autoActiveScanBadge.setFont(autoActiveScanBadge.getFont().deriveFont(Font.BOLD, 12f));
        headerRow.add(autoActiveScanBadge, BorderLayout.EAST);
        callout.add(headerRow);
        callout.add(vgap(4));

        autoActiveScanChk.setOpaque(false);
        autoActiveScanChk.setFont(autoActiveScanChk.getFont().deriveFont(Font.BOLD, 12f));
        autoActiveScanChk.setAlignmentX(LEFT_ALIGNMENT);
        // Takes effect immediately on click rather than waiting for the "Apply" button below, same
        // as the toolbar quick-toggle in QuimeraTab (see QuimeraTab#buildTopBar): this one setting
        // fires real traffic at the target the instant it's on, batching it behind Apply like the
        // rest of the form would mean it silently doesn't do what the checkbox visibly shows.
        autoActiveScanChk.addItemListener(e -> {
            if (syncingAutoActiveScan) return;
            settings.setAutoActiveScan(autoActiveScanChk.isSelected());
            refreshAutoActiveScan();
        });
        callout.add(autoActiveScanChk);
        Color descColor = dark ? new Color(200, 190, 170) : new Color(110, 90, 40);
        callout.add(wrappedLabel("Sends real extra requests (CORS Origin reflection, TRACE, HSTS", descColor));
        callout.add(wrappedLabel("downgrade, WebDAV, whichever of the four below are checked) for every new", descColor));
        callout.add(wrappedLabel("URL seen on intercepted proxy traffic, unattended. Enabling it also", descColor));
        callout.add(wrappedLabel("selects JWT, session-validation and exposed-Google-key probes; each", descColor));
        callout.add(wrappedLabel("can still be disabled individually afterwards. Off = purely passive.", descColor));

        return callout;
    }

    private static JLabel wrappedLabel(String text, Color color) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(11f));
        l.setForeground(color);
        l.setAlignmentX(LEFT_ALIGNMENT);
        return l;
    }

    /** Refreshes the auto-active-scan checkbox/badge plus the three checkboxes it's coupled to
     * (JWT, session invalidation and Google API key; see {@link QuimeraSettings#setAutoActiveScan})
     * from the live settings, safe to call anytime (e.g. after the QuimeraTab toolbar quick-toggle
     * changes it) without disturbing whatever unsaved edits the user has pending elsewhere on this
     * form. Without this, the coupling would take effect in the backing settings immediately but
     * these two boxes would keep showing their old, now-stale state, and clicking Apply later for
     * some unrelated field would silently revert the coupling back to whatever they displayed. */
    public void refreshAutoActiveScan() {
        syncingAutoActiveScan = true;
        try {
            autoActiveScanChk.setSelected(settings.isAutoActiveScan());
            updateAutoActiveScanBadge();
            jwtProbeChk.setSelected(settings.isJwtActiveProbeEnabled());
            sessionProbeChk.setSelected(settings.isSessionInvalidationProbeEnabled());
            googleApiProbeChk.setSelected(settings.isGoogleApiKeyProbeEnabled());
        } finally {
            syncingAutoActiveScan = false;
        }
    }

    private void updateAutoActiveScanBadge() {
        boolean on = autoActiveScanChk.isSelected();
        autoActiveScanBadge.setText(on ? "● ON" : "○ OFF");
        autoActiveScanBadge.setForeground(on ? new Color(30, 140, 60) : Color.GRAY);
    }

    private static JLabel sectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 12f));
        l.setAlignmentX(LEFT_ALIGNMENT);
        l.setBorder(BorderFactory.createEmptyBorder(6, 0, 6, 0));
        return l;
    }

    private static Component vgap(int h) { return Box.createRigidArea(new Dimension(0, h)); }

    private void openCollaboratorDialog() {
        if (collaboratorDialog == null) {
            collaboratorDialog = new CollaboratorDialog(SwingUtilities.getWindowAncestor(this), api);
        }
        collaboratorDialog.setVisible(true);
        collaboratorDialog.toFront();
    }

    private void openCookieAuthRulesDialog() {
        if (cookieAuthRulesDialog == null) {
            cookieAuthRulesDialog = new CookieAuthRulesDialog(SwingUtilities.getWindowAncestor(this), settings);
        } else {
            cookieAuthRulesDialog.loadFromSettings(); // pick up e.g. a "Reset to Defaults" done since it was last opened
        }
        cookieAuthRulesDialog.setVisible(true);
        cookieAuthRulesDialog.toFront();
    }

    private void openBrowserBridgeDialog() {
        if (browserBridgeDialog == null) {
            browserBridgeDialog = new BrowserBridgeDialog(
                    SwingUtilities.getWindowAncestor(this), settings, onBrowserBridgeApplied, browserBridgeRunning);
        } else {
            browserBridgeDialog.loadFromSettings();
        }
        browserBridgeDialog.setVisible(true);
        browserBridgeDialog.toFront();
    }

    /** Public so QuimeraTab can re-sync this form when the Settings tab is selected: jwtProbeChk
     * mirrors the same underlying setting as CookieAuthRulesDialog's own jwtActiveProbeChk, and
     * this panel is built once and kept alive for the whole session, not reloaded per-view, so
     * without this a JWT-probe toggle made over there would show stale here until Burp restarts,
     * and clicking Apply on an unrelated field would silently revert it back. */
    public void loadFromSettings() {
        loadingSettings = true;
        try {
            Set<String> enabled = settings.getEnabledTools();
            for (var e : toolChecks.entrySet()) e.getValue().setSelected(enabled.contains(e.getKey().name()));
            restrictScopeChk.setSelected(settings.isRestrictToScope());
            contextMenuScopeChk.setSelected(settings.isContextMenuRequireScope());
            refreshAutoActiveScan();
            optionsProbeChk.setSelected(settings.isActiveScanOptionsProbe());
            traceProbeChk.setSelected(settings.isActiveScanTraceProbe());
            hstsProbeChk.setSelected(settings.isActiveScanHstsProbe());
            webDavProbeChk.setSelected(settings.isActiveScanWebDavProbe());
            googleApiProbeChk.setSelected(settings.isGoogleApiKeyProbeEnabled());
            headerInfluenceProbeChk.setSelected(settings.isHeaderInfluenceProbeEnabled());
            headerInfluenceDelay.setValue(settings.getHeaderInfluenceDelayMillis());
            skipExtArea.setText(String.join("\n", settings.getSkipExtensions()));
            skipCtArea.setText(String.join("\n", settings.getSkipContentTypes()));
            suppressedHeadersArea.setText(String.join("\n", settings.getSuppressedHeaders()));
            externalEvidenceArchiveChk.setSelected(settings.isExternalEvidenceArchiveEnabled());
            externalEvidenceDirectory.setText(settings.getExternalEvidenceArchiveDirectory());
        } finally {
            loadingSettings = false;
        }
        updateDirtyState();
    }

    private void apply() {
        String archiveDirectory = externalEvidenceDirectory.getText().trim();
        if (externalEvidenceArchiveChk.isSelected() && archiveDirectory.isEmpty()) {
            statusLabel.setText("Choose a local folder before enabling the external evidence archive.");
            return;
        }
        Set<String> tools = new LinkedHashSet<>();
        for (var e : toolChecks.entrySet()) if (e.getValue().isSelected()) tools.add(e.getKey().name());
        settings.setEnabledTools(tools);
        settings.setRestrictToScope(restrictScopeChk.isSelected());
        settings.setContextMenuRequireScope(contextMenuScopeChk.isSelected());
        settings.setAutoActiveScan(autoActiveScanChk.isSelected());
        settings.setActiveScanOptionsProbe(optionsProbeChk.isSelected());
        settings.setActiveScanTraceProbe(traceProbeChk.isSelected());
        settings.setActiveScanHstsProbe(hstsProbeChk.isSelected());
        settings.setActiveScanWebDavProbe(webDavProbeChk.isSelected());
        settings.setJwtActiveProbeEnabled(jwtProbeChk.isSelected());
        settings.setSessionInvalidationProbeEnabled(sessionProbeChk.isSelected());
        settings.setGoogleApiKeyProbeEnabled(googleApiProbeChk.isSelected());
        settings.setHeaderInfluenceProbeEnabled(headerInfluenceProbeChk.isSelected());
        settings.setHeaderInfluenceDelayMillis(((Number) headerInfluenceDelay.getValue()).intValue());
        settings.setSkipExtensions(splitLines(skipExtArea.getText()));
        settings.setSkipContentTypes(splitLines(skipCtArea.getText()));
        settings.setSuppressedHeaders(splitLines(suppressedHeadersArea.getText()));
        settings.setExternalEvidenceArchive(externalEvidenceArchiveChk.isSelected(), archiveDirectory);
        statusLabel.setText("Applied.");
        updateDirtyState();
        if (onApplied != null) onApplied.run();
    }

    private void chooseExternalEvidenceDirectory() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose Quimera external evidence archive folder");
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setAcceptAllFileFilterUsed(false);
        String existing = externalEvidenceDirectory.getText().trim();
        if (!existing.isEmpty()) chooser.setCurrentDirectory(new java.io.File(existing));
        if (chooser.showOpenDialog(SwingUtilities.getWindowAncestor(this)) == JFileChooser.APPROVE_OPTION) {
            externalEvidenceDirectory.setText(chooser.getSelectedFile().toPath().toAbsolutePath().normalize().toString());
        }
    }

    private void installDirtyTracking() {
        java.awt.event.ItemListener item = ignored -> updateDirtyState();
        for (JCheckBox check : toolChecks.values()) check.addItemListener(item);
        for (JCheckBox check : java.util.List.of(restrictScopeChk, contextMenuScopeChk,
                optionsProbeChk, traceProbeChk, hstsProbeChk, webDavProbeChk, googleApiProbeChk,
                headerInfluenceProbeChk, jwtProbeChk, sessionProbeChk, externalEvidenceArchiveChk)) {
            check.addItemListener(item);
        }
        headerInfluenceDelay.addChangeListener(ignored -> updateDirtyState());
        DocumentListener documents = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent ignored) { updateDirtyState(); }
            @Override public void removeUpdate(DocumentEvent ignored) { updateDirtyState(); }
            @Override public void changedUpdate(DocumentEvent ignored) { updateDirtyState(); }
        };
        skipExtArea.getDocument().addDocumentListener(documents);
        skipCtArea.getDocument().addDocumentListener(documents);
        suppressedHeadersArea.getDocument().addDocumentListener(documents);
        externalEvidenceDirectory.getDocument().addDocumentListener(documents);
    }

    private void updateDirtyState() {
        if (loadingSettings || normalApplyForeground == null) return;
        boolean dirty = hasUnsavedChanges();
        applyBtn.setText(dirty ? "Apply • Unsaved changes" : "Apply");
        applyBtn.setForeground(dirty ? new Color(190, 45, 45) : normalApplyForeground);
        applyBtn.setToolTipText(dirty ? "Settings differ from the saved configuration" : "Save current settings");
    }

    private boolean hasUnsavedChanges() {
        Set<String> selectedTools = new LinkedHashSet<>();
        for (var entry : toolChecks.entrySet()) if (entry.getValue().isSelected()) selectedTools.add(entry.getKey().name());
        return !selectedTools.equals(settings.getEnabledTools())
                || restrictScopeChk.isSelected() != settings.isRestrictToScope()
                || contextMenuScopeChk.isSelected() != settings.isContextMenuRequireScope()
                || optionsProbeChk.isSelected() != settings.isActiveScanOptionsProbe()
                || traceProbeChk.isSelected() != settings.isActiveScanTraceProbe()
                || hstsProbeChk.isSelected() != settings.isActiveScanHstsProbe()
                || webDavProbeChk.isSelected() != settings.isActiveScanWebDavProbe()
                || googleApiProbeChk.isSelected() != settings.isGoogleApiKeyProbeEnabled()
                || headerInfluenceProbeChk.isSelected() != settings.isHeaderInfluenceProbeEnabled()
                || jwtProbeChk.isSelected() != settings.isJwtActiveProbeEnabled()
                || sessionProbeChk.isSelected() != settings.isSessionInvalidationProbeEnabled()
                || ((Number) headerInfluenceDelay.getValue()).intValue() != settings.getHeaderInfluenceDelayMillis()
                || !splitLines(skipExtArea.getText()).equals(settings.getSkipExtensions())
                || !splitLines(skipCtArea.getText()).equals(settings.getSkipContentTypes())
                || !splitLines(suppressedHeadersArea.getText()).equals(settings.getSuppressedHeaders())
                || externalEvidenceArchiveChk.isSelected() != settings.isExternalEvidenceArchiveEnabled()
                || !externalEvidenceDirectory.getText().trim().equals(settings.getExternalEvidenceArchiveDirectory());
    }

    private static java.util.List<String> splitLines(String text) {
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String line : text.split("\\r?\\n")) {
            String t = line.trim();
            if (!t.isEmpty()) out.add(t);
        }
        return out;
    }
}
