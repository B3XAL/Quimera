package com.b3xal.headeranalyzer.ui;

import com.b3xal.headeranalyzer.config.QuimeraSettings;

import javax.swing.*;
import java.awt.*;
import java.security.SecureRandom;
import java.util.function.BooleanSupplier;

/**
 * Modeless "Browser Bridge" dialog, opened from Settings, same shape as {@link CookieAuthRulesDialog}.
 * Configures the loopback server ({@code com.b3xal.headeranalyzer.browser.BrowserBridgeServer}) the
 * Quimera browser extension talks to. The bridge is off by default and always requires a pairing
 * token; loopback is transport scoping, not authentication.
 */
public final class BrowserBridgeDialog extends JDialog {

    private final QuimeraSettings settings;
    private final Runnable onApplied; // restarts the bridge server so a changed port/state takes effect
    private final BooleanSupplier isRunning; // reads the real bound-socket state, not just the setting

    private final JCheckBox enabledChk = new JCheckBox("Enable Browser Bridge");
    private final JSpinner portSpinner =
            new JSpinner(new SpinnerNumberModel(QuimeraSettings.DEFAULT_BROWSER_BRIDGE_PORT, 1, 65535, 1));
    private final JCheckBox tokenEnabledChk = new JCheckBox("Require pairing token");
    private final JTextField tokenField = new JTextField(32);
    private final JButton generateTokenBtn = new JButton("Generate");
    private final JButton copyTokenBtn = new JButton("Copy");

    // Live bind status: distinct from "Applied." (statusLabel below), this reflects whether the
    // socket is ACTUALLY listening right now, e.g. red "Failed to start (port already in use?)"
    // when another process (or a second Burp instance) already holds that port, previously this
    // only surfaced as a line in Burp's extension error log that nobody would think to check.
    private final JLabel bridgeStatusLabel = new JLabel(" ");
    private final JLabel statusLabel = new JLabel(" ");

    public BrowserBridgeDialog(Window owner, QuimeraSettings settings, Runnable onApplied,
                                BooleanSupplier isRunning) {
        super(owner, "Quimera - Browser Bridge", ModalityType.MODELESS);
        this.settings = settings;
        this.onApplied = onApplied;
        this.isRunning = isRunning;
        build();
        tokenEnabledChk.setEnabled(false);
        loadFromSettings();
        setSize(560, 460);
        setLocationRelativeTo(owner);
    }

    private void build() {
        JPanel root = new JPanel();
        root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
        root.setBorder(BorderFactory.createEmptyBorder(14, 16, 14, 16));

        // Plain wrapping JTextArea, not an HTML JLabel: Burp's look-and-feel disables Swing HTML
        // rendering process-wide (same lesson as CookieAuthRulesDialog's own intro).
        JTextArea intro = new JTextArea("Lets the Quimera browser extension send authorized Web " +
                "Storage, cookie and authentication evidence to this local Burp instance. It is off " +
                "by default and requires the pairing token shown below. The browser extension keeps " +
                "working locally when this bridge is disabled.");
        intro.setEditable(false);
        intro.setFocusable(false);
        intro.setOpaque(false);
        intro.setLineWrap(true);
        intro.setWrapStyleWord(true);
        intro.setAlignmentX(Component.LEFT_ALIGNMENT);
        intro.setMaximumSize(new Dimension(Integer.MAX_VALUE, 70));
        intro.setFont(intro.getFont().deriveFont(11f));
        intro.setForeground(new Color(110, 120, 135));
        root.add(intro);
        root.add(vgap(12));

        enabledChk.setAlignmentX(Component.LEFT_ALIGNMENT);
        // Generate a token right when the user turns the bridge on, don't make "the token field
        // is empty" a separate thing they have to notice and fix with the Generate button.
        enabledChk.addActionListener(e -> {
            if (enabledChk.isSelected() && tokenField.getText().trim().length() < 32) {
                tokenField.setText(generateToken());
            }
        });
        root.add(enabledChk);
        root.add(vgap(6));

        bridgeStatusLabel.setFont(bridgeStatusLabel.getFont().deriveFont(Font.BOLD, 11f));
        bridgeStatusLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        root.add(bridgeStatusLabel);
        root.add(vgap(10));

        JPanel portRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        portRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        portRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        portRow.add(new JLabel("Port:"));
        portRow.add(portSpinner);
        root.add(portRow);
        JLabel portHint = hint("Must match the port set in the extension's Options page. Default: "
                + QuimeraSettings.DEFAULT_BROWSER_BRIDGE_PORT + ".");
        root.add(portHint);
        root.add(vgap(16));

        root.add(sectionLabel("Pairing token (required)"));
        tokenEnabledChk.setAlignmentX(Component.LEFT_ALIGNMENT);
        root.add(tokenEnabledChk);
        root.add(vgap(6));

        JPanel tokenRow = new JPanel(new BorderLayout(6, 0));
        tokenRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        tokenRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        tokenField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        tokenRow.add(tokenField, BorderLayout.CENTER);
        JPanel tokenBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        tokenBtns.add(generateTokenBtn);
        tokenBtns.add(copyTokenBtn);
        tokenRow.add(tokenBtns, BorderLayout.EAST);
        root.add(tokenRow);
        root.add(hint("Paste this token into the browser extension. Rotate it if it is exposed."));
        root.add(vgap(16));

        generateTokenBtn.addActionListener(e -> tokenField.setText(generateToken()));
        copyTokenBtn.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new java.awt.datatransfer.StringSelection(tokenField.getText()), null);
            statusLabel.setText("Token copied to clipboard.");
        });

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

    private static String generateToken() {
        byte[] raw = new byte[24];
        new SecureRandom().nextBytes(raw);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    /** Plain, non-HTML JLabel: Burp's look-and-feel disables Swing HTML rendering process-wide
     * (see CookieAuthRulesDialog's own comment on the same gotcha), so a &lt;html&gt;-wrapped
     * label here would render raw tag characters instead of wrapping anything. These hints are
     * short enough to read fine as a single unwrapped line at the dialog's fixed width. */
    private static JLabel hint(String text) {
        JLabel l = new JLabel(text);
        l.setFont(l.getFont().deriveFont(11f));
        l.setForeground(new Color(110, 120, 135));
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        return l;
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
     * dialog is reopened (lazily created once and reused, see SettingsPanel). */
    public void loadFromSettings() {
        enabledChk.setSelected(settings.isBrowserBridgeEnabled());
        portSpinner.setValue(settings.getBrowserBridgePort());
        tokenEnabledChk.setSelected(settings.isBrowserBridgeTokenEnabled());
        tokenField.setText(settings.getBrowserBridgeToken());
        if (tokenField.getText().trim().length() < 32) {
            // Belt-and-suspenders: QuimeraSettings already generates one on construction, but
            // never leave the field visibly empty, that reads as broken, not "click Generate".
            tokenField.setText(generateToken());
        }
        refreshBridgeStatus();
    }

    /** Reflects the ACTUAL bound-socket state (not just the enabled setting): tells the user in
     * plain sight whether the port is really listening or the bind failed (most commonly: the
     * configured port is already in use by something else). */
    private void refreshBridgeStatus() {
        if (!settings.isBrowserBridgeEnabled()) {
            bridgeStatusLabel.setText("○ Disabled");
            bridgeStatusLabel.setForeground(Color.GRAY);
        } else if (isRunning != null && isRunning.getAsBoolean()) {
            bridgeStatusLabel.setText("● Running on 127.0.0.1:" + settings.getBrowserBridgePort());
            bridgeStatusLabel.setForeground(new Color(30, 140, 60));
        } else {
            bridgeStatusLabel.setText("● Failed to start on port " + settings.getBrowserBridgePort()
                    + " (already in use by something else? try a different port)");
            bridgeStatusLabel.setForeground(new Color(192, 57, 43));
        }
    }

    private void apply() {
        if (enabledChk.isSelected() && tokenField.getText().trim().length() < 32) {
            JOptionPane.showMessageDialog(this, "Generate or enter a pairing token of at least 32 characters.",
                    "Pairing token required", JOptionPane.WARNING_MESSAGE);
            return;
        }
        settings.setBrowserBridgeEnabled(enabledChk.isSelected());
        settings.setBrowserBridgePort((Integer) portSpinner.getValue());
        settings.setBrowserBridgeTokenEnabled(true);
        settings.setBrowserBridgeToken(tokenField.getText().trim());
        if (onApplied != null) onApplied.run(); // restarts the bridge server on the (possibly new) port
        refreshBridgeStatus();
        statusLabel.setText("Applied.");
    }
}
