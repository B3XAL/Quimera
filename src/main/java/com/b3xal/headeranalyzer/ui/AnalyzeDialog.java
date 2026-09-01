package com.b3xal.headeranalyzer.ui;

import burp.api.montoya.MontoyaApi;
import com.b3xal.headeranalyzer.analyzer.BulkAnalyzer;
import com.b3xal.headeranalyzer.config.QuimeraSettings;
import com.b3xal.headeranalyzer.model.UrlAnalysisResult;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Bulk analysis workflow, opened from the Logger's "Analyze" button.
 *
 * Passive mode re-analyzes traffic Burp has already crawled (no new requests).
 * Active mode sends a fresh request for every URL in scope, optionally the entire target , 
 * plus the OPTIONS/TRACE/HSTS probes, i.e. "coger el target completo y analizar todo, incluso
 * haciendo peticiones activas para las URLs que tenemos."
 */
public final class AnalyzeDialog extends JDialog {

    private final MontoyaApi api;
    private final BulkAnalyzer bulkAnalyzer;
    private final QuimeraSettings settings;
    private final Consumer<UrlAnalysisResult> onResult;

    private final JRadioButton passiveMode = new JRadioButton("Passive, re-analyze already-crawled responses", true);
    private final JRadioButton activeMode  = new JRadioButton("Active, send fresh requests + CORS/TRACE/HSTS probes");

    private final JRadioButton scopeEntire = new JRadioButton("Entire target (Burp scope)", true);
    private final JRadioButton scopeHost   = new JRadioButton("Host:");
    private final JRadioButton scopePaste  = new JRadioButton("Paste URLs:");

    private final JTextField hostField  = new JTextField(24);
    private final JTextArea  urlsArea   = new JTextArea(6, 30);
    private final JCheckBox  runProbes  = new JCheckBox("Also run CORS/TRACE/HSTS probes on each URL", true);
    private final JCheckBox  restrictScope = new JCheckBox("Restrict active requests to Burp scope", true);

    private final JProgressBar progress = new JProgressBar();
    private final JLabel statusLabel = new JLabel(" ");
    private final JButton runBtn = new JButton("Run");

    public AnalyzeDialog(Window owner, MontoyaApi api, BulkAnalyzer bulkAnalyzer,
                          QuimeraSettings settings, Consumer<UrlAnalysisResult> onResult) {
        super(owner, "Quimera: Analyze", ModalityType.MODELESS);
        this.api          = api;
        this.bulkAnalyzer = bulkAnalyzer;
        this.settings     = settings;
        this.onResult     = onResult;
        build();
    }

    private void build() {
        setLayout(new BorderLayout(8, 8));
        ((JComponent) getContentPane()).setBorder(BorderFactory.createEmptyBorder(12, 14, 12, 14));

        ButtonGroup modeGroup = new ButtonGroup();
        modeGroup.add(passiveMode); modeGroup.add(activeMode);

        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(scopeEntire); scopeGroup.add(scopeHost); scopeGroup.add(scopePaste);

        JPanel modePanel = new JPanel();
        modePanel.setLayout(new BoxLayout(modePanel, BoxLayout.Y_AXIS));
        modePanel.setBorder(BorderFactory.createTitledBorder("Mode"));
        modePanel.add(passiveMode);
        modePanel.add(activeMode);

        JPanel activeOpts = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        activeOpts.add(runProbes);
        JPanel activeOpts2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        activeOpts2.add(restrictScope);
        modePanel.add(activeOpts);
        modePanel.add(activeOpts2);

        JPanel targetPanel = new JPanel(new GridBagLayout());
        targetPanel.setBorder(BorderFactory.createTitledBorder("Target"));
        GridBagConstraints g = new GridBagConstraints();
        g.anchor = GridBagConstraints.WEST; g.insets = new Insets(2, 2, 2, 4); g.gridx = 0;

        g.gridy = 0; targetPanel.add(scopeEntire, g);
        g.gridy = 1; targetPanel.add(scopeHost, g);
        g.gridx = 1; targetPanel.add(hostField, g);
        g.gridx = 0; g.gridy = 2; targetPanel.add(scopePaste, g);
        g.gridx = 1; g.fill = GridBagConstraints.BOTH; g.weightx = 1; g.weighty = 1;
        urlsArea.setLineWrap(false);
        urlsArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        JScrollPane urlsScroll = new JScrollPane(urlsArea);
        urlsScroll.setPreferredSize(new Dimension(300, 100));
        targetPanel.add(urlsScroll, g);

        activeMode.addActionListener(e -> updateEnabled());
        passiveMode.addActionListener(e -> updateEnabled());
        scopeHost.addActionListener(e -> updateEnabled());
        scopeEntire.addActionListener(e -> updateEnabled());
        scopePaste.addActionListener(e -> updateEnabled());

        progress.setStringPainted(true);
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC, 11f));
        statusLabel.setForeground(Color.GRAY);

        runBtn.addActionListener(e -> run());
        JButton closeBtn = new JButton("Close");
        closeBtn.addActionListener(e -> dispose());

        JPanel southButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        southButtons.add(runBtn);
        southButtons.add(closeBtn);

        JPanel south = new JPanel(new BorderLayout(4, 4));
        south.add(progress, BorderLayout.NORTH);
        south.add(statusLabel, BorderLayout.CENTER);
        south.add(southButtons, BorderLayout.SOUTH);

        JPanel top = new JPanel(new BorderLayout(8, 8));
        top.add(modePanel, BorderLayout.NORTH);
        top.add(targetPanel, BorderLayout.CENTER);

        add(top, BorderLayout.CENTER);
        add(south, BorderLayout.SOUTH);

        updateEnabled();
        pack();
        setLocationRelativeTo(getOwner());
    }

    private void updateEnabled() {
        boolean active = activeMode.isSelected();
        runProbes.setEnabled(active);
        restrictScope.setEnabled(active);
        scopePaste.setEnabled(active); // passive re-analysis only makes sense against crawled scope/host
        if (!active && scopePaste.isSelected()) scopeEntire.setSelected(true);
        hostField.setEnabled(scopeHost.isSelected());
        urlsArea.setEnabled(scopePaste.isSelected() && active);
    }

    private void run() {
        runBtn.setEnabled(false);
        progress.setValue(0);
        // Indeterminate ("barber pole") only until the first tick reports a real total, sitemap
        // size / URL count isn't known until the background task resolves it, see
        // BulkAnalyzer.ProgressListener. Once that arrives the bar switches to a normal 0-100%.
        progress.setIndeterminate(true);
        statusLabel.setText("Running…");

        Consumer<UrlAnalysisResult> resultCb = r -> SwingUtilities.invokeLater(() -> onResult.accept(r));
        Runnable onDone = () -> SwingUtilities.invokeLater(() -> {
            progress.setIndeterminate(false);
            progress.setValue(progress.getMaximum());
            progress.setString("Done");
            statusLabel.setText("Done.");
            runBtn.setEnabled(true);
        });
        BulkAnalyzer.ProgressListener onProgress = (done, total) -> SwingUtilities.invokeLater(() -> {
            if (progress.isIndeterminate()) progress.setIndeterminate(false);
            if (progress.getMaximum() != total) progress.setMaximum(Math.max(total, 1));
            progress.setValue(done);
            progress.setString(done + " / " + total);
            statusLabel.setText("Analyzing " + done + " of " + total + "…");
        });

        if (passiveMode.isSelected()) {
            String host = scopeHost.isSelected() ? hostField.getText().trim() : null;
            bulkAnalyzer.analyzeSitemap(host, resultCb, onProgress, onDone);
            return;
        }

        boolean requireScope = restrictScope.isSelected();
        boolean probes = runProbes.isSelected();

        if (scopePaste.isSelected()) {
            List<String> urls = new ArrayList<>();
            for (String line : urlsArea.getText().split("\\r?\\n")) {
                String u = line.trim();
                if (u.isEmpty()) continue;
                if (!u.startsWith("http")) u = "https://" + u;
                urls.add(u);
            }
            if (urls.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Paste at least one URL.", "No URLs", JOptionPane.WARNING_MESSAGE);
                runBtn.setEnabled(true);
                progress.setIndeterminate(false);
                return;
            }
            bulkAnalyzer.activeScanUrls(urls, requireScope, probes, resultCb, onProgress, onDone);
        } else {
            String host = scopeHost.isSelected() ? hostField.getText().trim() : null;
            bulkAnalyzer.activeScanEntireTarget(host, requireScope, probes, resultCb, onProgress, onDone);
        }
    }
}
