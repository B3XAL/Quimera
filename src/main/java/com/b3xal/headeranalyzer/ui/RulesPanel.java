package com.b3xal.headeranalyzer.ui;

import com.b3xal.headeranalyzer.analyzer.RuleDefinition;
import com.b3xal.headeranalyzer.analyzer.RuleStore;

import static com.b3xal.headeranalyzer.ui.render.ScrollUtil.scrollPane;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.List;

/**
 * Rules tab, full editor for detection rules (headers and cookies alike): enable/disable,
 * create/edit/delete custom rules, and import/export the whole rule set as JSON.
 */
public final class RulesPanel extends JPanel {

    private final RuleStore ruleStore;

    private static final String[] COLS = {"On", "Header", "Type", "Checks", "Source"};
    private final DefaultTableModel model = new DefaultTableModel(COLS, 0) {
        @Override public boolean isCellEditable(int r, int c) { return c == 0; }
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
    };
    private final JTable table = new JTable(model);
    private List<RuleDefinition> shown = List.of();

    public RulesPanel(RuleStore ruleStore) {
        super(new BorderLayout());
        this.ruleStore = ruleStore;
        build();
        reload();
    }

    private void build() {
        table.setRowHeight(22);
        table.setAutoCreateRowSorter(true);
        table.getColumnModel().getColumn(0).setMaxWidth(40);
        table.getColumnModel().getColumn(2).setMaxWidth(90);
        table.getColumnModel().getColumn(3).setMaxWidth(70);
        table.getColumnModel().getColumn(4).setMaxWidth(90);

        model.addTableModelListener(e -> {
            if (e.getColumn() != 0 || e.getType() != javax.swing.event.TableModelEvent.UPDATE) return;
            int row = e.getFirstRow();
            if (row < 0 || row >= shown.size()) return;
            boolean enabled = (Boolean) model.getValueAt(row, 0);
            ruleStore.setEnabled(shown.get(row).id, enabled);
        });

        JButton newBtn    = new JButton("New Rule");
        JButton editBtn    = new JButton("Edit");
        JButton deleteBtn  = new JButton("Delete");
        JButton importBtn  = new JButton("Import JSON");
        JButton exportBtn  = new JButton("Export JSON");
        JButton resetBtn   = new JButton("Reset to Defaults");

        newBtn.addActionListener(e -> {
            RuleEditDialog dlg = new RuleEditDialog(SwingUtilities.getWindowAncestor(this), null);
            dlg.setVisible(true);
            if (dlg.isConfirmed()) { ruleStore.add(dlg.getRule()); reload(); }
        });

        editBtn.addActionListener(e -> {
            RuleDefinition rd = selected();
            if (rd == null) return;
            RuleEditDialog dlg = new RuleEditDialog(SwingUtilities.getWindowAncestor(this), rd);
            dlg.setVisible(true);
            if (dlg.isConfirmed()) { ruleStore.update(dlg.getRule()); reload(); }
        });

        deleteBtn.addActionListener(e -> {
            RuleDefinition rd = selected();
            if (rd == null) return;
            if (rd.builtin) {
                JOptionPane.showMessageDialog(this,
                        "Built-in rules can't be deleted, disable them instead (uncheck 'On').",
                        "Built-in rule", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            int choice = JOptionPane.showConfirmDialog(this, "Delete rule for '" + rd.headerName + "'?",
                    "Delete Rule", JOptionPane.YES_NO_OPTION);
            if (choice == JOptionPane.YES_OPTION) { ruleStore.delete(rd.id); reload(); }
        });

        importBtn.addActionListener(e -> doImport());
        exportBtn.addActionListener(e -> doExport());

        resetBtn.addActionListener(e -> {
            int choice = JOptionPane.showConfirmDialog(this,
                    "Restore the shipped default rule set? This discards ALL custom rules and edits.",
                    "Reset to Defaults", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice == JOptionPane.YES_OPTION) { ruleStore.resetToDefaults(); reload(); }
        });

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        toolbar.add(newBtn);
        toolbar.add(editBtn);
        toolbar.add(deleteBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(importBtn);
        toolbar.add(exportBtn);
        toolbar.add(new JSeparator(SwingConstants.VERTICAL));
        toolbar.add(resetBtn);

        // Plain wrapping JTextArea, not an HTML JLabel: Burp's look-and-feel sets the Swing
        // "html.disable" UIManager flag process-wide (same lesson already learned in LoggerPanel/
        // CookiePanel's tooltips), so a <html>...</html>-wrapped JLabel here rendered the raw tag
        // characters to the user instead of formatting/wrapping anything.
        JTextArea hint = new JTextArea(
                "Rules define what Quimera looks for in a response header. \"Missing\" fires when a " +
                "mandatory header is absent; \"Checks\" run when the header IS present (regex match/no-match " +
                "→ severity + description). Changes apply to new traffic immediately and persist across restarts.");
        hint.setEditable(false);
        hint.setFocusable(false);
        hint.setOpaque(false);
        hint.setLineWrap(true);
        hint.setWrapStyleWord(true);
        hint.setFont(hint.getFont().deriveFont(Font.ITALIC, 11f));
        hint.setForeground(Color.GRAY);
        hint.setBorder(BorderFactory.createEmptyBorder(4, 6, 6, 6));

        JPanel north = new JPanel(new BorderLayout());
        north.add(toolbar, BorderLayout.NORTH);
        north.add(hint, BorderLayout.SOUTH);

        add(north, BorderLayout.NORTH);
        add(scrollPane(table), BorderLayout.CENTER);
    }

    private RuleDefinition selected() {
        int row = table.getSelectedRow();
        if (row < 0) return null;
        int modelRow = table.convertRowIndexToModel(row);
        return modelRow < shown.size() ? shown.get(modelRow) : null;
    }

    private void reload() {
        shown = ruleStore.all();
        model.setRowCount(0);
        for (RuleDefinition rd : shown) {
            model.addRow(new Object[]{
                    rd.enabled, rd.headerName, rd.mandatory ? "Mandatory" : "Optional",
                    rd.checks.size(), rd.builtin ? "Built-in" : "Custom"
            });
        }
    }

    private void doExport() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Export Quimera Rules");
        fc.setSelectedFile(new File("quimera-rules.json"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        File file = fc.getSelectedFile();
        if (!file.getName().toLowerCase().endsWith(".json")) file = new File(file.getAbsolutePath() + ".json");
        try {
            Files.writeString(file.toPath(), ruleStore.exportJson());
            JOptionPane.showMessageDialog(this, "Rules exported to:\n" + file.getAbsolutePath(),
                    "Export OK", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void doImport() {
        int warn = JOptionPane.showConfirmDialog(this,
                "Importing replaces the ENTIRE current rule set. Continue?",
                "Import Rules", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (warn != JOptionPane.YES_OPTION) return;

        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("Import Quimera Rules");
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            String json = Files.readString(fc.getSelectedFile().toPath());
            ruleStore.importJson(json);
            reload();
            JOptionPane.showMessageDialog(this, "Rules imported (" + shown.size() + " total).",
                    "Import OK", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Import failed: " + ex.getMessage(),
                    "Import Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
