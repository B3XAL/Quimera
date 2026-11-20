package com.b3xal.headeranalyzer.ui.render;

import com.b3xal.headeranalyzer.model.FindingStatus;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/** Renders a FindingStatus (Open / Resolved / Reopened) as a colored badge in a table cell. */
public class StatusRenderer extends DefaultTableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                     boolean isSelected, boolean hasFocus,
                                                     int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        setHorizontalAlignment(SwingConstants.CENTER);
        setFont(getFont().deriveFont(Font.BOLD, 11f));

        if (value instanceof FindingStatus status) {
            setText(status.label);
            if (!isSelected) {
                switch (status) {
                    case OPEN     -> { c.setBackground(new Color(211, 127,   0)); c.setForeground(Color.WHITE); }
                    case RESOLVED -> { c.setBackground(new Color( 39, 174,  96)); c.setForeground(Color.WHITE); }
                    case REOPENED -> { c.setBackground(new Color(192,  57,  43)); c.setForeground(Color.WHITE); }
                }
            }
        } else {
            setText(value != null ? value.toString() : "");
            if (!isSelected) { c.setBackground(table.getBackground()); c.setForeground(table.getForeground()); }
        }
        return c;
    }
}
