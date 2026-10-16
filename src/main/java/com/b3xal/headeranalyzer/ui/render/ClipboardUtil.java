package com.b3xal.headeranalyzer.ui.render;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.image.BufferedImage;

/**
 * Copy-to-clipboard helpers for the Report tab's "evidence for a screenshot" workflow:
 * render any JComponent as a PNG-quality image (pasteable directly into Word/a ticket),
 * or copy plain text/Markdown.
 */
public final class ClipboardUtil {

    private ClipboardUtil() {}

    public static void copyImage(JComponent component) {
        int w = component.getWidth();
        int h = component.getHeight();
        if (w <= 0 || h <= 0) {
            w = component.getPreferredSize().width;
            h = component.getPreferredSize().height;
            component.setSize(w, h);
            component.doLayout();
        }
        BufferedImage img = new BufferedImage(Math.max(w, 1), Math.max(h, 1), BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = img.createGraphics();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        component.paint(g2);
        g2.dispose();

        Transferable transferable = new Transferable() {
            @Override public java.awt.datatransfer.DataFlavor[] getTransferDataFlavors() {
                return new java.awt.datatransfer.DataFlavor[]{java.awt.datatransfer.DataFlavor.imageFlavor};
            }
            @Override public boolean isDataFlavorSupported(java.awt.datatransfer.DataFlavor flavor) {
                return java.awt.datatransfer.DataFlavor.imageFlavor.equals(flavor);
            }
            @Override public Object getTransferData(java.awt.datatransfer.DataFlavor flavor) {
                return img;
            }
        };
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(transferable, null);
    }

    public static void copyText(String text) {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(new StringSelection(text == null ? "" : text), null);
    }
}
