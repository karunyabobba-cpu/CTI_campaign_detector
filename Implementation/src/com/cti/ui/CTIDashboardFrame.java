package com.cti.ui;

import com.cti.db.DatabaseManager;
import com.cti.model.CampaignCluster;
import com.cti.model.Indicator;
import com.cti.service.EntityExtractor;
import com.cti.service.GraphClusterEngine;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.util.List;

public class CTIDashboardFrame extends JFrame {
    private final DefaultTableModel tableModel;
    private final JTable indicatorTable;
    private final JTextArea graphSummaryArea;
    private final JLabel statusLabel;
    private final DatabaseManager dbManager = new DatabaseManager();

    private File selectedDatasetFile = new File("../Dataset/suspicious_messages.csv");
    private File selectedIntelFile = new File("../Dataset/threat_intel_feeds.csv");

    public CTIDashboardFrame() {
        setTitle("OSINT-Driven CTI Framework - Coordinated Social Engineering Campaign Detector");
        setSize(1050, 650);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(10, 10));

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 10));
        topPanel.setBackground(new Color(30, 41, 59));

        JButton btnLoadCsv = new JButton("1. Select Dataset CSV");
        JButton btnRunAnalysis = new JButton("2. Run OSINT & Graph Clustering");
        JButton btnLoadDb = new JButton("Load Saved DB Records");
        JButton btnUpdateRisk = new JButton("Update Selected Risk");
        JButton btnDeleteRow = new JButton("Delete Selected IOC");

        styleButton(btnLoadCsv, new Color(59, 130, 246));
        styleButton(btnRunAnalysis, new Color(16, 185, 129));
        styleButton(btnLoadDb, new Color(99, 102, 241));
        styleButton(btnUpdateRisk, new Color(245, 158, 11));
        styleButton(btnDeleteRow, new Color(239, 68, 68));

        topPanel.add(btnLoadCsv);
        topPanel.add(btnRunAnalysis);
        topPanel.add(btnLoadDb);
        topPanel.add(btnUpdateRisk);
        topPanel.add(btnDeleteRow);
        add(topPanel, BorderLayout.NORTH);

        String[] columns = {"Campaign ID", "IOC Type", "Indicator Value", "Risk Score", "MITRE ATT&CK Technique"};
        tableModel = new DefaultTableModel(columns, 0);
        indicatorTable = new JTable(tableModel);
        indicatorTable.setRowHeight(25);
        JScrollPane tableScroll = new JScrollPane(indicatorTable);
        tableScroll.setBorder(BorderFactory.createTitledBorder("Extracted & Enriched Indicators of Compromise (IOCs)"));

        graphSummaryArea = new JTextArea();
        graphSummaryArea.setEditable(false);
        graphSummaryArea.setFont(new Font("Monospaced", Font.PLAIN, 13));
        JScrollPane summaryScroll = new JScrollPane(graphSummaryArea);
        summaryScroll.setBorder(BorderFactory.createTitledBorder("Detected Coordinated Campaign Clusters (Knowledge Graph)"));

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tableScroll, summaryScroll);
        splitPane.setDividerLocation(620);
        add(splitPane, BorderLayout.CENTER);

        statusLabel = new JLabel(" Ready. Default dataset: Dataset/suspicious_messages.csv");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        add(statusLabel, BorderLayout.SOUTH);

        btnLoadCsv.addActionListener(e -> chooseDatasetFile());
        btnRunAnalysis.addActionListener(e -> runMultithreadedAnalysis());
        btnLoadDb.addActionListener(e -> loadFromDatabase());
        btnUpdateRisk.addActionListener(e -> updateSelectedRisk());
        btnDeleteRow.addActionListener(e -> deleteSelectedIndicator());
    }

    private void styleButton(JButton btn, Color bg) {
        btn.setBackground(bg);
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.setFont(new Font("SansSerif", Font.BOLD, 12));
    }

    private void chooseDatasetFile() {
        JFileChooser chooser = new JFileChooser(".");
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            selectedDatasetFile = chooser.getSelectedFile();
            statusLabel.setText(" Selected dataset: " + selectedDatasetFile.getAbsolutePath());
        }
    }

    private void runMultithreadedAnalysis() {
        statusLabel.setText(" Running NLP Entity Extraction, Threat Intel Enrichment & Graph Clustering...");
        SwingWorker<List<CampaignCluster>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<CampaignCluster> doInBackground() throws Exception {
                EntityExtractor extractor = new EntityExtractor();
                List<Indicator> indicators = extractor.analyzeSource(selectedDatasetFile, selectedIntelFile);

                GraphClusterEngine graphEngine = new GraphClusterEngine();
                List<CampaignCluster> clusters = graphEngine.detectCampaignClusters(indicators, extractor.getCoOccurrenceEdges());

                dbManager.saveCampaignResults(clusters);
                return clusters;
            }

            @Override
            protected void done() {
                try {
                    List<CampaignCluster> clusters = get();
                    populateTableAndGraphSummary(clusters);
                    statusLabel.setText(" Analysis complete! Detected " + clusters.size() + " coordinated campaigns & synced to MySQL.");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(CTIDashboardFrame.this, "Error: " + ex.getMessage(), "Analysis Error", JOptionPane.ERROR_MESSAGE);
                    statusLabel.setText(" Error during analysis.");
                }
            }
        };
        worker.execute();
    }

    private void populateTableAndGraphSummary(List<CampaignCluster> clusters) {
        tableModel.setRowCount(0);
        StringBuilder sb = new StringBuilder();
        sb.append("=== CAMPAIGN KNOWLEDGE GRAPH REPORT ===\n\n");

        for (CampaignCluster c : clusters) {
            sb.append("[").append(c.getCampaignId()).append("] ").append(c.getCampaignName()).append("\n");
            sb.append("  • Avg Risk Score : ").append(String.format("%.1f", c.getAverageRiskScore())).append("/100\n");
            sb.append("  • Primary Tactic : ").append(c.getPrimaryMitreTactic()).append("\n");
            sb.append("  • Linked Nodes   :\n");

            for (Indicator ind : c.getIndicators()) {
                tableModel.addRow(new Object[]{
                    c.getCampaignId(),
                    ind.getIndicatorType(),
                    ind.getValue(),
                    ind.getRiskScore(),
                    ind.getMitreTechnique()
                });
                sb.append("      -> (").append(ind.getIndicatorType()).append(") ").append(ind.getValue()).append("\n");
            }
            sb.append("----------------------------------------\n");
        }
        graphSummaryArea.setText(sb.toString());
    }

    private void loadFromDatabase() {
        try {
            List<String[]> rows = dbManager.fetchAllIndicators();
            tableModel.setRowCount(0);
            for (String[] row : rows) {
                tableModel.addRow(row);
            }
            statusLabel.setText(" Loaded " + rows.size() + " records from MySQL database.");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "DB Read Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void updateSelectedRisk() {
        int row = indicatorTable.getSelectedRow();
        if (row == -1) {
            JOptionPane.showMessageDialog(this, "Select an indicator row first.");
            return;
        }
        String iocValue = tableModel.getValueAt(row, 2).toString();
        String input = JOptionPane.showInputDialog(this, "Enter new Risk Score (0-100) for " + iocValue + ":");
        if (input != null) {
            try {
                int newScore = Integer.parseInt(input.trim());
                dbManager.updateIndicatorRisk(iocValue, newScore);
                tableModel.setValueAt(newScore, row, 3);
                statusLabel.setText(" Updated risk score for " + iocValue + " in MySQL.");
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Invalid input or DB error: " + ex.getMessage());
            }
        }
    }

    private void deleteSelectedIndicator() {
        int row = indicatorTable.getSelectedRow();
        if (row == -1) {
            JOptionPane.showMessageDialog(this, "Select an indicator row to delete.");
            return;
        }
        String iocValue = tableModel.getValueAt(row, 2).toString();
        try {
            dbManager.deleteIndicator(iocValue);
            tableModel.removeRow(row);
            statusLabel.setText(" Deleted " + iocValue + " from MySQL.");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, ex.getMessage(), "Delete Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new CTIDashboardFrame().setVisible(true));
    }
}