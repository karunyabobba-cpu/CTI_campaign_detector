package com.cti.service;

import com.cti.exception.CTIAnalysisException;
import com.cti.model.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class EntityExtractor implements OSINTAnalyzer<Indicator> {

    private static final Pattern EMAIL_PATTERN = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("(?<=http://|https://|@)[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

    private final List<Set<String>> coOccurrenceEdges = new ArrayList<>();

    public List<Set<String>> getCoOccurrenceEdges() {
        return coOccurrenceEdges;
    }

    @Override
    public List<Indicator> analyzeSource(File datasetFile, File intelFeedFile) throws CTIAnalysisException {
        Map<String, String[]> threatIntelMap = loadThreatIntel(intelFeedFile);
        Map<String, Indicator> extractedMap = new LinkedHashMap<>();
        coOccurrenceEdges.clear();

        try (BufferedReader br = new BufferedReader(new FileReader(datasetFile))) {
            String line = br.readLine(); // skip header
            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty()) continue;

                int nlpUrgencyBoost = calculateNlpUrgencyScore(line);
                if (nlpUrgencyBoost == 0) continue;

                Set<String> messageEntities = new HashSet<>();

                Matcher emailMatcher = EMAIL_PATTERN.matcher(line);
                while (emailMatcher.find()) {
                    String email = emailMatcher.group().toLowerCase();
                    messageEntities.add(email);
                    extractedMap.putIfAbsent(email, createEnrichedIndicator(email, "EMAIL", nlpUrgencyBoost, threatIntelMap));
                }

                Matcher domainMatcher = DOMAIN_PATTERN.matcher(line);
                while (domainMatcher.find()) {
                    String domain = domainMatcher.group().toLowerCase();
                    messageEntities.add(domain);
                    extractedMap.putIfAbsent(domain, createEnrichedIndicator(domain, "DOMAIN", nlpUrgencyBoost, threatIntelMap));
                }

                Matcher ipMatcher = IP_PATTERN.matcher(line);
                while (ipMatcher.find()) {
                    String ip = ipMatcher.group();
                    messageEntities.add(ip);
                    extractedMap.putIfAbsent(ip, createEnrichedIndicator(ip, "IP", nlpUrgencyBoost, threatIntelMap));
                }

                if (messageEntities.size() > 1) {
                    coOccurrenceEdges.add(messageEntities);
                }
            }
        } catch (IOException e) {
            throw new CTIAnalysisException("Failed reading suspicious messages dataset: " + e.getMessage(), e);
        }

        return new ArrayList<>(extractedMap.values());
    }

    private int calculateNlpUrgencyScore(String text) {
        String lower = text.toLowerCase();
        String[] lures = {"urgent", "suspended", "verify", "security alert", "password reset", "refund", "expired", "claim"};
        int score = 0;
        for (String lure : lures) {
            if (lower.contains(lure)) score += 15;
        }
        return Math.min(score, 40);
    }

    private Map<String, String[]> loadThreatIntel(File intelFile) throws CTIAnalysisException {
        Map<String, String[]> intel = new HashMap<>();
        if (intelFile == null || !intelFile.exists()) return intel;

        try (BufferedReader br = new BufferedReader(new FileReader(intelFile))) {
            String line = br.readLine();
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length >= 4) {
                    intel.put(parts[0].trim().toLowerCase(), parts);
                }
            }
        } catch (IOException e) {
            throw new CTIAnalysisException("Failed reading OSINT threat intel feed: " + e.getMessage(), e);
        }
        return intel;
    }

    private Indicator createEnrichedIndicator(String val, String type, int nlpBoost, Map<String, String[]> intelMap) {
        int baseRisk = 50 + nlpBoost;
        String mitre = "T1566 - Social Engineering Phishing";

        if (intelMap.containsKey(val)) {
            String[] info = intelMap.get(val);
            mitre = info[2].trim();
            baseRisk = Math.min(100, Integer.parseInt(info[3].trim()));
        }

        switch (type) {
            case "DOMAIN": return new DomainIndicator(val, baseRisk, mitre);
            case "IP": return new IpIndicator(val, baseRisk, mitre);
            default: return new EmailIndicator(val, baseRisk, mitre);
        }
    }
}