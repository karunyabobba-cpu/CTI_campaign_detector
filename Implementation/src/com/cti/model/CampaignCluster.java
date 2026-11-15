package com.cti.model;

import java.util.ArrayList;
import java.util.List;

public class CampaignCluster {
    private final String campaignId;
    private final String campaignName;
    private final List<Indicator> indicators;

    public CampaignCluster(String campaignId, String campaignName) {
        this.campaignId = campaignId;
        this.campaignName = campaignName;
        this.indicators = new ArrayList<>();
    }

    public void addIndicator(Indicator indicator) {
        indicator.setCampaignId(this.campaignId);
        if (!indicators.contains(indicator)) {
            indicators.add(indicator);
        }
    }

    public double getAverageRiskScore() {
        return indicators.stream()
                .mapToInt(Indicator::getRiskScore)
                .average()
                .orElse(0.0);
    }

    public String getPrimaryMitreTactic() {
        return indicators.stream()
                .map(Indicator::getMitreTechnique)
                .filter(t -> t != null && !t.equals("Unknown"))
                .findFirst()
                .orElse("T1566 - Phishing");
    }

    public String getCampaignId() { return campaignId; }
    public String getCampaignName() { return campaignName; }
    public List<Indicator> getIndicators() { return indicators; }
}