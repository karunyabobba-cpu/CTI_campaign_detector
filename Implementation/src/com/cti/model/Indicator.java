package com.cti.model;

import java.util.Objects;

public abstract class Indicator {
    private String value;
    private int riskScore;
    private String mitreTechnique;
    private String campaignId;

    public Indicator(String value, int riskScore, String mitreTechnique) {
        this.value = value;
        this.riskScore = riskScore;
        this.mitreTechnique = mitreTechnique;
        this.campaignId = "UNASSIGNED";
    }

    public abstract String getIndicatorType();
    public abstract String getThreatSummary();

    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getMitreTechnique() { return mitreTechnique; }
    public void setMitreTechnique(String mitreTechnique) { this.mitreTechnique = mitreTechnique; }

    public String getCampaignId() { return campaignId; }
    public void setCampaignId(String campaignId) { this.campaignId = campaignId; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Indicator)) return false;
        Indicator that = (Indicator) o;
        return Objects.equals(value.toLowerCase(), that.value.toLowerCase());
    }

    @Override
    public int hashCode() {
        return Objects.hash(value.toLowerCase());
    }
}