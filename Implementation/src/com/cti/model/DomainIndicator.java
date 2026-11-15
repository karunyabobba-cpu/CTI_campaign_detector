package com.cti.model;

public class DomainIndicator extends Indicator {
    public DomainIndicator(String domain, int riskScore, String mitreTechnique) {
        super(domain, riskScore, mitreTechnique);
    }

    @Override
    public String getIndicatorType() {
        return "DOMAIN";
    }

    @Override
    public String getThreatSummary() {
        return "Malicious/Lookalike Domain [" + getValue() + "] | Risk: " + getRiskScore();
    }
}