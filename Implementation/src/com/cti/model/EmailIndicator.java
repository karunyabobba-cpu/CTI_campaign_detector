package com.cti.model;

public class EmailIndicator extends Indicator {
    public EmailIndicator(String email, int riskScore, String mitreTechnique) {
        super(email, riskScore, mitreTechnique);
    }

    @Override
    public String getIndicatorType() {
        return "EMAIL";
    }

    @Override
    public String getThreatSummary() {
        return "Social Engineering Sender [" + getValue() + "] | Risk: " + getRiskScore();
    }
}