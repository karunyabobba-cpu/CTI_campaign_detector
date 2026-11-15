package com.cti.model;

public class IpIndicator extends Indicator {
    public IpIndicator(String ipAddress, int riskScore, String mitreTechnique) {
        super(ipAddress, riskScore, mitreTechnique);
    }

    @Override
    public String getIndicatorType() {
        return "IP_ADDRESS";
    }

    @Override
    public String getThreatSummary() {
        return "C2 / Phishing Host IP [" + getValue() + "] | Risk: " + getRiskScore();
    }
}