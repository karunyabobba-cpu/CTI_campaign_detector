CREATE DATABASE IF NOT EXISTS cti_campaign_db;
USE cti_campaign_db;

CREATE TABLE IF NOT EXISTS threat_indicators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    indicator_value VARCHAR(255) NOT NULL UNIQUE,
    indicator_type VARCHAR(50) NOT NULL,
    mitre_technique VARCHAR(150),
    risk_score INT DEFAULT 50,
    campaign_id VARCHAR(50),
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS detected_campaigns (
    campaign_id VARCHAR(50) PRIMARY KEY,
    campaign_name VARCHAR(150),
    indicator_count INT,
    avg_risk_score DOUBLE,
    mitre_tactic VARCHAR(150)
);

USE cti_campaign_db;
SELECT * FROM detected_campaigns;
SELECT * FROM threat_indicators;