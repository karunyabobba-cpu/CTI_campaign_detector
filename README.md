# OSINT-Driven CTI Framework for Coordinated Social Engineering Campaign Detection

**Project:** CTI Campaign Detector  |  **ID:** AP25110090053  |  **Language:** Java (Swing) + MySQL

A desktop Cyber Threat Intelligence (CTI) tool that reads suspicious messages (phishing emails and similar lures), extracts indicators of compromise (IOCs), enriches them with an OSINT threat-intel feed, and groups related indicators into **coordinated campaigns** using graph clustering. Results are shown in a Swing dashboard and stored in MySQL.

---

## Features

- **Entity extraction** – regex-based extraction of email addresses, domains and IPv4 addresses from message text.
- **Lure scoring (lightweight NLP)** – keyword scan for social-engineering phrases (`urgent`, `suspended`, `verify`, `security alert`, `password reset`, `refund`, `expired`, `claim`). Each hit adds 15 points, capped at 40. Messages with no lure keywords are ignored (e.g. the benign university newsletter).
- **Threat-intel enrichment** – indicators found in `threat_intel_feeds.csv` take the feed's MITRE ATT&CK technique and risk score; unknown ones default to `50 + lure boost` and `T1566 - Social Engineering Phishing`.
- **Graph clustering** – indicators that appear in the same message are linked, as are emails and their own sender domain. Connected components (found with BFS) become campaigns (`CAMP-001`, `CAMP-002`, ...).
- **Dashboard** – table of IOCs, plus a text "knowledge graph" report per campaign with average risk and primary MITRE tactic.
- **MySQL persistence** – save results, reload them, edit an IOC's risk score, or delete an IOC.

## How it works

```
suspicious_messages.csv ──► EntityExtractor ──► indicators + co-occurrence edges
threat_intel_feeds.csv  ──►  (enrichment)                │
                                                         ▼
                                              GraphClusterEngine (BFS)
                                                         │
                                                         ▼
                                       CampaignCluster list ──► Swing dashboard
                                                         └────► MySQL (cti_campaign_db)
```

With the bundled sample data the tool finds **two campaigns**:

| Campaign | Linked indicators | Threat actor in feed |
|---|---|---|
| Campaign #1 | `paypa1-verify.com`, `192.168.45.12`, `amazon-refunds.org`, and the related sender emails | APT-ShadowFin |
| Campaign #2 | `micros0ft-update.net`, `10.200.14.88`, and the related sender emails | UNC-4012 |

MSG005 mentions both `paypa1-verify.com` and `billing@amazon-refunds.org`, which is what pulls the Amazon-themed refund lure into the first campaign.

## Project structure

```
CTI_Campaign_Detector_AP25110090053/
├── Dataset/
│   ├── suspicious_messages.csv     # 6 sample messages (msg_id, sender, subject, body, timestamp)
│   └── threat_intel_feeds.csv      # 5 OSINT indicators (value, type, MITRE technique, risk, actor)
├── Implementation/                 # NetBeans (Ant) project
│   ├── src/com/cti/
│   │   ├── model/       Indicator (abstract), DomainIndicator, IpIndicator,
│   │   │                EmailIndicator, CampaignCluster
│   │   ├── service/     OSINTAnalyzer (interface), EntityExtractor, GraphClusterEngine
│   │   ├── db/          DatabaseManager (JDBC access)
│   │   ├── exception/   CTIAnalysisException
│   │   └── ui/          CTIDashboardFrame (main class)
│   ├── database_setup.sql          # creates the schema
│   ├── build.xml, nbproject/       # NetBeans project files
│   └── build/                      # compiled classes
├── Documentation/README.md         # original short run notes
├── Report/report.docx
└── PPT/ppt.pdf
```

## Database schema

Database `cti_campaign_db`, created by `Implementation/database_setup.sql`:

- **`threat_indicators`** – `id`, `indicator_value` (unique), `indicator_type`, `mitre_technique`, `risk_score`, `campaign_id`, `detected_at`
- **`detected_campaigns`** – `campaign_id` (PK), `campaign_name`, `indicator_count`, `avg_risk_score`, `mitre_tactic`

## Requirements

- JDK (the NetBeans project is set to `javac.source/target = 26`; lower both in *Project Properties → Sources* if you use an older JDK, e.g. 17 or 21)
- Apache NetBeans
- MySQL Server and MySQL Workbench
- MySQL Connector/J (`mysql-connector-j-*.jar`)

## Setup and run

1. **Create the database.** In MySQL Workbench, run `Implementation/database_setup.sql`.
2. **Open the project.** In NetBeans: *File → Open Project* and select the `Implementation` folder.
3. **Add the MySQL driver.** Right-click *Libraries → Add JAR/Folder* and choose your `mysql-connector-j-*.jar`. The bundled project properties point to a path on the original author's machine, so you must re-point it.
4. **Set your credentials.** In `DatabaseManager.java`, set `USER` and `PASSWORD` to your MySQL login. The default URL is `jdbc:mysql://localhost:3306/cti_campaign_db`.
5. **Set the main class** to `com.cti.ui.CTIDashboardFrame` (*Project Properties → Run*), then run it.
6. **Use the dashboard:**
   - **1. Select Dataset CSV** – optionally pick a different messages file.
   - **2. Run OSINT & Graph Clustering** – extract, enrich, cluster, and save to MySQL.
   - **Load Saved DB Records** – show what is stored in MySQL.
   - **Update Selected Risk** – change the risk score (0–100) of the selected IOC.
   - **Delete Selected IOC** – remove the selected IOC from MySQL.

> **Working directory matters.** The default dataset paths are `../Dataset/suspicious_messages.csv` and `../Dataset/threat_intel_feeds.csv`, relative to where the app is launched. Running from the `Implementation` folder (NetBeans' default) makes them resolve correctly. Otherwise, use *Select Dataset CSV*. Note that the button only changes the messages file; the intel feed path stays at its default.

## Input formats

**`suspicious_messages.csv`**

```
msg_id,sender,subject,body,timestamp
MSG001,support@paypa1-verify.com,Urgent: Account Suspended,Please verify your login at http://paypa1-verify.com/login ...,2026-10-01 09:15:00
```

**`threat_intel_feeds.csv`**

```
indicator_value,indicator_type,mitre_technique,risk_score,threat_actor
paypa1-verify.com,DOMAIN,T1566.002 - Spearphishing Link,92,APT-ShadowFin
```

Both files are parsed by simple line reading and splitting on commas, so avoid extra commas inside fields.

## Known limitations

- **`src/com/cti/db/DatabaseManager.java` in this zip is a copy of `CTIDashboardFrame.java`**, not the real database class, so the project will not compile from source as shipped. The correct compiled class is in `build/classes/com/cti/db/`. Restore the source file with `getConnection()`, `saveCampaignResults()`, `fetchAllIndicators()`, `updateIndicatorRisk()` and `deleteIndicator()` before building.

- Only `http://` / `https://` URLs and `@` senders are recognised as domains; bare domains in text are not extracted.
- Lure detection is keyword-based, not a trained NLP model.
- The IP regex matches any dotted quad (it does not check each octet is ≤ 255).
- Each CSV is read line by line, so a message body containing a comma will be split incorrectly in the feed file and a multi-line body will not be handled.
- Database credentials are hard-coded in `DatabaseManager.java`; do not commit real passwords.

## Author

Student ID: AP25110090053
