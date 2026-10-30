# SOC Analyst Investigation Labs & Case Studies

**Hands-on Security Operations Center (SOC) Investigations | Threat Detection | Incident Triage | Incident Response**

## About This Repository

This repository documents practical Security Operations Center (SOC) investigations performed in simulated enterprise environments using the **LetsDefend Blue Team Platform**.

The objective is to demonstrate practical SOC Tier 1 / L1 analyst capabilities through security alert investigation, log analysis, event correlation, threat intelligence enrichment, and incident response workflows.

Each investigation follows a structured analytical approach to identify suspicious activities, investigate potential threats, determine their impact, and document findings using industry-standard security frameworks.

## Investigation Capabilities

| Area | Investigation Focus |
|---|---|
| Alert Triage | Analyzing and prioritizing security alerts |
| Email Security | Investigating phishing and malicious emails |
| Log Analysis | Analyzing proxy, firewall, and endpoint logs |
| Threat Intelligence | Identifying malicious IPs, domains, and URLs |
| Event Correlation | Correlating security events across multiple sources |
| Endpoint Investigation | Investigating suspicious processes and activities |
| Incident Response | Documenting findings and recommending containment actions |
| MITRE ATT&CK | Mapping observed attacker techniques to ATT&CK |

## Investigation Case Studies

The following case studies contain detailed investigation reports, including alert analysis, evidence, investigation procedures, findings, and recommended response actions.

| ID | Investigation | Category | Report |
|---|---|---|---|
| 86 | Outbound Credential Phishing Investigation | Proxy / Web Security | [View Investigation](./investigations/SOC-EventID-86-Proxy-Phishing-URL.md) |
| 82 | Inbound Phishing Email with Suspicious Task Scheduler Activity | Email Security / Endpoint | [View Investigation](./investigations/SOC-EventID-82-Phishing-Mail-Detected-Suspicious-Task-Scheduler.md) |
| 52 | Internal-to-Internal Phishing Investigation | Email Security | [View Investigation](./investigations/SOC-EventID-52-Phishing-Mail-Detected-Internal-to-Internal.md) |
| 45 | Malicious Attachment Detected - Phishing Email | Email Security | [View Investigation](./investigations/SOC-Event-ID-45-Malicious-Attachment-Detected-Phishing-Alert.md) 

## SOC Investigation Methodology

Each case study follows a structured SOC investigation lifecycle:

1. **Alert Identification** – Understand the triggered security alert and its severity.
2. **Initial Triage** – Validate the alert and identify potentially suspicious indicators.
3. **Evidence Collection** – Collect relevant logs, timestamps, IP addresses, URLs, domains, and endpoint information.
4. **Log Correlation** – Correlate telemetry across available security sources.
5. **Threat Intelligence Analysis** – Investigate suspicious indicators and assess their reputation.
6. **MITRE ATT&CK Mapping** – Identify relevant adversary tactics and techniques.
7. **Impact Assessment** – Determine the potential scope and impact of the activity.
8. **Incident Classification** – Assess whether the activity is malicious, benign, or requires further investigation.
9. **Response Recommendations** – Document containment, remediation, and escalation recommendations.

## Tools & Technologies

- **SOC Platform:** LetsDefend
- **Security Monitoring:** SIEM / EDR telemetry
- **Network Security:** Proxy Logs, Firewall Logs
- **Email Security:** Email Header Analysis, Phishing Detection
- **Threat Intelligence:** IP, Domain, and URL Reputation Analysis
- **Framework:** MITRE ATT&CK
- **Documentation:** Markdown, Git, GitHub

## Framework Alignment

Investigations are mapped to the [MITRE ATT&CK Framework](https://attack.mitre.org/) wherever applicable to document observed attacker behaviors, tactics, and techniques.

## Repository Structure

```text
SOC-Analyst-Investigation-Labs/
│
├── README.md
│
└── investigations/
    ├── SOC-EventID-86-Proxy-Phishing-URL.md
    ├── SOC-EventID-82-Phishing-Mail-Detected-Suspicious-Task-Scheduler.md
    └── SOC-EventID-52-Phishing-Mail-Detected-Internal-to-Internal.md
    └── SOC-EventID-45-Malicious-Attachment-Detected-Phishing-Alert.md
```

## Disclaimer

All investigations documented in this repository are conducted in simulated environments for educational and professional development purposes.

The reports are intended to demonstrate SOC investigation methodologies and do not represent access to or analysis of unauthorized enterprise systems or confidential organizational data.

---

**Author:** Suhas Jadhav  
**Focus:** SOC Analyst | Blue Team | Threat Detection | Incident Response

