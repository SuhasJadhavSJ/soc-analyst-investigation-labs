# SOC Analyst Investigation Labs & Case Studies

A structured repository documenting hands-on triage, log correlation, threat intelligence analysis, and incident response procedures conducted across simulated enterprise environments (LetsDefend Blue Team Platform). 

Each case study follows standard Security Operations Center (SOC) Tier 1 / Level 1 triage workflows, aligning telemetry across email security gateways, proxy/firewall perimeter logs, and endpoint detection and response (EDR) platforms with the MITRE ATT&CK framework.

---

## 📁 Repository Structure

```text
├── README.md                                          # Portfolio dashboard & incident index
└── investigations/                                    # Detailed SOC incident reports
    ├── SOC-EventID-93-Exchange-Phishing-Excel-Macro.md # Spearphishing macro analysis (In Progress)
    ├── SOC-EventID-86-Proxy-Phishing-URL.md            # Outbound credential phishing investigation
    └── SOC-EventID-36-Endpoint-Malware-Detected.md     # Host malware triage & hash verification