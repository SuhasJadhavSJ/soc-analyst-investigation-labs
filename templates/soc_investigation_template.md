# [INCIDENT REPORT] Event ID: <ID> - <Rule Name>

## 1. Executive Summary
- **Verdict:** [True Positive / False Positive]
- **Severity:** [Low / Medium / High / Critical]
- **Status:** Closed / Escalated to L2
- **Summary:** Concise summary answering: What happened? Did the attack succeed? What is the containment state?

---

## 2. Alert Metadata
| Parameter | Value |
| :--- | :--- |
| **Event ID** | <e.g., 93> |
| **Alert Trigger Time** | <YYYY-MM-DD HH:MM:SS> |
| **Rule Name** | <e.g., SOC146 - Phishing Mail Detected - Excel 4.0 Macros> |
| **Alert Type** | <Exchange / Proxy / Malware / Endpoint> |
| **Source / Sender** | <Source IP / Sender Address> |
| **Destination / Target** | <Target User / Destination IP> |
| **Device Action** | Allowed / Blocked |

---

## 3. Investigation Playbook & Triage Steps

### Step 1: Ingestion & Initial Scoping
- **Action:** Created case ticket for EventID `<ID>`.
- **Initial Observation:** Review alert severity, device action (e.g., `Allowed` indicates payload reached the user mailbox or host).

### Step 2: Evidence & Cross-Platform Pivoting
<!-- Include findings based on the alert type -->
- **Email Security / Message Tracking:**
  - Sender: `sender[@]domain[.]com`
  - Subject: `<Subject Line>`
  - Attachment / URL: `<Defanged Name/Link>` (SHA256: `<Hash>`)
- **Threat Intelligence (VT, AbuseIPDB, Any.Run):**
  - SMTP / Source IP Reputation: `<Reputation score and classification>`
  - Artifact Detection: `<X/Y engine detections, malicious behaviors>`
- **Log Management & Network Traffic:**
  - Search internal host IP for outbound requests around alert timestamp.
  - Proxy/Firewall logs: Destination IP, HTTP status codes, bytes sent/received.
- **Endpoint Security (EDR):**
  - Check host process tree: Parent PID $\rightarrow$ Child PID $\rightarrow$ Command-line args.
  - Check active connections or persistence (Registry run keys, scheduled tasks).

---

## 4. Analysis & Correlated Evidence Table
*Curated records extracted during triage:*

| Timestamp | Source | Destination | Event / Command / Status | Significance |
| :--- | :--- | :--- | :--- | :--- |
| 2021-06-13 14:13:28 | 24.213.228[.]54 | lars[@]letsdefend[.]io | SMTP Inbound - Allowed | Phishing delivery |
| 2021-06-13 14:15:02 | 172.16.17.45 | 198.51.100[.]14:443 | HTTP GET - 200 OK | Payload downloaded |

---

## 5. Artifacts & Indicators of Compromise (IOCs)
| Type | Indicator (Defanged) | Context / Classification |
| :--- | :--- | :--- |
| **IPv4** | `24.213.228[.]54` | External Mail Relay / Malicious Sender |
| **Domain/URL**| `hxxp[://]malicious-domain[.]com/login` | Phishing Landing Page |
| **SHA256** | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Malicious Macro Document |

---

## 6. Containment & Remediation Actions
1. **Endpoint Isolation:** Quarantined host `<Hostname>` via EDR to prevent lateral movement.
2. **Mailbox Purge:** Deleted malicious email from target inbox and searched Exchange logs for other recipients.
3. **Network Block:** Blocked sender domain and external C2 IP on perimeter firewall and web proxy.
4. **Credential Reset:** Initiated password reset and revoked active sessions for compromised account.

---

## 7. Lessons Learned & Tuning Suggestions
- **Detection Engineering:** Implement/tune firewall rules to block inbound Office documents containing XLM 4.0 macro structures.