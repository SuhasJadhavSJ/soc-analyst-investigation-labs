# [INCIDENT REPORT] Event ID: 45 - SOC114 Malicious Attachment Detected - Phishing Alert

## 1. Executive Summary
- **Verdict:** True Positive (Weaponized Password-Protected Archive / Dropper)
- **Severity:** High
- **Status:** Closed / Remediated
- **Summary:** An inbound spearphishing email originating from `accounting@cmail.carleton.ca` via SMTP relay `49.234.43.39` targeted internal user `richard@letsdefend.io` under the subject "Invoice". The message contained an encrypted, password-protected ZIP archive titled `c9ad9506bcccfaa987ff9fc11b91698d.zip` (password: `infected`) designed to evade email gateway static inspection. Threat intelligence sandboxing flagged the payload as a malicious trojan downloader attempting to retrieve secondary stage executables (`network.exe`) from `andaluciabeach.net` and connect to dynamic DNS infrastructure. Log Management confirmed whether user execution occurred, leading to email quarantine and indicator blocking.

---

## 2. Alert Metadata
| Parameter | Value |
| :--- | :--- |
| **Event ID** | 45 |
| **Alert Trigger Time** | 2021-01-31T15:48:30+03:00 |
| **Rule Name** | SOC114 - Malicious Attachment Detected - Phishing Alert |
| **MITRE ATT&CK ID** | T1598.001 (Spearphishing Attachment) |
| **Log Source / Layer** | Exchange / Email Security |
| **Source Address / Relay** | accounting@cmail.carleton.ca (SMTP: 49.234.43.39) |
| **Destination Address** | richard@letsdefend.io |
| **Device Action** | Allowed |

---

## 3. Investigation Playbook & Triage Steps

### Step 1: Ingestion & Initial Scoping
- **Ticket Ingestion:** Claimed and initiated active investigation for Event ID 45 in Case Management.
- **Initial Telemetry Assessment:**
  - Inbound email delivered to internal employee `richard@letsdefend.io`.
  - Gateway recorded `Device Action: Allowed`, confirming the email reached the user's inbox because standard perimeter scanners could not unpack the password-protected archive automatically.
  - Initial triage priority focused on sandbox detonation and verification of host execution.

### Step 2: Email Security & Artifact Extraction
- Accessed Email Security console and retrieved message details:
  - **Sender Display / Header:** `accounting@cmail.carleton.ca`
  - **SMTP Relay:** `49.234.43.39`
  - **Subject:** `Invoice`
  - **Body / Lure:** "Dear customer, Your invoice for the shopping you..." with clear social engineering financial pretext.
  - **Attachment:** `c9ad9506bcccfaa987ff9fc11b91698d.zip`
  - **Archive Password Provided in Body:** `infected`
  - **Attachment Hash (SHA-256):** `5c34c14865f4a98f6cc623710e445f479175aeafafcb55614b139fb61cff9de7`

### Step 3: Threat Intelligence & Sandbox Detonation
- **VirusTotal Telemetry:**
  - Flagged by multiple engines as `Trojan.GenericKD` / `Trojan.Generic`.
  - Identified behavior: Password-protected ZIP evasion, sets process names, and detects debug environments.
- **Hybrid-Analysis Detonation:**
  - Threat Score: **100 / 100 (Malicious)**.
  - AV Detection: Malicious Trojan.Generic family.
- **C2 & Infrastructure Relations:**
  - Outbound payload delivery URL: `hxxp[://]andaluciabeach[.]net/image/network.exe`
  - Contacted dynamic DNS domain: `eichelberger[.]duckdns[.]org`
  - Contacted IP addresses: `45.137.22.189`, `70.38.21.229`

### Step 4: Endpoint Security & Log Management Correlation
- Queried Log Management for destination IP addresses `45.137.22.189` and `70.38.21.229`, and requested domains `andaluciabeach.net` and `eichelberger.duckdns.org`:
  - Correlated with egress logs for workstation assigned to user `richard@letsdefend.io`.
  - Confirmed no outbound connections to the C2 addresses or secondary executable drops (`network.exe`) occurred.
  - If user opened/ran payload: Executed immediate host isolation via EDR console; otherwise confirmed zero execution.

---

## 4. Evidence & Telemetry Logs

| Timestamp | Source Address / IP | Destination Address | Action Taken | Context / Findings |
| :--- | :--- | :--- | :--- | :--- |
| **2021-01-31 18:18:30** | accounting@cmail.carleton.ca (49.234.43.39) | richard@letsdefend.io | ALLOWED | Inbound email delivered with password-protected ZIP |
| **2021-01-31 18:20+** | Richard's Host IP | External Perimeter | Evaluated | Checked for C2 beacons (`45.137.22.189` / `andaluciabeach.net`) |

---

## 5. Artifacts & Indicators of Compromise (IOCs)

| Artifact Type | Value (Raw) | Value (Defanged) | Context / Classification |
| :--- | :--- | :--- | :--- |
| **Email Sender** | `accounting@cmail.carleton.ca` | `accounting[@]cmail[.]carleton[.]ca` | Compromised external sender address |
| **SMTP IPv4** | `49.234.43.39` | `49.234.43[.]39` | Originating Mail Relay |
| **Attachment File** | `c9ad9506bcccfaa987ff9fc11b91698d.zip` | `c9ad9506bcccfaa987ff9fc11b91698d[.]zip` | Encrypted Trojan Dropper Archive |
| **SHA-256 Hash** | `5c34c14865f4a98f6cc623710e445f479175aeafafcb55614b139fb61cff9de7` | `5c34c14865f4a98f6cc623710e445f479175aeafafcb55614b139fb61cff9de7` | Malicious Archive SHA-256 |
| **C2 Domain** | `andaluciabeach.net` | `andaluciabeach[.]net` | Payload Distribution Server |
| **C2 Domain** | `eichelberger.duckdns.org` | `eichelberger[.]duckdns[.]org` | Malicious Dynamic DNS C2 |
| **C2 URL** | `http://andaluciabeach.net/image/network.exe` | `hxxp[://]andaluciabeach[.]net/image/network[.]exe` | Second-stage dropped executable |
| **C2 IPv4** | `45.137.22.189` | `45.137.22[.]189` | Malicious C2 IP |
| **C2 IPv4** | `70.38.21.229` | `70.38.21[.]229` | Malicious C2 IP |

---

## 6. Containment & Remediation Actions Taken
1. **Mailbox Purge:** Deleted the malicious email message and encrypted attachment directly from Richard's inbox via Email Security.
2. **Perimeter Blacklisting:** Submitted sender IP `49.234.43.39`, domain `andaluciabeach.net`, and C2 IPs `45.137.22.189` / `70.38.21.229` to edge firewall and mail gateway blocklists.
3. **Endpoint Verification:** Checked EDR to verify no unauthorized child processes (`powershell.exe`, `cmd.exe`) spawned or downloaded `network.exe`.
4. **Detection Tuning Recommendation:** Recommend updating the email gateway to flag or quarantine incoming emails that include passwords in plain text alongside password-protected archive attachments to defeat automated scanning evasion.

---

## 7. Final Verdict
*   **Verdict:** **True Positive**
*   **Incident Type:** Inbound Spearphishing / Trojan Dropper (Evasion via Password-Protected Archive)
*   **Resolution:** Remediated & Closed.