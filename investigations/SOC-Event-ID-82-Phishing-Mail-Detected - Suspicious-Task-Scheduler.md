# [INCIDENT REPORT] Event ID: 82 - Phishing Mail Detected - Suspicious Task Scheduler

## 1. Executive Summary
- **Verdict:** True Positive (Malicious PDF Weaponized / Persistence via Task Scheduler)
- **Severity:** Medium
- **Status:** Closed / Remediated
- **Summary:** An inbound spearphishing email originated from external address `aaronluo@cmail.carleton.ca` via SMTP relay `189.162.189.159` targeting internal user `mark@letsdefend.io`. The message contained a weaponized attachment titled `Material.pdf`. Threat intelligence validation confirmed malicious intent (VirusTotal: 30/61 detections, Hybrid-Analysis: 100/100 score). The email gateway successfully enforced perimeter policy with `Device Action: Blocked`, preventing delivery to the user's inbox and neutralizing host-level execution risk.

---

## 2. Alert Metadata
| Parameter | Value |
| :--- | :--- |
| **Event ID** | 82 |
| **Alert Trigger Time** | 2021-03-21T12:26:57+03:00 |
| **Rule Name** | Phishing Mail Detected - Suspicious Task Scheduler |
| **Source Address / Relay** | aaronluo@cmail.carleton.ca (SMTP: 189.162.189.159) |
| **Destination Address** | mark@letsdefend.io |
| **Device Action** | Blocked |

---

## 3. Investigation Playbook & Triage Steps

### Step 1: Ingestion & Initial Scoping
- **Ticket Ingestion:** Claimed and initiated active investigation for Event ID 82 in Case Management.
- **Initial Telemetry Assessment:**
  - Inbound email alert triggered under rule `Phishing Mail Detected - Suspicious Task Scheduler`.
  - Target identity identified as internal user `mark@letsdefend.io`.
  - Security control registered `Device Action: Blocked`, confirming the malicious message was intercepted at the mail gateway layer and quarantined prior to mailbox delivery.

### Step 2: Email Security & Artifact Extraction
- Inspected the quarantined message details:
  - **Sender Display / Header:** `aaronluo@cmail.carleton.ca`
  - **Originating SMTP Relay:** `189.162.189.159`
  - **Attached Artifact:** `Material.pdf` (Size: 350.14 KB)
  - **Extracted SHA-256:** `39fb927c32221134a423760c5d1f58bca4cbbcc87c891c79e390a22b63608eb4`
  - **Extracted MD5:** `72c812cf21909a48eb9cceb9e04b865d`

### Step 3: Threat Intelligence & Sandbox Verification
- **VirusTotal Telemetry:**
  - Multi-engine detection: **30 / 61 vendors flagged as malicious**.
  - Behavioral tags: `pdf`, `calls-wmi`, `direct-cpu-clock-access`, `checks-network-adapters`, `detect-debug-environment`, `acroform`.
- **Hybrid-Analysis Telemetry:**
  - Threat Score: **100 / 100 (Malicious)**.
  - Identified automated persistence mechanisms designed to create scheduled tasks (`Suspicious Task Scheduler` execution behavior).

### Step 4: Endpoint & Network Impact Assessment
- Correlated Log Management records for host associated with `mark@letsdefend.io`:
  - Verified no outbound network handshakes or C2 callbacks occurred to the sender IP `189.162.189.159`.
  - Confirmed the file was not delivered or opened on the endpoint (`Device Action: Blocked`).
  - No host isolation required as zero endpoint interaction took place.

---

## 4. Correlated Telemetry & Evidence

| Timestamp (UTC) | Log Source | Source Address | Destination Address | Action Taken | Context / Payload |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **2021-03-21 12:26:57** | Email Gateway | aaronluo@cmail.carleton.ca (189.162.189.159) | mark@letsdefend.io | BLOCKED | Inbound delivery quarantined; contains `Material.pdf` |

---

## 5. Artifacts & Indicators of Compromise (IOCs)

| Artifact Type | Value (Raw) | Value (Defanged) | Context / Classification |
| :--- | :--- | :--- | :--- |
| **Email Sender** | `aaronluo@cmail.carleton.ca` | `aaronluo[@]cmail[.]carleton[.]ca` | Compromised external sender / Phishing origin |
| **SMTP IPv4** | `189.162.189.159` | `189.162.189[.]159` | External Mail Relay |
| **File Name** | `Material.pdf` | `Material[.]pdf` | Weaponized PDF Attachment |
| **SHA-256** | `39fb927c32221134a423760c5d1f58bca4cbbcc87c891c79e390a22b63608eb4` | `39fb927c32221134a423760c5d1f58bca4cbbcc87c891c79e390a22b63608eb4` | Malicious PDF Hash (30/61 on VT) |
| **MD5** | `72c812cf21909a48eb9cceb9e04b865d` | `72c812cf21909a48eb9cceb9e04b865d` | Artifact MD5 Hash |

---

## 6. Containment & Remediation Actions Taken
1. **Perimeter Block Confirmed:** Verified gateway successfully quarantined the inbound email, preventing delivery to `mark@letsdefend.io`.
2. **Indicator Cataloging:** Added the sender IP `189.162.189.159` and attachment hash (`SHA-256: 39fb927c...`) to the perimeter mail gateway blocklist.
3. **Endpoint Verification:** Checked endpoint logs to ensure no historical interaction occurred with the malicious sender.

---

## 7. Final Verdict
*   **Verdict:** **True Positive**
*   **Incident Type:** Inbound Weaponized Attachment / Phishing
*   **Containment Status:** Successfully Blocked at Perimeter; Case Closed.