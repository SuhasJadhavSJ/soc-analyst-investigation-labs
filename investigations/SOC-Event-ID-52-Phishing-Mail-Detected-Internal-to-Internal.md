# [INCIDENT REPORT] Event ID: 52 - SOC120 Phishing Mail Detected - Internal to Internal

## 1. Executive Summary 
- **Event ID:** 52
- **Severity:** Medium 
- **Status:** Closed 
- **Summary:** Alert `SOC120` flagged an internal-to-internal email from `john@letsdefend.io` to `susie@letsdefend.io` with the subject "Meeting" originating from internal mail IP `172.16.20.3`. Investigation of the email content, and user context confirm that it was legitimate business correspondence. No suspicious file was identified. The case was resolved as a False Positive.


## 2. Alert Metadata
| Parameter | Value |
| :--- | :--- |
| **Event ID** | 52 |
| **Alert Trigger Time** | 2021-02-07T04:24:09+03:00 |
| **Rule Name** | SOC120 - Phishing Mail Detected - Internal to Internal |
| **Log Source / Layer** | Exchange |
| **Source Address / Relay** | john@letsdefend.io (SMTP: 172.16.20.3) |
| **Destination Address** | susie@letsdefend.io |
| **Device Action** | Allowed |


## 3. Investigation Playbook & Triage Steps

### Step 1 : Ingestion & Iitial Scoping
- **Ticket Ingestion:** Claimed and initiated triage for Event ID 52 in Case Managemnt.
- **Initial Telementary Assestment:**
    - Alert trigered on an internal mail echange between corporate accounts (`john@letsdefend.io` $\rightarrow$ `susie@letsdefend.io`).
    - Source IP `172.16.20.3` is verified as an internal network segment / authorised exchange routing interface.
    - Deleviry action was `Allowed`, required artifacts analysis to verify message legitimacy. 

### Step 2 : Email Security & Artifact Analysis
- Inspected the raw email message in Email Security :
    - **Sender:** `john@letsdefend.io` (Matches envelope sender; no domain spoofing or lookalike variation).
    - **Receipient:** `susie@letsdefend.io`
    - **Subject:** Meeting
    - **Body / Content Review:** Reviewed text body for social engineering lures, artificial urgency, or unusual requests (e.g., gift cards, unexpected wire transfers, password reset demands). Content was standard internal collaboration regarding scheduled meetings.
    - **Links / Attachments:** Verified that no external credential-harvesting hyperlinks or obfuscated executable/macro attachments were embedded in the message.

### Step 3 : Threat Intelligence & Host Verification
- **Internal Origin Veriication:** Confirmed IP `172.16.20.3` falls within internal RFC 1918 private address space and aligns with authorized corporate Exchange mail flow.
- **Endpoint / Log Verification:** 
    - Checked Log Management for anomalous authentication or suspicious outbound proxy traffic from John's host to rule out account takeover (ATO).
    - No concurrent unauthorized access, compromised session tokens, or anomalous egress beacons detected for `john@letsdefend.io`.



## 4. Evidence & Telemetry Logs
| Timestamp | Source Address / IP | Destination Address | Action Taken | Context / Findings |
| :--- | :--- | :--- | :--- | :--- |
| **2021-02-07 04:24:09** | john@letsdefend.io (172.16.20.3) | susie@letsdefend.io | ALLOWED | Benign meeting invite; no malicious artifacts or lures |


## 5. Artifact Assessment

| Artifact Type | Value / Indicator | Status / Classification | Notes |
| :--- | :--- | :--- | :--- |
| **Sender Email** | `john@letsdefend.io` | Legitimate / Authorized | Internal employee mailbox |
| **Recipient Email** | `susie@letsdefend.io` | Legitimate / Authorized | Internal employee mailbox |
| **Source IP** | `172.16.20.3` | Internal RFC 1918 | Corporate internal mail infrastructure |
| **Subject Line** | `Meeting` | Benign | Standard business scheduling communication |


## 6. Containment & Remediation Actions Taken
1. **Endpoint Containment:** Not Required. No malicious payload or secondary execution occurred.
2. **Account Status:** Active. No indicators of account compromise or session hijacking.
3. **Detection Tuning Recommendation:** Review rule `SOC120` detection logic to ensure internal-to-internal alerts account for standard message templates and trusted internal mail paths to minimize false alarms.



## 7. Final Verdict
*   **Verdict:** **False Positive**
*   **Classification:** Legitimate Internal Business Communication
*   **Resolution:** Verified Safe; Case Closed without Remediation.