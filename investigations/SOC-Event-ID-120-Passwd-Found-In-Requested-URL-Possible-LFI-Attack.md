## SOC Incident Investigation Report — EventID 120

### 1. Executive Summary
On **March 1, 2022, at 10:10:41 UTC+3**, a SIEM alert (`SOC170 - Passwd Found in Requested URL - Possible LFI Attack`) triggered on **WebServer1006** (`172.16.17.13`) when an external IP (`106.55.45.162`) sent an HTTP `GET` request containing a directory traversal payload (`https://172.16.17.13/?file=../../../../etc/passwd`). Web server logs confirm the request returned an HTTP `500 Internal Server Error`, indicating that the Local File Inclusion (LFI) exploitation attempt failed and no sensitive system files were disclosed. Threat intelligence checks on VirusTotal returned clean results for the source IP. The incident is classified as a **True Positive (Unsuccessful Attack)**, **no host containment or Tier-2 escalation** is required, and the alert is closed after recommending perimeter IP blocking.

---

### 2. Alert & Incident Metadata

| Field | Details |
| :--- | :--- |
| **Event ID** | `120` |
| **Event Time** | `2022-03-01T10:10:41+03:00` |
| **Detection Rule** | `SOC170 - Passwd Found in Requested URL - Possible LFI Attack` |
| **Alert Type** | Web Attack (Local File Inclusion / Path Traversal) |
| **Trigger Reason** | URL Contains `passwd` |
| **Device Action** | Allowed |
| **Target Hostname** | `WebServer1006` |
| **Destination IP** | `172.16.17.13` |
| **Requested URL** | `https://172.16.17.13/?file=../../../../etc/passwd` |
| **HTTP Method** | `GET` |
| **Source IP** | `106.55.45.162` |
| **User-Agent** | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)` |
| **MITRE ATT&CK** | **T1190** (Exploit Public-Facing Application) |
| **Assigned Role** | Security Analyst (SOC L1) |
| **Difficulty** | Easy |
| **Verdict** | **True Positive — Unsuccessful Attack (Closed — No Escalation Required)** |

---

### 3. Incident Timeline & Log Analysis

Reviewing the HTTP proxy/web server logs for `WebServer1006` confirms a single, unsuccessful path traversal attempt:

| Step | Web Log Timestamp | Vector / Parameter | Payload | HTTP Status | Purpose / Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `2022-03-01 12:40:26` | `GET /` (`?file=`) | `../../../../etc/passwd` | `500 Internal Server Error` | Attempted LFI to read `/etc/passwd` — **Failed** |

---

### 4. Threat Intelligence & IOC Analysis

#### Indicators of Compromise (IOCs)
* **Attacker Source IP:** `106[.]55[.]45[.]162`
* **Targeted Endpoint / URI:** `https[:]//172.16.17.13/?file=../../../../etc/passwd`
* **Anomalous User-Agent:** `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)` (Legacy Windows XP / IE6 user-agent string commonly associated with automated vulnerability scanners or exploit scripts)

#### Threat Intelligence Enrichment (VirusTotal)
* **Source IP (`106[.]55[.]45[.]162`):** **0 detections / Clean** across security vendors on VirusTotal at the time of analysis.

---

### 5. Root Cause & Impact Assessment
* **Root Cause:** An external scanner/attacker probed the `file` query parameter on `WebServer1006` using path traversal sequences (`../../../../etc/passwd`), and the traffic passed through the perimeter/WAF (`Device Action: Allowed`). However, the backend web application failed to process or resolve the malicious file path, returning an HTTP `500` error.
* **Impact:** **None.** The LFI attack was unsuccessful (`500 Internal Server Error`), `/etc/passwd` was not exposed, and no evidence of post-exploitation or host compromise exists.

---

### 6. Containment, Closure & Recommendations

#### Actions Taken
* **Containment:** **Not Required.** `WebServer1006` (`172.16.17.13`) was not compromised and remains operational without isolation.
* **Classification & Closure:** Marked as **True Positive** (malicious intent confirmed via path traversal payload) with **unsuccessful exploitation**; closed at Tier-1 without Tier-2 escalation.

#### Recommended Remediation
1. **Network Blocking:** Block source IP `106[.]55[.]45[.]162` at the perimeter firewall and WAF to prevent follow-up reconnaissance or exploitation attempts.
2. **Input Validation & Error Handling:**
   * Sanitize and strictly validate the `file` parameter on `WebServer1006` using an allowlist of permitted filenames rather than accepting direct file paths.
   * Configure custom HTTP `500` error pages so stack traces or internal server paths are not leaked during failed requests.
3. **WAF Policy Enforcement:** Update WAF rules for path traversal / LFI (`SOC170`) from **Alert/Allow** mode to **Block/Prevent** mode.