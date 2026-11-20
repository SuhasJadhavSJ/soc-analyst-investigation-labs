## SOC Incident Investigation Report — EventID 118

### 1. Executive Summary
On **February 28, 2022, at 04:12:45 UTC+3**, a SIEM alert (`SOC168 - Whoami Command Detected in Request Body`) triggered on **WebServer1004** (`172.16.17.16`) due to an external IP (`61.177.172.87`) sending HTTP `POST` requests containing OS command injection payloads to `https://172.16.17.16/video/`. Correlation of web server proxy logs and endpoint terminal history confirms that the commands executed on the host, exposing sensitive system files (`/etc/passwd` and `/etc/shadow`). The incident is classified as a **True Positive**, the compromised host has been **contained**, and the case has been **escalated** to Tier-2 / Incident Response.

---

### 2. Alert & Incident Metadata

| Field | Details |
| :--- | :--- |
| **Event ID** | `118` |
| **Event Time** | `2022-02-28T04:12:45+03:00` |
| **Detection Rule** | `SOC168 - Whoami Command Detected in Request Body` |
| **Alert Type** | Web Attack (OS Command Injection) |
| **Trigger Reason** | Request Body Contains `whoami` string |
| **Device Action** | Allowed |
| **Target Hostname** | `WebServer1004` |
| **Destination IP** | `172.16.17.16` |
| **Requested URL** | `https://172.16.17.16/video/` |
| **HTTP Method** | `POST` |
| **Source IP** | `61.177.172.87` |
| **User-Agent** | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)` |
| **MITRE ATT&CK** | **T1190** (Exploit Public-Facing Application) / **T1059.004** (Unix Shell) |
| **Assigned Role** | Security Analyst (SOC L1) |
| **Difficulty** | Easy |
| **Verdict** | **True Positive (Escalated)** |

---

### 3. Incident Timeline & Log Correlation

Correlating the HTTP `POST` traffic against the endpoint terminal history on `WebServer1004` confirms sequential command execution (accounting for timezone offset between log sources):

| Step | HTTP Log Timestamp | Endpoint Timestamp | Vector / Parameter | Command Executed | HTTP Status | Purpose / Impact |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `2022-02-28 06:41:06` | `28.02.2022 04:11` | `POST /video/` (`?c=ls`) | `ls` | `200 OK` | Directory listing / discovery |
| **2** | `2022-02-28 06:42:00` | `28.02.2022 04:12` | `POST /video/` (`?c=whoami`) | `whoami` | `200 OK` | Current user privilege enumeration |
| **3** | `2022-02-28 06:43:37` | `28.02.2022 04:13` | `POST /video/` (`?c=uname`) | `uname` | `200 OK` | OS / kernel fingerprinting |
| **4** | `2022-02-28 06:44:09` | `28.02.2022 04:14` | `POST /video/` (`?c=cat /etc/passwd`) | `cat /etc/passwd` | `200 OK` | Local user account enumeration |
| **5** | `2022-02-28 06:45:39` | `28.02.2022 04:17` | `POST /video/` (`?c=cat /etc/shadow`) | `cat /etc/shadow` | `200 OK` | Password hash extraction (indicates elevated/root context) |

---

### 4. Threat Intelligence & IOC Analysis

#### Indicators of Compromise (IOCs)
* **Malicious Source IP:** `61[.]177[.]172[.]87` (ASN: `AS4134` / Chinanet, Geolocation: `CN`)
* **Targeted Endpoint / URI:** `https[:]//172.16.17.16/video/` (Parameter: `c=`)
* **Anomalous User-Agent:** `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)` (Outdated Windows XP / IE6 string commonly used by automated exploitation scripts)

#### Threat Intelligence Enrichment (VirusTotal)
* **Detection Ratio:** 1/92 security vendors flagged the IP as malicious (Community Score: `-1`):
  * **Fortinet:** Malicious (`Malware`)
  * **alphaMountain.ai:** Suspicious
  * **AlphaSOC:** Suspicious
  * **Abusix:** Clean

---

### 5. Root Cause & Impact Assessment
* **Root Cause:** Unsanitized user input in parameter `c` on the `/video/` endpoint (`WebServer1004`), allowing arbitrary OS command injection, combined with an `Allowed` firewall/WAF policy.
* **Impact:**
  * **Confirmed Code Execution:** The attacker successfully executed shell commands (`ls`, `whoami`, `uname`) and received `200 OK` responses.
  * **Credential Exposure:** Because `cat /etc/shadow` executed successfully, the web application service was running with elevated (`root` or shadow-read) privileges, exposing local system password hashes to offline cracking.

---

### 6. Containment, Escalation & Recommendations

#### Actions Taken
* **Containment:** `WebServer1004` (`172.16.17.16`) has been isolated/contained to prevent further unauthorized access, lateral movement, or data exfiltration.
* **Classification & Escalation:** Marked as **True Positive** and escalated to Tier-2 Incident Response for forensic imaging and eradication.

#### Recommended Remediation
1. **Network Blocking:** Block source IP `61[.]177[.]172[.]87` at the perimeter firewall, WAF, and IPS/IDS.
2. **Credential Rotation:** Immediately reset passwords for all local accounts listed in `/etc/passwd` and `/etc/shadow` on `WebServer1004`, and rotate any application secrets, API keys, or database credentials stored on the host.
3. **Application Patching & Privilege Reduction:**
   * Sanitize and validate all input parameters on `/video/` and disable direct OS command execution functions.
   * Reconfigure the web server and Docker container (`docker-compose-deploy.yml`) to run under a dedicated, non-root, least-privilege user rather than `root`.
4. **WAF / Detection Tuning:** Switch command injection detection rules (`SOC168`) from **Alert/Allow** mode to **Block/Prevent** mode at the WAF layer.