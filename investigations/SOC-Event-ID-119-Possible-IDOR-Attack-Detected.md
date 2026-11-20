## SOC Incident Investigation Report — EventID 119

### 1. Executive Summary
On **February 28, 2022, at 22:48:05 UTC+3**, a SIEM alert (`SOC169 - Possible IDOR Attack Detected`) triggered on **WebServer1005** (`172.16.17.15`) after an external IP (`134.209.118.137`) issued consecutive HTTP `POST` requests to `https://172.16.17.15/get_user_info/`. Analysis of web server logs confirms that the attacker enumerated sequential `user_id` parameters (`2`, `1`, `3`, `5`), receiving `200 OK` responses for each query, indicating successful unauthorized access to user account records via Insecure Direct Object Reference (IDOR). Threat intelligence confirms the source IP is flagged as malicious on VirusTotal. The incident is classified as a **True Positive**, **WebServer1005** has been **contained**, and the case has been **escalated** to Tier-2 / Incident Response.

---

### 2. Alert & Incident Metadata

| Field | Details |
| :--- | :--- |
| **Event ID** | `119` |
| **Event Time** | `2022-02-28T22:48:05+03:00` |
| **Detection Rule** | `SOC169 - Possible IDOR Attack Detected` |
| **Alert Type** | Web Attack (Broken Access Control / IDOR) |
| **Trigger Reason** | Consecutive requests to the same page |
| **Device Action** | Allowed |
| **Target Hostname** | `WebServer1005` |
| **Destination IP** | `172.16.17.15` |
| **Requested URL** | `https://172.16.17.15/get_user_info/` |
| **HTTP Method** | `POST` |
| **Source IP** | `134.209.118.137` |
| **User-Agent** | `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)` |
| **MITRE ATT&CK** | **T1190** (Exploit Public-Facing Application) / **T1087** (Account Discovery) |
| **Assigned Role** | Security Analyst (SOC L1) |
| **Difficulty** | Medium |
| **Verdict** | **True Positive (Escalated)** |

---

### 3. Incident Timeline & Log Analysis

Reviewing the HTTP proxy/web server logs for `WebServer1005` shows sequential object enumeration targeting the `user_id` parameter over a 3-minute window:

| Step | Web Log Timestamp | Vector / Parameter | Target Object | HTTP Status | Purpose / Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `2022-03-01 01:15:00` | `POST /get_user_info/` (`?user_id=2`) | User ID `2` | `200 OK` | Unauthorized retrieval of user #2 profile data |
| **2** | `2022-03-01 01:15:43` | `POST /get_user_info/` (`?user_id=1`) | User ID `1` | `200 OK` | Unauthorized retrieval of user #1 (likely admin/root user) data |
| **3** | `2022-03-01 01:16:14` | `POST /get_user_info/` (`?user_id=3`) | User ID `3` | `200 OK` | Unauthorized retrieval of user #3 profile data |
| **4** | `2022-03-01 01:18:01` | `POST /get_user_info/` (`?user_id=5`) | User ID `5` | `200 OK` | Continued sequential enumeration of user #5 profile data |

---

### 4. Threat Intelligence & IOC Analysis

#### Indicators of Compromise (IOCs)
* **Malicious Source IP:** `134[.]209[.]118[.]137`
* **Targeted Endpoint / URI:** `https[:]//172.16.17.15/get_user_info/` (Parameter: `user_id=`)
* **Anomalous User-Agent:** `Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)` (Legacy Windows XP / IE6 user-agent string characteristic of automated scripts or replay tools)

#### Threat Intelligence Enrichment (VirusTotal)
* **Source IP (`134[.]209[.]118[.]137`):** Flagged as **Malicious** by security vendors on VirusTotal, corroborating hostile intent.

---

### 5. Root Cause & Impact Assessment
* **Root Cause:** Missing server-side authorization and ownership checks on the `/get_user_info/` endpoint (`WebServer1005`), allowing an unauthenticated or low-privileged requester to retrieve arbitrary user records simply by incrementing/modifying the `user_id` parameter, combined with an `Allowed` WAF/firewall action.
* **Impact:**
  * **Confirmed Data Exposure:** Four distinct user records (`user_id` `1`, `2`, `3`, and `5`) returned `200 OK` responses, resulting in unauthorized disclosure of user account information (and potential privileged account details for `user_id=1`).

---

### 6. Containment, Escalation & Recommendations

#### Actions Taken
* **Containment:** `WebServer1005` (`172.16.17.15`) has been isolated/contained to prevent further data enumeration or exfiltration.
* **Classification & Escalation:** Marked as **True Positive** and escalated to Tier-2 Incident Response for full scope assessment and application remediation.

#### Recommended Remediation
1. **Network Blocking:** Block source IP `134[.]209[.]118[.]137` at the perimeter firewall, WAF, and IPS/IDS.
2. **Access Control & Code Fix:**
   * Enforce strict server-side session authorization on `/get_user_info/` so authenticated users can only query their own `user_id` unless explicitly holding an administrative role.
   * Replace predictable sequential integer IDs (`1, 2, 3, 5`) with non-sequential, cryptographically random UUIDs.
3. **Account & Data Review:** Audit the data returned for `user_id` `1`, `2`, `3`, and `5` to determine whether PII, session tokens, or password hashes were exposed, and force password/token resets for affected accounts.
4. **WAF / Rate-Limiting:** Configure WAF rules (`SOC169`) to **Block** rapid sequential parameter enumeration and apply rate-limiting on sensitive API endpoints.