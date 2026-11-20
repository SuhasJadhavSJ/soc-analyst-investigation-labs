## SOC Incident Investigation Report — EventID 117

### 1. Executive Summary
On **February 27, 2022, at 00:36:04 UTC+3**, a SIEM alert (`SOC167 - LS Command Detected in Requested URL`) triggered for internal workstation **EliotPRD** (`172.16.17.46`) following an outbound HTTP `GET` request to `https://letsdefend.io/blog/?s=skills` (`188.114.96.15`). Investigation of proxy traffic and endpoint browser history confirms that the alert fired due to the substring `ls` appearing inside the legitimate search keyword `skills` (`?s=skills`) while the user was reading SOC career articles on LetsDefend. No command injection payload was sent, and the destination IP is clean. The incident is classified as a **False Positive**, **no containment** is required, and the alert is closed.

---

### 2. Alert & Incident Metadata

| Field | Details |
| :--- | :--- |
| **Event ID** | `117` |
| **Event Time** | `2022-02-27T00:36:04+03:00` |
| **Detection Rule** | `SOC167 - LS Command Detected in Requested URL` |
| **Alert Type** | Web Attack |
| **Trigger Reason** | URL Contains `LS` |
| **Device Action** | Allowed |
| **Source Hostname** | `EliotPRD` |
| **Source IP** | `172.16.17.46` (Internal Workstation) |
| **Destination IP** | `188.114.96.15` (Cloudflare / `letsdefend.io`) |
| **Requested URL** | `https://letsdefend.io/blog/?s=skills` |
| **HTTP Method** | `GET` |
| **User-Agent** | `Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:24.0) Gecko/20100101 Firefox/24.0` |
| **MITRE ATT&CK** | **T1190** (Exploit Public-Facing Application — Rule Mapping Only / Not Applicable) |
| **Assigned Role** | Security Analyst (SOC L1) |
| **Difficulty** | Easy |
| **Verdict** | **False Positive (Closed — No Containment Required)** |

---

### 3. Incident Timeline & Log Correlation

Correlating outbound HTTP proxy logs with endpoint browser history on `EliotPRD` confirms normal, continuous web browsing activity (accounting for timezone offset between log sources):

| Step | Proxy Log Timestamp | Endpoint Timestamp | Requested URL | HTTP Status | Context / Activity |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | `2022-02-27 02:31:52` | `27.02.2022 00:01` | `https://letsdefend.io/blog/` | `200 OK` | Visited LetsDefend blog homepage |
| **2** | `2022-02-27 02:35:17` | `27.02.2022 00:05` | `https://letsdefend.io/blog/how-to-become-a-soc-analyst/` | `200 OK` | Read SOC Analyst career article |
| **3** | `2022-02-27 02:43:45` | `27.02.2022 00:13` | `https://letsdefend.io/blog/how-to-analyze-rtf-template-injection-attacks/` | `200 OK` | Read RTF template injection analysis guide |
| **4** | `2022-02-27 02:53:06` | `27.02.2022 00:23` | `https://letsdefend.io/blog/red-team-vs-blue-team-learn-the-difference/` | `200 OK` | Read Red Team vs. Blue Team article |
| **5** | `2022-02-27 03:05:25` | `27.02.2022 00:35` | `https://letsdefend.io/blog/how-to-prepare-soc-analyst-resume/` | `200 OK` | Read SOC resume preparation guide |
| **6** | `2022-02-27 03:06:04` *(Alert)* | `27.02.2022 00:36` | `https://letsdefend.io/blog/?s=skills` | `200 OK` | Used blog search bar for keyword `"skills"` (Triggered `SOC167`) |
| **7** | `2022-02-27 03:07:51` | `27.02.2022 00:37` | `https://letsdefend.io/blog/soc-analyst-career-without-a-degree/` | `200 OK` | Continued reading SOC career article |

---

### 4. Threat Intelligence & Artifact Analysis

#### Observed Artifacts
* **Source IP:** `172.16.17.46` (`EliotPRD` — internal corporate workstation)
* **Destination IP:** `188.114.96.15` (Cloudflare CDN IP hosting `letsdefend.io`)
* **Requested URL:** `https://letsdefend.io/blog/?s=skills`
* **User-Agent:** `Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:24.0) Gecko/20100101 Firefox/24.0` (Standard Firefox browser on Ubuntu Linux)

#### Threat Intelligence Enrichment
* **Destination IP (`188.114.96.15`):** Clean across threat intelligence engines; associated with legitimate cybersecurity training platform `letsdefend.io`.
* **Source IP (`172.16.17.46`):** Internal host exhibiting normal human browsing intervals (1–12 minutes between article reads).

---

### 5. Root Cause & Impact Assessment
* **Root Cause:** Overly broad string-matching logic in SIEM rule `SOC167` (`URL Contains LS`), which matched the trailing letters `ls` inside the benign search query parameter `?s=skills` without enforcing word boundaries or shell command separators (`;`, `|`, `&&`, `%20`).
* **Impact:** **None.** No exploitation occurred, no unauthorized commands were executed, and no enterprise assets were compromised.

---

### 6. Containment, Closure & Recommendations

#### Actions Taken
* **Containment:** **Not Required.** Host `EliotPRD` (`172.16.17.46`) remains operational without isolation.
* **Classification & Closure:** Marked as **False Positive** and closed at Tier-1 without escalation.

#### Recommended Detection Tuning
1. **Refine Rule Logic (`SOC167`):** Update the detection signature to require command-injection delimiters or word boundaries before/after `ls` (e.g., matching `(;|&&|\|\||`|\$\()\s*ls(\s|$)` rather than an unrestricted substring match on `ls`).
2. **Directionality Context:** Scope `T1190` (Exploit Public-Facing Application) web attack rules to prioritize **inbound** traffic targeting internal web servers rather than routine outbound user browsing to trusted domains.