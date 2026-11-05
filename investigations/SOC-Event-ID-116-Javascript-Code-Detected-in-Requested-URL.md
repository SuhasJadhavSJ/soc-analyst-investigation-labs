# [INCIDENT REPORT] Event ID: 116
SOC166 - Javascript Code Detected in Requested URL

## 1. Executive Summary
- **Verdict:** True Positive
- **Severity:** Medium
- **Status:** Closed
- **Summary:** An external attacker operating from IP 112.85.42[.]13 launched multiple Cross-Site Scripting (XSS) probe payloads against internal web server WebServer1002 (172.16.17[.]17) targeting the `/search/?q=` parameter. Log analysis confirmed all malicious requests received HTTP 302 redirects, and forensic review of WebServer1002's Endpoint Security logs confirmed zero terminal command executions, suspicious child processes, or anomalous outbound connections during the attack window. Because the attack originated from the Internet and was unsuccessful, Tier 2 escalation was not required. The attacker IP was flagged for perimeter blocking.

---

## 2. Alert Metadata
| Parameter | Value |
| :--- | :--- |
| **Event ID** | 116 |
| **Alert Trigger Time** | 2022-02-26 18:56:46+03:00 |
| **Rule Name** | SOC166 - Javascript Code Detected in Requested URL |
| **Alert Type** | Web Attack |
| **Source / Sender** | 112.85.42[.]13 (China Unicom) |
| **Destination / Target** | 172.16.17[.]17 (WebServer1002) |
| **Device Action** | Allowed |

---

## 3. Investigation Playbook & Triage Steps

### Step 1: Ingestion & Initial Scoping
- **Action:** Created case ticket for EventID `116` under rule `SOC166`.
- **Initial Observation:** Rule triggered on JavaScript execution syntax in an inbound HTTP GET request. The perimeter firewall allowed the connection to reach the target web server.

### Step 2: Evidence & Cross-Platform Pivoting
- **Planned Test Verification:** Checked internal mailbox and security scheduling records; confirmed no approved penetration test or attack simulation exercises were active.
- **Threat Intelligence (VirusTotal / Public Repositories):**
  - Evaluated source IP `112.85.42[.]13` (AS4837 China Unicom); detected with suspicious web-scanning activity history.
- **Log Management & Network Traffic:**
  - Evaluated 8 total HTTP requests from the attacker:
    - Baseline requests to `/` and `/about-us/` returned HTTP 200 OK.
    - Probing requests using `<$img...onerror>`, `<$script>`, and `<$svg>` tags to `/search/?q=` all returned HTTP 302 redirects, preventing script rendering.
- **Endpoint Security (EDR Verification):**
  - Inspected `WebServer1002` (172.16.17[.]17):
    - **Terminal History:** Zero commands were executed on 2022-02-26. Only historical administrative deployment commands from 2022-02-02 (`docker-compose build/up`) were present.
    - **Network Action:** No unauthorized outbound sessions or C2 callbacks were established around the attack timeframe.
    - **Processes:** Only expected legitimate Windows system processes were running.

---

## 4. Analysis & Correlated Evidence Table
*Curated records extracted during triage:*

| Timestamp | Source | Destination | Event / Command / Status | Significance |
| :--- | :--- | :--- | :--- | :--- |
| 2022-02-26 21:04:34 | 112.85.42[.]13 | 172.16.17[.]17 | GET / - HTTP 200 | Initial web enumeration |
| 2022-02-26 21:05:10 | 112.85.42[.]13 | 172.16.17[.]17 | GET /about-us/ - HTTP 200 | Endpoint reconnaissance |
| 2022-02-26 21:15:43 | 112.85.42[.]13 | 172.16.17[.]17 | GET /search/?q=test - HTTP 200 | Baseline input test |
| 2022-02-26 21:16:23 | 112.85.42[.]13 | 172.16.17[.]17 | GET /search/?q=<$img%20src%20=q%20onerror=prompt(8)$> - HTTP 302 | Image event handler XSS attempt |
| 2022-02-26 21:16:36 | 112.85.42[.]13 | 172.16.17[.]17 | GET /search/?q=prompt(8) - HTTP 302 | Reflection parameter probe |
| 2022-02-26 21:20:09 | 112.85.42[.]13 | 172.16.17[.]17 | GET /search/?q=<$script>$for((i)in(self))eval(i)(1)<$/script> - HTTP 302 | JavaScript execution attempt |
| 2022-02-26 21:23:40 | 112.85.42[.]13 | 172.16.17[.]17 | GET /search/?q=<$svg><$script%20?>$alert(1) - HTTP 302 | SVG script tag obfuscation test |
| 2022-02-26 21:26:55 | 112.85.42[.]13 | 172.16.17[.]17 | GET /search/?q=<$script>javascript:$alert(1)</script> - HTTP 302 | Standard XSS alert test |

---

## 5. Artifacts & Indicators of Compromise (IOCs)
| Type | Indicator (Defanged) | Context / Classification |
| :--- | :--- | :--- |
| **IPv4** | `112.85.42[.]13` | External Attacker IP |
| **URI Parameter** | `/search/?q=<$script>javascript:$alert(1)</script>` | Reflected XSS Payload |
| **User-Agent** | `Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1` | Attacker Browser Fingerprint |

---

## 6. Containment & Remediation Actions
1. **Perimeter Block:** Added `112.85.42[.]13` to perimeter firewall and WAF blocklists.
2. **Application Hardening:** Instructed development team to implement contextual output encoding and input sanitization on all search query inputs.
3. **Security Headers:** Enforce strict `Content-Security-Policy` (CSP) directives (`script-src 'self'`) to block unauthorized inline script execution across browsers.

---

## 7. Lessons Learned & Tuning Suggestions
- **WAF Signature Optimization:** Configure WAF rules to inspect query strings for script injection characters (`<script>`, `onerror=`, `javascript:`) and drop requests at the boundary before they hit application endpoints.