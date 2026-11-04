# [INCIDENT REPORT] Event ID: 115
SOC165 - Possible SQL Injection Payload Detected

## 1. Executive Summary
- **Verdict:** True Positive
- **Severity:** Medium
- **Status:** Closed
- **Summary:** An external threat actor utilizing IP 167.99.169[.]17 targeted the internal web server WebServer1001 (172.16.17[.]18) with multiple SQL injection payloads via the HTTP GET parameter `/search/?q=`. The target server returned HTTP 500 (Internal Server Error) across all 5 injection attempts, confirming that database syntax errors were generated rather than unauthorized data exposure. The attack was unsuccessful and originated from the Internet, so Tier 2 escalation was not required. The attacker IP has been blocked at the perimeter firewall/WAF.

---

## 2. Alert Metadata
| Parameter | Value |
| :--- | :--- |
| **Event ID** | 115 |
| **Alert Trigger Time** | 2022-02-25 11:34:32+03:00 |
| **Rule Name** | SOC165 - Possible SQL Injection Payload Detected |
| **Alert Type** | Web Attack |
| **Source / Sender** | 167.99.169[.]17 (DigitalOcean, LLC) |
| **Destination / Target** | 172.16.17[.]18 (WebServer1001) |
| **Device Action** | Allowed |

---

## 3. Investigation Playbook & Triage Steps

### Step 1: Ingestion & Initial Scoping
- **Action:** Created case ticket for EventID `115`.
- **Initial Observation:** Alert rule triggered on incoming web traffic containing pattern `OR 1 = 1`. Device action was set to `Allowed`, allowing HTTP requests to hit the backend web application directly.

### Step 2: Evidence & Cross-Platform Pivoting
- **Threat Intelligence (VT, AbuseIPDB):**
  - Source IP: `167.99.169[.]17`
  - Host/ASN: DigitalOcean, LLC (ASN 14061)
  - Reputation: Flagged as malicious/phishing by multiple threat intelligence vendors on VirusTotal.
- **Log Management & Network Traffic:**
  - Evaluated 6 sequential HTTP requests across a ~4-minute window:
    - 1 preliminary baseline request to root `/` returning HTTP `200 OK` (3,547 bytes).
    - 5 sequential SQL injection payloads to `/search/?q=` testing string delimiters, tautologies, and column order.
    - All 5 injection attempts returned HTTP `500` (948 bytes), confirming backend application error handling instead of data leakage.
- **Endpoint Security (EDR) & Escalation Check:**
  - Direction: External (Internet) to Internal (DMZ/Web Server).
  - No host compromise, web shell placement, or lateral movement detected.
  - Per Tier 2 escalation criteria, failed external web attacks do not require Tier 2 escalation.

---

## 4. Analysis & Correlated Evidence Table
*Curated records extracted during triage:*

| Timestamp | Source | Destination | Event / Command / Status | Significance |
| :--- | :--- | :--- | :--- | :--- |
| 2022-02-25 14:00:15 | 167.99.169[.]17 | 172.16.17[.]18 | GET / - HTTP 200 (3547 B) | Initial reconnaissance / service discovery |
| 2022-02-25 14:02:31 | 167.99.169[.]17 | 172.16.17[.]18 | GET /search/?q=%27%20OR%20%271 - HTTP 500 | SQLi single-quote string escape probe |
| 2022-02-25 14:02:55 | 167.99.169[.]17 | 172.16.17[.]18 | GET /search/?q=%27 - HTTP 500 | SQLi single-quote syntax break probe |
| 2022-02-25 14:03:12 | 167.99.169[.]17 | 172.16.17[.]18 | GET /search/?q=%27%20OR%20%27x%27%3D%27x - HTTP 500 | SQLi boolean-based validation probe |
| 2022-02-25 14:03:51 | 167.99.169[.]17 | 172.16.17[.]18 | GET /search/?q=1%27%20ORDER%20BY%203--%2B - HTTP 500 | SQLi column count enumeration attempt |
| 2022-02-25 14:04:32 | 167.99.169[.]17 | 172.16.17[.]18 | GET /search/?q=%22%20OR%201%20%3D%201%20--%20- - HTTP 500 | SQLi double-quote tautology bypass payload |

---

## 5. Artifacts & Indicators of Compromise (IOCs)
| Type | Indicator (Defanged) | Context / Classification |
| :--- | :--- | :--- |
| **IPv4** | `167.99.169[.]17` | Attacker Source IP (DigitalOcean) |
| **URL Parameter** | `/search/?q=%22%20OR%201%20%3D%201%20--%20-` | SQL Injection Tautology Payload |
| **User-Agent** | `Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1` | Attacker Client User-Agent |

---

## 6. Containment & Remediation Actions
1. **Network Block:** Blocklisted source IP `167.99.169[.]17` on perimeter firewall and WAF.
2. **Application Remediation:** Notified development team to enforce parameterized queries / prepared statements for the `/search/?q=` parameter.
3. **Error Handling Hardening:** Suppressed backend SQL stack traces and detailed HTTP 500 responses, replacing them with generic sanitized error pages.

---

## 7. Lessons Learned & Tuning Suggestions
- **Detection Engineering:** Tune WAF inspection signatures to automatically drop and rate-limit HTTP GET requests containing SQL injection operators (`OR 1=1`, `ORDER BY`, quote break characters) before reaching the application layer.