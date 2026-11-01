# [INCIDENT REPORT] Event ID: 93 - SOC146 Phishing Mail Detected – Excel 4.0 Macros

## 1. Executive Summary
- **Verdict:** True Positive (Weaponized Spreadsheet / Excel 4.0 Macro Trojan Loader)
- **Severity:** High
- **Status:** Closed / Remediated
- **Summary:** An inbound spearphishing email originating from `trenton@tritowncomputers.com` via SMTP relay `24.213.228.54` targeted internal recipient `lars@letsdefend.io` under the subject "RE: Meeting Notes". The message delivered an archive attachment containing a weaponized Excel spreadsheet (`research-1646684671.xls`) designed to utilize legacy Excel 4.0 (XLM) macros for execution evasion. The email gateway permitted delivery (`Device Action: Allowed`). Threat intelligence analysis and sandbox detonation confirmed the spreadsheet is malicious, designed to drop secondary DLL payloads (`iroto.dll` and `iroto1.dll`) and initiate outbound network connections to staging infrastructure. Host-level investigation on `LarsPRD` (`172.16.17.57`) verified that the user executed the payload, triggering `excel.exe` to spawn `regsvr32.exe` and execute both dropped DLL binaries. The affected endpoint was quarantined via host isolation, and associated IOCs were blocked across network and perimeter controls.

---

## 2. Alert Metadata
| Parameter | Value |
| :--- | :--- |
| **Event ID** | 93 |
| **Alert Trigger Time** | 2021-06-13T14:13:28+03:00 |
| **Rule Name** | SOC146 - Phishing Mail Detected - Excel 4.0 Macros |
| **MITRE ATT&CK ID** | T1566 (Phishing), T1204.002 (User Execution: Malicious File), T1218.010 (System Binary Proxy Execution: Regsvr32) |
| **Log Source / Layer** | Exchange / Email Security |
| **Source Address / Relay** | trenton@tritowncomputers.com (SMTP: 24.213.228.54) |
| **Destination Address** | lars@letsdefend.io |
| **Device Action** | Allowed |

---

## 3. Investigation Playbook & Triage Steps

### Step 1: Ingestion & Initial Scoping
- **Ticket Ingestion:** Claimed and initiated active investigation for Event ID 93 in Case Management.
- **Initial Telemetry Assessment:**
  - Inbound email delivered to internal employee `lars@letsdefend.io`.
  - Gateway recorded `Device Action: Allowed`, confirming the email reached the user's inbox without being quarantined at the perimeter.
  - Initial triage priority focused on verifying attachment contents, extracting file hashes for multi-engine analysis, and evaluating recipient host telemetry for execution indicators.

### Step 2: Email Security & Artifact Extraction
- Accessed Email Security console and retrieved message details:
  - **Sender Display / Header:** `trenton@tritowncomputers.com`
  - **SMTP Relay:** `24.213.228.54`
  - **Subject:** `RE: Meeting Notes`
  - **Body / Lure:** "Hello! Please inspect your docs as one document that you can find through the attachment."
  - **Attachment:** Archive containing the weaponized spreadsheet `research-1646684671.xls`.
  - **Extracted Secondary Binaries:** `iroto.dll` and `iroto1.dll`.
  - **Attachment Hash (SHA-256):** `1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820`

### Step 3: Threat Intelligence & Sandbox Detonation
- **VirusTotal Telemetry - Spreadsheet (`research-1646684671.xls`):**
  - Detection Score: **40 / 62 security vendors** flagged the file as malicious.
  - Identified Behavior / Tags: Tagged with `calls-wmi`, Excel 4.0 (XLM) macro exploitation, and automated payload staging.
- **VirusTotal Telemetry - Dropped Binaries (`iroto.dll` & `iroto1.dll`):**
  - `iroto.dll` (`055b9e9af987aec9ba7adb0eef947f39b516a213d663cc52a71c7f0af146a946`): **28 / 71 security vendors** flagged as malicious (Popular labels: `trojan.qshell/usbljc26`, `W32/Qshell.VHO!tr`).
  - `iroto1.dll` (`e05c717b43f7e204f315eb8c298f9715791385516335acd8f20ec9e26c3e9b0b`): **26 / 70 security vendors** flagged as malicious.
  - Behavioral traits: Detects debug environment, checks user input, and registers runtime modules.
- **C2 & Infrastructure Relations:**
  - Contacted URLs: `hxxp[://]royalpalm[.]sparkblue[.]lk:443/`, `hxxps[://]royalpalm[.]sparkblue[.]lk/vcNHyrq3Yg8/dot[.]html`, `hxxp[://]nws[.]visionconsulting[.]ro:443/`, and `hxxps[://]nws[.]visionconsulting[.]ro/N1G1KCXA/dot[.]html`.
  - Associated infrastructure domains: `royalpalm[.]sparkblue[.]lk` and `nws[.]visionconsulting[.]ro`.

### Step 4: Endpoint Security & Log Management Correlation
- Identified recipient workstation under Endpoint Security as `LarsPRD` (`172.16.17.57`).
- **Process Activity Telemetry:**
  - Inspected active processes on `LarsPRD`.
  - Confirmed process execution of `regsvr32.exe` running the command line `regsvr32.exe -s iroto.dll` spawned directly by parent process `C:\Windows\System32\excel.exe`.
- **Terminal History Telemetry:**
  - `13.06.2021 14:20`: Execution recorded for `regsvr32.exe -s ../iroto.dll`.
  - `13.06.2021 14:21`: Execution recorded for `regsvr32.exe -s ../iroto1.dll`.
- **Host Containment:** Executed immediate host isolation on `LarsPRD` via the Endpoint Security console to contain potential C2 beaconing and prevent lateral propagation.

---

## 4. Evidence & Telemetry Logs

| Timestamp | Source Address / IP | Destination Address | Action Taken | Context / Findings |
| :--- | :--- | :--- | :--- | :--- |
| **2021-06-13 14:13:28** | `trenton@tritowncomputers.com` (`24.213.228.54`) | `lars@letsdefend.io` | ALLOWED | Inbound email delivered with malicious Excel attachment |
| **2021-06-13 14:20:00** | `LarsPRD` (`172.16.17.57`) | Local Endpoint (Cmdline) | EXECUTED | User terminal log: `regsvr32.exe -s ../iroto.dll` executed |
| **2021-06-13 14:21:00** | `LarsPRD` (`172.16.17.57`) | Local Endpoint (Cmdline) | EXECUTED | User terminal log: `regsvr32.exe -s ../iroto1.dll` executed |
| **2021-06-13 14:21+** | `LarsPRD` (`172.16.17.57`) | External Perimeter | BLOCKED / ISOLATED | Host isolated via EDR; evaluated C2 domains `royalpalm.sparkblue.lk` and `nws.visionconsulting.ro` |

---

## 5. Artifacts & Indicators of Compromise (IOCs)

| Artifact Type | Value (Raw) | Value (Defanged) | Context / Classification |
| :--- | :--- | :--- | :--- |
| **Email Sender** | `trenton@tritowncomputers.com` | `trenton[@]tritowncomputers[.]com` | Phishing Sender Address |
| **SMTP IPv4** | `24.213.228.54` | `24.213.228[.]54` | Originating Mail Relay IP |
| **Attachment File** | `research-1646684671.xls` | `research-1646684671[.]xls` | Malicious Excel 4.0 Macro Spreadsheet |
| **SHA-256 Hash (XLS)** | `1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820` | `1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820` | Macro Spreadsheet SHA-256 |
| **Dropped File** | `iroto.dll` | `iroto[.]dll` | Malicious Loader Binary |
| **SHA-256 Hash (DLL)** | `055b9e9af987aec9ba7adb0eef947f39b516a213d663cc52a71c7f0af146a946` | `055b9e9af987aec9ba7adb0eef947f39b516a213d663cc52a71c7f0af146a946` | Dropped DLL Hash |
| **Dropped File** | `iroto1.dll` | `iroto1[.]dll` | Secondary Loader Binary |
| **SHA-256 Hash (DLL)** | `e05c717b43f7e204f315eb8c298f9715791385516335acd8f20ec9e26c3e9b0b` | `e05c717b43f7e204f315eb8c298f9715791385516335acd8f20ec9e26c3e9b0b` | Secondary Dropped DLL Hash |
| **C2 Domain** | `royalpalm.sparkblue.lk` | `royalpalm[.]sparkblue[.]lk` | External Staging / C2 Domain |
| **C2 Domain** | `nws.visionconsulting.ro` | `nws[.]visionconsulting[.]ro` | External Staging / C2 Domain |
| **C2 URL** | `https://royalpalm.sparkblue.lk/vcNHyrq3Yg8/dot.html` | `hxxps[://]royalpalm[.]sparkblue[.]lk/vcNHyrq3Yg8/dot[.]html` | Secondary Staging URL |
| **C2 URL** | `https://nws.visionconsulting.ro/N1G1KCXA/dot.html` | `hxxps[://]nws[.]visionconsulting[.]ro/N1G1KCXA/dot[.]html` | Secondary Staging URL |

---

## 6. Containment & Remediation Actions Taken
1. **Endpoint Isolation:** Quarantined host `LarsPRD` (`172.16.17.57`) via Endpoint Security to cut off active network sessions and isolate the executing `regsvr32.exe` processes.
2. **Mailbox Purge:** Purged the phishing message and associated malicious attachments from Lars's mailbox across the Exchange environment.
3. **Perimeter Blacklisting:** Submitted sender address `trenton@tritowncomputers.com`, originating relay `24.213.228.54`, and staging domains `royalpalm.sparkblue.lk` and `nws.visionconsulting.ro` to perimeter mail and DNS/firewall blocklists.
4. **EDR Signature Distribution:** Ingested the SHA-256 hashes of `research-1646684671.xls`, `iroto.dll`, and `iroto1.dll` into enterprise endpoint detection rules for immediate automated kill and quarantine.
5. **Endpoint Remediations:** Scheduled full offline malware remediation, persistence audit (Run keys, scheduled tasks, and temp staging directories), and credential resets for user Lars.
6. **Policy Recommendation:** Enforce group policies (GPO) to restrict or disable Excel 4.0 (XLM) macros enterprise-wide and configure attack surface reduction (ASR) rules to prevent Office applications from spawning child processes (`regsvr32.exe`, `rundll32.exe`, `cmd.exe`, `powershell.exe`).

---

## 7. Final Verdict
- **Verdict:** **True Positive**
- **Incident Type:** Inbound Spearphishing / Malware Dropper (Excel 4.0 XLM Macro Execution via Regsvr32)
- **Resolution:** Remediated & Closed. Host isolated and network indicators blocked.