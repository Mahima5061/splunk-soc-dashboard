# Splunk SOC Home-Lab Detection Dashboard

A home-lab Security Operations Center (SOC) project built using Splunk Enterprise
to demonstrate the full detection lifecycle — from log ingestion to detection rule
writing and dashboard visualization.

---

## Project Overview

This project simulates real-world SOC analyst work on a Windows 11 home-lab environment.
It covers three core detection scenarios mapped to MITRE ATT&CK techniques:

| Detection | Event ID | MITRE Technique |
|---|---|---|
| Brute-Force Login Attempts | 4625 | T1110 – Brute Force |
| Unauthorized Account Creation | 4720 | T1136 – Create Account |
| Obfuscated PowerShell Execution | 4688 | T1059.001 – PowerShell |

---

## Environment

- **OS:** Windows 11 Home (Build 26200)
- **SIEM:** Splunk Enterprise (local instance, localhost:8000)
- **Log Sources:** Windows Security, System, and Application Event Logs
- **Data Input Method:** Local Event Log Collection (no Universal Forwarder needed)

---

## Project Structure

```
splunk-soc-dashboard/
├── README.md
├── dashboard/
│   └── soc-dashboard.xml        # Importable Splunk Classic Dashboard XML
├── spl-queries/
│   └── detection-queries.md     # All SPL detection queries with explanations
├── docs/
│   └── mitre-attack-mapping.md  # MITRE ATT&CK mapping for each detection
└── screenshots/
    ├── 01-data-input-setup.png
    ├── 02-event-verification.png
    ├── 03-failed-login-detection.png
    ├── 04-new-user-creation.png
    ├── 05-powershell-encoded-detection.png
    └── 08-final-dashboard.png
```

---

## Setup Steps

### 1. Configure Log Ingestion
In Splunk Web (localhost:8000):
- Go to Settings → Data Inputs → Local Event Log Collections
- Select: Security, System, Application logs
- Index: main (default)

### 2. Enable Audit Policies
Run in Command Prompt (Administrator):
```cmd
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### 3. Simulate Attack Activity
```cmd
# Brute-force simulation (run in Command Prompt, enter wrong password when prompted)
runas /user:YourUsername cmd

# Backdoor account creation (run as Administrator)
net user testbackdoor Test@1234 /add

# Obfuscated PowerShell simulation (run in PowerShell)
powershell -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==
```

---

## Detections

### Detection 1: Brute-Force Login (T1110)
**Logic:** Flags any account with 3+ failed logins within a 5-minute window.
```spl
index=main EventCode=4625
| bucket _time span=5m
| stats count by Account_Name, _time
| where count >= 3
```
**Why it matters:** A single failed login is normal. Repeated failures in a tight
window indicate an automated or manual brute-force attempt.

---

### Detection 2: Unauthorized Account Creation (T1136)
**Logic:** Flags any new local user account creation — no threshold needed.
```spl
index=main EventCode=4720
| table _time, Subject_Account_Name, Account_Name, ComputerName
| rename Subject_Account_Name as "New_Account_Created", Account_Name as "Created_By"
```
**Why it matters:** Attackers create new accounts after gaining access to maintain
persistence — even one unexpected account creation warrants immediate investigation.

---

### Detection 3: Obfuscated PowerShell Execution (T1059.001)
**Logic:** Flags PowerShell processes launched with encoding or policy bypass flags.
```spl
index=main EventCode=4688
New_Process_Name=*powershell*
(Process_Command_Line=*EncodedCommand* OR Process_Command_Line=*ExecutionPolicy*Bypass* OR Process_Command_Line=*-enc*)
| table _time, Account_Name, New_Process_Name, Process_Command_Line
```
**Why it matters:** Attackers encode PowerShell commands to hide malicious intent
from basic log inspection. The -EncodedCommand and -ExecutionPolicy Bypass flags
are strong indicators of suspicious activity.

---

## Dashboard

The Splunk dashboard contains three panels:
- **Failed Login Attempts Over Time** — bar chart showing login failure spikes
- **New User Accounts Created** — table showing account name, creator, and timestamp
- **Suspicious PowerShell Executions** — table showing full command line captured

![SOC Dashboard](screenshots/08-final-dashboard.png)

To import the dashboard into your own Splunk instance:
1. Go to Dashboards → Create New Dashboard
2. Click Source/XML view
3. Paste the contents of `dashboard/soc-dashboard.xml`
4. Save

---

## Key Learnings

- Windows 11 Home does not include `secpol.msc` — audit policies must be configured
  via `auditpol.exe` command-line tool instead
- Process creation logging (4688) requires two separate settings: audit policy AND
  command-line capture registry key — without both, command arguments are not logged
- Not all 4625 (failed login) events are equivalent — computer account failures
  (COMPUTERNAME$) differ from user-initiated failures and must be distinguished
  during triage
- Threshold tuning matters — detection sensitivity directly affects false positive
  rate, which is a core SOC analyst responsibility

---

## References
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Windows Security Event IDs Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Splunk SPL Documentation](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)

---

## Author
**Mahima Chowdary Eragandula**
B.Tech Computer Science Engineering | Mohan Babu University
GitHub: [@Mahima5061](https://github.com/Mahima5061)
