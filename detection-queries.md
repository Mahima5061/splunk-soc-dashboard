# SOC Home-Lab — Saved SPL Queries

These are the core searches used to validate that Splunk is correctly capturing
simulated attack activity from Windows Security logs, plus the threshold-based
detection logic built from them.

General pattern used throughout:
```
index=main EventCode=XXXX | table _time, [relevant fields]
```

---

## 1. Failed Login Attempts (Brute-Force Simulation)
**Event ID:** 4625 — An account failed to log on
**MITRE ATT&CK:** T1110 – Brute Force

**Raw verification query:**
```spl
index=main EventCode=4625 | table _time, Account_Name, Logon_Type, Failure_Reason, EventCode
```

**Detection query (threshold-based):**
```spl
index=main EventCode=4625 
| bucket _time span=5m 
| stats count by Account_Name, _time 
| where count >= 3
```

**What it shows:** Accounts with 3 or more failed login attempts within any 5-minute window.
**Real-world relevance:** Multiple failed logins from the same account in a short window is
a classic brute-force indicator. A single failure is normal (typo); repeated failures in a
tight window are not.
**Tuning note:** Threshold and time window are adjustable. Too strict = misses slow/distributed
brute-force attempts (false negatives). Too loose = alert fatigue (false positives).

---

## 2. New User Account Creation (Backdoor Account Simulation)
**Event ID:** 4720 — A user account was created
**MITRE ATT&CK:** T1136 – Create Account

```spl
index=main EventCode=4720 
| table _time, Subject_Account_Name, Account_Name, ComputerName
| rename Subject_Account_Name as "New_Account_Created", Account_Name as "Created_By"
```

**What it shows:** Who created a new account, and the name of the account created.
**Real-world relevance:** Attackers who gain admin access often create a new account to
maintain persistent access (a "backdoor"). No threshold needed here — even one unexpected
account creation is worth flagging and reviewing against known/approved admin activity.

---

## 3. Obfuscated PowerShell Execution
**Event ID:** 4688 — A new process has been created
**MITRE ATT&CK:** T1059.001 – Command and Scripting Interpreter: PowerShell

```spl
index=main EventCode=4688 
New_Process_Name=*powershell* 
(Process_Command_Line=*EncodedCommand* OR Process_Command_Line=*ExecutionPolicy*Bypass* OR Process_Command_Line=*-enc*)
| table _time, Account_Name, New_Process_Name, Process_Command_Line
```

**What it shows:** Any PowerShell process launched using common obfuscation/evasion flags:
`-EncodedCommand` (or its shorthand `-enc`) and `-ExecutionPolicy Bypass`.
**Real-world relevance:** Attackers use base64-encoded PowerShell commands and policy bypass
flags to hide their actual intent from casual log review and basic keyword-based detection.
Requires both Process Creation auditing AND command-line logging to be enabled (see notes below).

---

## Setup notes (one-time, not part of detections)
- Logon auditing enabled via: `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`
- Process creation auditing enabled via: `auditpol /set /subcategory:"Process Creation" /success:enable`
- Command-line logging enabled via registry:
  `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f`
