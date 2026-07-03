# MITRE ATT&CK Mapping

This document maps each detection in the SOC Home-Lab dashboard to its
corresponding MITRE ATT&CK tactic and technique.

---

## Detection 1: Brute-Force Login Attempts

| Field | Detail |
|---|---|
| **Tactic** | Credential Access (TA0006) |
| **Technique** | T1110 – Brute Force |
| **Sub-technique** | T1110.001 – Password Guessing |
| **Event ID** | 4625 – An account failed to log on |
| **SPL Logic** | 3+ failed logins from same account within 5-minute window |

**What it detects:** An attacker repeatedly trying different passwords against
a known account to gain unauthorized access. Common in both automated tooling
(Hydra, Medusa) and manual attempts.

**Real-world example:** An attacker who obtains a list of company email addresses
from a data breach uses an automated tool to try common passwords against each
account — this generates a burst of 4625 events in a short window, which this
detection catches.

---

## Detection 2: Unauthorized Account Creation

| Field | Detail |
|---|---|
| **Tactic** | Persistence (TA0003) |
| **Technique** | T1136 – Create Account |
| **Sub-technique** | T1136.001 – Local Account |
| **Event ID** | 4720 – A user account was created |
| **SPL Logic** | Any 4720 event — no threshold, single occurrence is alertable |

**What it detects:** An attacker who has gained admin-level access creating a
new local user account to maintain persistent access, even if their original
entry point is discovered and closed.

**Real-world example:** After gaining access via a phishing attack, an attacker
creates a new admin account called something innocuous like "svc_backup" to
ensure they can return later — this generates a 4720 event which this detection
flags immediately.

---

## Detection 3: Obfuscated PowerShell Execution

| Field | Detail |
|---|---|
| **Tactic** | Execution (TA0002) |
| **Technique** | T1059 – Command and Scripting Interpreter |
| **Sub-technique** | T1059.001 – PowerShell |
| **Event ID** | 4688 – A new process has been created |
| **SPL Logic** | PowerShell process with -EncodedCommand, -enc, or -ExecutionPolicy Bypass flags |

**What it detects:** An attacker using PowerShell's built-in encoding capability
to hide the true content of a malicious script from basic log inspection and
keyword-based detection tools.

**Real-world example:** Malware droppers (including many ransomware families)
use encoded PowerShell commands to download and execute their payload without
the command being readable in plain text — the -EncodedCommand flag is one of
the most reliable indicators of this technique.

---

## Summary Table

| Detection | Tactic | Technique | Sub-technique | Event ID |
|---|---|---|---|---|
| Brute-Force Login | Credential Access (TA0006) | T1110 | T1110.001 | 4625 |
| New Account Creation | Persistence (TA0003) | T1136 | T1136.001 | 4720 |
| Obfuscated PowerShell | Execution (TA0002) | T1059 | T1059.001 | 4688 |

---

## References
- [MITRE ATT&CK T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1136 – Create Account](https://attack.mitre.org/techniques/T1136/)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
