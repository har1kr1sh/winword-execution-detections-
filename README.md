# MS Word Execution & Reverse Shell Detection Rules

This repository provides production-ready detection logic, SIEM queries, and YARA signatures to detect **Microsoft Word (`winword.exe`)** initiating process execution, spawning command shells, and establishing outbound network connections.

## 🎯 Threat Context

* **Tactic:** Initial Access, Execution, Command & Control
* **Technique:** Spearphishing Attachment (`T1566.001`), Command & Scripting Interpreter: PowerShell (`T1059.001`), Application Layer Protocol (`T1071`)
* **Attack Scenario:** A user opens a malicious Word document containing a macro or exploit payload. `winword.exe` spawns `powershell.exe` silently in the background, which initiates an outbound connection to an attacker-controlled C2 server to serve an interactive reverse shell.

## 📊 Detection Coverage Matrix

| Rule / Query | Platform | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- |
| `winword_spawns_powershell.yml` | Sigma (Sysmon / Evtx) | T1566.001, T1059.001 | Detects `winword.exe` spawning shells or scripting hosts. |
| `winword_suspicious_network.kql` | M365 Defender / KQL | T1059.001, T1071.001 | Correlates Word child process creation with outbound traffic. |
| `winword_anomalous_outbound.spl` | Splunk (Sysmon Event ID 3)| T1071.001 | Flags direct external IP connections originating from Word. |
| `reverse_shell_payload.yar` | YARA | T1059.001 | Identifies TCP socket reverse shell logic in script payloads. |

## 🧪 Testing & Validation

You can validate these rules in a sandbox/lab environment using the provided safe PowerShell test script in `test-emulation/`.