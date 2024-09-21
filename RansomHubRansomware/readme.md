# RansomHub Overview

**RansomHub** is a sophisticated ransomware group known for its high-value target attacks and advanced capabilities. Originally known as **Cyclops** and **Knight**, the group operates as a Ransomware-as-a-Service (RaaS) model, attracting affiliates through underground forums. RansomHub is recognized for leveraging complex attack vectors, including custom-built ransomware strains, zero-day vulnerabilities, and social engineering techniques.

## Key Features of RansomHub

- **Double Extortion Tactics**: Combines data encryption with data exfiltration, pressuring victims to pay by threatening to publish stolen data.
- **RaaS Model**: Operates a Ransomware-as-a-Service model similar to major ransomware variants like LockBit and ALPHV, sharing profits with affiliates.
- **Sophisticated Attacks**: Utilizes complex initial access methods, including exploiting zero-day vulnerabilities and conducting phishing campaigns.

## Related Groups

- **Conti**
- **LockBit**
- **REvil**

## Recent Activities and Trends

- **Latest Campaigns**: Targeted critical infrastructure sectors, including healthcare, financial services, and public utilities, impacting at least 210 victims since February 2024.
- **Emerging Trends**: Increased use of RaaS models and sophisticated phishing campaigns to gain network access.

## Indicators of Attack (IoA)

- Unauthorized remote access attempts
- Unusual network traffic patterns
- Suspicious email attachments or links
- Unexpected system slowdowns or crashes
- Encrypted files with altered file extensions

## Initial Access Methods

RansomHub typically compromises internet-connected systems and user endpoints using the following techniques:

1. **Phishing Emails**: Emails with malicious links and attachments. `([T1566])`
2. **Exploitation of Known Vulnerabilities**: Targets common security flaws to gain system access. `([T1190])`
3. **Password Spraying Attacks**: Attempts to log in using commonly known credentials from data breaches. `([T1110.003])`

## Exploited Vulnerabilities

RansomHub affiliates exploit various known vulnerabilities, including:

- **CVE-2023-3519 (CWE-94)**: Citrix ADC Remote Code Execution via specially crafted HTTP GET requests.
- **CVE-2023-27997 (CWE-787 | CWE-122)**: FortiOS and FortiProxy memory overflow vulnerabilities enabling remote code execution.
- **CVE-2023-46604 (CWE-502)**: Java OpenWire Protocol Marshaller RCE in Apache ActiveMQ, allowing arbitrary command execution.
- **CVE-2023-22515**: Unauthorized creation of administrator accounts in Confluence Data Center.
- **CVE-2023-46747 (CWE-306 | CWE-288)**: BIG-IP system command execution vulnerabilities bypassing configuration tools.
- **CVE-2023-48788 (CWE-89)**: SQL Injection vulnerability in FortiClientEMS enabling unauthorized command execution.
- **CVE-2017-0144**: Windows SMB Remote Code Execution flaw.
- **CVE-2020-1472**: Netlogon privilege escalation vulnerability.
- **CVE-2020-0787**: Additional Zerologon privilege escalation vulnerability related to Netlogon protocol.

## Discovery Techniques

RansomHub affiliates use network scanning tools like AngryIPScanner, Nmap, and PowerShell-based methods to identify targets within compromised networks.

- Network Scanning Tools: `([T1018], [T1046], [T1059.001])`

## Defense Evasion Tactics

- **Obfuscation**: The ransomware is often disguised as harmless file names like `Windows.exe` and placed in accessible folders such as the Desktop or Downloads. `([T1036])`
- **Log Clearing**: System logs are erased to prevent incident response efforts. `([T1070])`
- **Disabling Security**: Using WMI and custom tools, RansomHub disables antivirus and endpoint detection and response (EDR) tools. `([T1562.001])`

## Privilege Escalation and Lateral Movement

Once inside, RansomHub affiliates:

- **Create New User Accounts** `([T1136])`
- **Reactivate Disabled Accounts** `([T1098])`
- **Use Tools like Mimikatz** `([S0002])` to escalate privileges and collect credentials `([T1003], [T1068])`
- **Move Laterally Using**:
  - Remote Desktop Protocol (RDP) `([T1021.001])`
  - PsExec `([S0029])`
  - AnyDesk `([T1219])`
  - Cobalt Strike `([S0154])`
  - Metasploit and other C2 methods

## Data Exfiltration

Data exfiltration methods vary by affiliate, using:

- PuTTY `([T1048.002])`
- Amazon AWS S3 tools `([T1537])`
- HTTP POST requests `([T1048.003])`
- WinSCP, Rclone, Cobalt Strike, Metasploit

## Encryption

RansomHub employs the Curve 25519 Elliptic Curve Cryptography algorithm to encrypt accessible files `([T1486])`. This algorithm uses unique public/private keys for each victim organization. During encryption, the ransomware halts various processes, including:

- `vmms.exe`, `msaccess.exe`, `mspub.exe`, `svchost.exe`, `vmcompute.exe`
- `notepad.exe`, `ocautoupds.exe`, `ocomm.exe`, `ocssd.exe`, `oracle.exe`
- `onenote.exe`, `outlook.exe`, `powerpnt.exe`, `explorer.exe`, `sql.exe`
- `steam.exe`, `synctime.exe`, `vmwp.exe`, `thebat.exe`, `thunderbird.exe`
- `visio.exe`, `winword.exe`, `wordpad.exe`, `xfssvccon.exe`, `TeamViewer.exe`
- `agntsvc.exe`, `dbsnmp.exe`, `dbeng50.exe`, `encsvc.exe`

## Mitigation Strategies

1. **Implement Robust Backups**: Regularly back up critical data to recover quickly after an attack.
2. **Enhance Network Security**: Use firewalls, intrusion detection systems, and other measures to prevent unauthorized access.
3. **Educate Employees**: Train staff on phishing and other ransomware-related threats to reduce susceptibility.
4. **Consider Cyber Insurance**: Obtain coverage to mitigate financial losses and support recovery efforts after an attack.

---

RansomHub’s activities highlight the evolving landscape of ransomware, underscoring the need for robust cybersecurity measures and continuous vigilance.
