# Suspicious Port Threat Hunting Rule
### High-Fidelity Network Port Detection with External Intelligence and Full Process Attribution
Author: Ala Dabat  
Updated: 2025-11-14  

---

## Purpose

This rule detects outbound network connections over suspicious or malicious ports sourced from an external intelligence feed, and correlates them with full process-level telemetry. It is designed to expose high-risk outbound behaviour, encrypted tunnels, disguised C2 channels, and malicious binaries attempting to blend into legitimate traffic.

The rule enriches each match with:

- Executable name  
- Command-line  
- SHA256  
- Parent process  
- Signer information  
- User context  
- MITRE technique mapping  
- Dynamic risk scoring  
- Analyst hunting directives  

Suitable for SOC L2.5–L3 analysts, threat hunters, and CTI teams.

---

## Detection Summary

### What This Rule Detects
- Suspicious outbound ports defined by open-source threat intelligence  
- Malware beaconing through rare or non-standard ports  
- Unsigned or untrusted binaries making outbound connections  
- Supply-chain style C2 behaviour seen in 3CX, SolarWinds, F5 intrusions  
- Encrypted tunnels (SOCKS, OpenVPN, custom proxy tooling)  
- LOLBins generating outbound network traffic  
- Multi-stage loaders communicating through uncommon ports  

### What This Rule Does Not Detect

| Not Detected | Reason |
|--------------|--------|
| Malware with no network activity | No traffic = no signal |
| C2 using 80/443 | Behaviour-based checks required |
| QUIC-based C2 | UDP encryption conceals ports |
| DNS-over-HTTPS C2 | Hidden inside HTTPS |
| Port knocking sequences | Needs stateful logic |
| Localhost-only C2 | Local connections intentionally excluded |

---

## Data Sources

| Table | Purpose |
|-------|---------|
| DeviceNetworkEvents | Outbound network traffic |
| DeviceProcessEvents | Process and command-line attribution |
| External CSV Feed | Suspicious port metadata |

External CSV source:  
https://github.com/mthcht/awesome-lists/blob/main/Lists/suspicious_ports_list.csv

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| TA0011 | T1071 | Application Layer C2 |
| TA0011 | T1090 | Proxy/Tunneling |
| TA0011 | T1573 | Encrypted communication channel |

---

## Analyst Hunting Directives

1. Identify the executable responsible for the suspicious network connection.  
2. Review the parent process to catch LOLBin-driven C2 activity.  
3. Inspect full command-line arguments for encoded or download-related parameters.  
4. Evaluate SHA256 and signer reputation.  
5. Check connection patterns for regular intervals (beaconing).  
6. Run a threat-intel lookup on the destination IP or hostname.  
7. Validate the user session and associated privilege level.  
8. If activity is malicious or unexplained, isolate the host and perform memory capture.  

---

## Example Output

| DeviceName | RemotePort | Process | RiskLevel | Notes |
|------------|------------|---------|-----------|-------|
| LAPTOP-123 | 1080 | powershell.exe | CRITICAL | Behaviour aligned with proxy/tunneling activity |
| WS-04 | 1194 | unknown.exe | HIGH | Encrypted channel indicative of C2 |
| PC-17 | 5985 | rundll32.exe | HIGH | Abnormal WinRM-based traffic |
