# 🧬 Supply-Chain & Sideloading / Driver Abuse Detection (KQL)

This rule detects **post-compromise behaviours** associated with major supply-chain and component hijacking attacks such as:

- **3CX DesktopApp** compromise (malicious DLL sideloading)
- **F5 BIG-IP** backdoor (malicious driver + DLL loader)
- **SolarWinds SUNBURST** (staged, dormant DLL backdoor)
- **NotPetya / M.E.Doc**-style loader behaviour

It focuses on:

- Malicious **DLL drops** in abused directories
- **Fast-load DLL execution** (sideloading)
- **Dormant DLL / driver staging**
- **Unsigned/invalid drivers** (BYOVD)
- **Registry persistence** referencing executables/scripts
- **Remote payload downloads** for DLLs, drivers and loaders
- **Threat Intelligence enrichment** (MISP / TI table)

---

## 🧩 What This Rule Detects

### Behavioural Surfaces

| Stage                         | Behaviour / Surface                                  | Detected? |
|-------------------------------|------------------------------------------------------|-----------|
| Malicious DLL drop            | `.dll` in ProgramData/Users/Temp/Tasks               | ✔         |
| Fast-load DLL execution       | DLL loaded < 5 min after drop                        | ✔✔        |
| DLL loaded into high-trust app| 3CX / SolarWinds / Outlook / Teams                   | ✔✔        |
| Dormant DLL                   | DLL in writable path >7d, no load                    | ✔         |
| Driver drop                   | `.sys` in writable or abused locations               | ✔✔        |
| Dormant driver                | `.sys` dropped but never loaded >7d                  | ✔✔        |
| Unsigned / bad-signed load    | DLL/driver with invalid/unknown signature            | ✔✔        |
| Registry execution/persistence| Run keys / services / script paths in Registry       | ✔✔        |
| Payload download              | URLs with `.dll/.sys/.exe/.bin/.dat`                 | ✔✔        |
| TI-correlated artefacts       | Hash/IP/URL/Domain matches in ThreatIntelligence     | ✔✔        |

---

## 🎯 Supply-Chain Attack Coverage

| Attack                     | DLL Drop | DLL Fast-Load | Dormant DLL | Driver Abuse | Registry Persistence | Network Payloads | Notes |
|----------------------------|----------|---------------|-------------|-------------|----------------------|------------------|-------|
| **3CX DesktopApp**         | ✔        | ✔✔            | ❌          | ❌          | ✔ (variants)         | ✔                | Malicious DLL sideloaded into 3CX app |
| **F5 BIG-IP 2025**         | ✔        | ✔             | ✔           | ✔✔          | ✔✔                   | ✔                | Dormant driver + DLL loader + services |
| **SolarWinds SUNBURST**    | ✔        | ✔             | ✔✔          | ❌          | ✔                    | ✔                | Staged DLL backdoor active after delay |
| **NotPetya (M.E.Doc)**     | ✔        | ✔             | ❌          | ❌          | ✔                    | ✔                | DLL loader prior to disk wiping         |
| **Generic Vendor Compromise** | ✔     | ✔             | ✔           | ✔           | ✔                    | ✔                | Behaviour-first detection, IOC-free     |

---

## 🚦 ThreatHunterDirective & HuntingDirectives

The rule emits two key fields for SOC analysts:

### `ThreatHunterDirective`
A **single, context-aware triage line**, e.g.:

- `CRITICAL: Likely DLL sideloading supply-chain compromise (3CX/SolarWinds-style)...`
- `CRITICAL: Suspicious driver activity consistent with BYOVD/F5-style compromise...`
- `HIGH: Dormant DLL in writable path; potential staged loader (SolarWinds-style)...`
- `MEDIUM: Remote download of executable component...`

This makes the rule **SOC-friendly** and ready for alerting or incident queues.

### `HuntingDirectives`
An **array of step-by-step actions** for human hunters:

1. Confirm if DLL/driver is expected for the vendor/application.
2. Check process lineage and verify installer/update legitimacy.
3. For DLL sideloading, inspect the parent process (e.g. 3CX / SolarWinds) and validate the binary’s integrity.
4. For drivers, review signing, origin of install, and linked services.
5. Pivot to network events for C2 or staging infra around drop/load times.
6. If compromise suspected, isolate endpoint and feed IOCs into MISP/TI.
7. Hunt for the same hash/filename/persistence pattern across all endpoints.

---

## 🧠 MITRE ATT&CK Mapping

| Tactic            | Techniques                                                     |
|-------------------|----------------------------------------------------------------|
| **TA0003 – Persistence**      | T1547.001 (Registry Run Keys), T1543.003 (Services), T1195 (Supply Chain) |
| **TA0004 – Privilege Escalation** | T1543.003 (Driver/Service), T1574.001 (DLL hijack)          |
| **TA0005 – Defense Evasion**  | T1574.001 (Sideloading), T1036 (Masquerading)                   |
| **TA0006 – Credential Access**| Dependent on follow-on modules (e.g., LSASS access, not in this rule) |
| **TA0011 – C2**               | T1105 (Ingress Tool Transfer)                                   |
| **TA0010 – Exfiltration**     | T1041/T1020 when combined with C2 detection                     |

This rule is **post-compromise & behaviour-first**, not IOC-centric, but it **can be boosted with MISP / TI** via the `ThreatIntelligenceIndicator` table.

---

## 🛠 How To Use

1. **Paste** `MDE_SupplyChain_Sideloading_DriverAbuse.kql` into **Advanced Hunting**.
2. Adjust:
   - `lookback` (default: 14d)  
   - `dormant_window` (default: 7d)  
   - `confidence_threshold` (default: 3)
3. Seed `known_malicious_hashes` with:
   - Supply-chain IOCs from **MISP**
   - Hashes from your threat feeds
4. Optionally wire into:
   - Custom detection rule  
   - Sentinel Analytics Rule (via Defender → Sentinel connector)  
   - SOAR playbook using `ThreatHunterDirective` as summary text

---

## 📂 Suggested Repo Layout

```text
SupplyChain-Detection/
├── MDE_SupplyChain_Sideloading_DriverAbuse.kql
└── README.md
