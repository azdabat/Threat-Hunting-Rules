# 🧬 Registry Persistence & Hijack Detection (MDE / Sentinel)

**Author:** Ala Dabat  
**Detection Type:** Endpoint Persistence Hunt (Registry)  
**Tactics:**  
- TA0003 – Persistence  
- TA0002 – Execution  
- TA0005 – Defense Evasion  

---

## 🎯 Purpose

This detection hunts for **high-risk registry-based persistence** and **hijack mechanisms**, focusing on:

- Run / RunOnce keys  
- Winlogon (Userinit / Shell)  
- AppInit_DLLs  
- Services-based persistence  
- IFEO (Image File Execution Options) injection  
- COM hijacking (CLSID + InprocServer32)  
- LSA / SSP credential theft hooks  
- User-writable paths and LOLBin-staged payloads  

It’s tuned for **L3 threat hunting** and designed to surface **true persistence** rather than noise from normal software installs.

---

## 🧠 What This Rule Will Detect

| Category | Detected? | Description |
|----------|-----------|-------------|
| Registry Run / RunOnce persistence | 🟩 Yes | Malware or tools set to start at logon |
| Winlogon Shell/Userinit hijacks | 🟩 Yes | Alternate shells, custom userinit executables |
| AppInit_DLLs abuse | 🟩 Yes | Global DLL injection into processes |
| Services-based persistence | 🟩 Yes | New or modified `Services` entries |
| IFEO injection | 🟩 Yes | Debugger redirection (mimikatz-style tricks) |
| COM hijacking (CLSID/InprocServer32) | 🟩 Yes | COM objects pointed to attacker DLLs |
| LSA/SSP credential theft hooks | 🟩 Yes | Malicious SSP DLLs for credential theft |
| LOLBin-backed registry payloads | 🟩 Yes | `rundll32`, `regsvr32`, `mshta`, `powershell` etc. |
| Base64/encoded payloads in values | 🟩 Yes | Staged scripts / commands in registry |
| Rare unsigned binaries as persistence | 🟩 Yes | Uses prevalence & signer logic |

---

## ❌ What This Rule Will *Not* Detect

| Missed Category | Reason |
|-----------------|--------|
| WMI Event Consumers | No `WMIEvent` / `Win32_*` surface used here |
| Scheduled Tasks persistence | Needs `DeviceProcessEvents` + TaskCache / XML hunt |
| Startup folder shortcuts | File-system based, not registry |
| Kernel / driver persistence | Requires driver telemetry, ELAM/ETW providers |
| GPO-based persistence | GPO registry.pol / SYSVOL writes, not endpoint-written |
| Fileless-only, fully in-memory malware | No registry footprint to detect |

Pair this rule with your **DLL/driver sideloading** and **scheduled tasks** hunts for full coverage.

---

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|--------|-----------|-------------|
| TA0003 – Persistence | T1547.001 | Registry Run Keys / Startup Folder |
| TA0003 – Persistence | T1547.009 | LSA / SSP credential providers |
| TA0003 – Persistence | T1543.003 | Windows Service persistence |
| TA0003 – Persistence | T1546.012 | IFEO injection |
| TA0003 – Persistence | T1546.015 | COM Hijacking |
| TA0002 – Execution | T1059.001 | PowerShell execution via registry |
| TA0002 – Execution | T1218.010/011/005 | LOLBins: regsvr32, rundll32, mshta |
| TA0005 – Defense Evasion | T1105 | Payload download / staging from registry config |

---

## 🧪 Detection Logic Summary

The rule stacks multiple **independent signals**:

- **Key Scope:** Only known persistence / hijack keys in HKLM/HKCU  
- **Payload Content:**  
  - Encoded Command / Base64  
  - URLs / IP addresses / domains  
  - Executable/script extensions (`.exe`, `.dll`, `.ps1`, `.vbs`, `.js`, etc.)  
- **Abnormal Initiator:** Unsigned or rare processes writing these keys  
- **Signer & Publisher:** Non-trusted or unknown publisher modifies persistence keys  
- **Prevalence:** Rare binaries (≤ 2 devices) weighted more heavily  

It then aggregates per **Device + RegistryKey + ValueName** and returns:

- Signal count  
- Severity  
- Who wrote the value  
- Example command line  
- MITRE techniques  
- Hunting directives

---

## 🕵️‍♂️ Analyst Hunting Directives

The rule emits a `HuntingDirectives` column with guidance like:

1. Review the exact persistence key and value on the host.  
2. Confirm the binary and signer are expected in your environment.  
3. Examine the command line for encoded or LOLBin-based execution.  
4. Pivot on `ProcSHA` and signer to see where else it exists.  
5. If suspicious, remove the registry value and quarantine the binary.  
6. Correlate with recent processes, network traffic, and alerts.  
7. Map activity to MITRE for reporting and incident timeline.  

This is tuned for **L3 analysts** performing low-noise, high-context hunts.

---

## 🧬 Supply-Chain & Famous Attack Relevance

This registry persistence hunt supports analysis of:

- **NotPetya / M.E.Doc-style wipers** – Service persistence, run keys, and staged execution.  
- **3CX Supply Chain** – Secondary DLL loaders persisting via Run / RunOnce or COM hijacks.  
- **F5 / appliance-style pivots** – When attackers move from appliance into Windows estate and drop persistence.  
- **APT & red-team tradecraft** – IFEO, COM, and LSA-based backdoors frequently used for stealthy long-term access.  

While supply-chain infections begin elsewhere (trojanised updates, compromised vendor software), **the long-term foothold often ends up in exactly these registry paths**.

---

## 🧱 Example Output Fields

| Field | Description |
|-------|-------------|
| `DeviceName` | Host with suspicious persistence |
| `RegistryKey`, `ValueName`, `ValueData` | Exact persistence location and payload |
| `ProcUser` | User context performing the change |
| `ProcSigner`, `ProcCompany` | Publisher metadata for the initiating binary |
| `ProcSHA` | Hash to pivot across environment / VT |
| `MaxSignals` | Combined signal weight (behaviour + rarity + signer) |
| `ThreatSeverity` | CRITICAL / HIGH / MEDIUM derived from signal profile |
| `MITRE_Tactics`, `MITRE_Techniques` | ATT&CK mapping |
| `HuntingDirectives` | SOC-ready guidance for response |

---

## 📁 Suggested Folder Structure (GitHub)

Create a dedicated folder in your repo, for example:

```
/Registry-Persistence-Detection
    ├── registry_persistence_hunt.kql
    ├── README.md
    ├── samples/
    └── references/
```

---

## 📌 How to Create the Folder in GitHub

**Option A – in the GitHub Web UI**

1. Go to your repository.  
2. Click **“Add file” → “Create new file”**.  
3. In the filename box, type:  
   `Registry-Persistence-Detection/README.md`  
4. Paste this README content.  
5. Commit the file.  
6. To add the rule, create another file:  
   `Registry-Persistence-Detection/registry_persistence_hunt.kql`  
   and paste the KQL query.

**Option B – using Git locally**

```bash
mkdir Registry-Persistence-Detection
cd Registry-Persistence-Detection

# Create files
echo "" > README.md
echo "" > registry_persistence_hunt.kql

# Then open & paste content, then:
git add .
git commit -m "Add registry persistence detection rule and README"
git push
```

---

## 🔗 Pairing Suggestions

For maximum coverage, pair this rule with:

- **DLL & Driver Sideloading Hunt** (your existing rule)  
- **Scheduled Task Persistence Hunt**  
- **WMI Event Consumer Hunt**  
- **OAuth Consent / Cloud Persistence Rule** (the one above)  

Together, they form a strong **endpoint + cloud persistence** story for your portfolio.
