# Registry Persistence & Hijack Detection (MDE / Sentinel)

**Author:** Ala Dabat  
**Detection Type:** Endpoint Persistence Hunt (Registry – Behavioral)  
**Primary Tactics:** TA0003 (Persistence) | TA0002 (Execution) | TA0005 (Defense Evasion)  
**Audience:** L3 SOC / Threat Hunting / Detection Engineering  

---

## Purpose

This repository documents a **behavioral, low-noise registry persistence detection framework** designed to surface *true attacker persistence* rather than routine software activity.

The detection strategy combines **three complementary models**:

1. **High-risk registry surface monitoring** (classic persistence & hijacks)  
2. **Registry Drift Detection** (statistical rarity across the organization)  
3. **Registry Re-Write Detection** (self-healing / resilience behavior)

Together, these models detect persistence that:
- does not belong in the environment  
- refuses to stay removed  
- survives remediation attempts  

This approach deliberately avoids reliance on IOCs, blocklists, or brittle string matching and instead models **attacker behavior**.

---

## Coverage Overview

### Registry Persistence Surfaces Covered

- Run / RunOnce (HKCU & HKLM)
- Winlogon Shell and Userinit
- AppInit_DLLs (global DLL injection)
- Services-based persistence
- IFEO debugger hijacking
- COM hijacking (CLSID / InprocServer32)
- LSA / SSP credential provider persistence

### Behavioral Models Implemented

| Model | Description | Why It Matters |
|------|-------------|----------------|
| **Classic Persistence Detection** | Monitors known abuse-prone registry locations | Catches direct persistence placement |
| **Registry Drift** | Finds registry values that are *rare or unique* across the org | Detects stealthy custom payloads |
| **Registry Re-Write** | Detects persistence values repeatedly rewritten | Catches self-healing malware |

---

## What This Detection Actively Finds

Category | Detected | Description
---------|----------|------------
Registry Run / RunOnce persistence | Yes | Malware or tooling set to execute at logon
Winlogon Shell / Userinit hijacks | Yes | Alternate shells or chained payload execution
AppInit_DLLs abuse | Yes | Global DLL injection into GUI processes
Services persistence | Yes | New or modified services / drivers
IFEO debugger hijack | Yes | Debugger redirection to attacker binaries
COM hijacking | Yes | CLSID → malicious InprocServer32 DLL
LSA / SSP hooks | Yes | Credential interception via SSP DLLs
LOLBin-backed persistence | Yes | regsvr32, rundll32, mshta, powershell, wscript
Encoded registry payloads | Yes | Base64 / encoded scripts and commands
Rare binaries | Yes | Low-prevalence executables across the org
Self-healing persistence | Yes | Registry values rewritten repeatedly

---

## What This Detection Does *Not* Cover

Category | Reason
---------|--------
Scheduled Tasks | Covered by separate Task Drift / Re-Register hunt
Startup Folder shortcuts | File-system based (separate hunt)
WMI Event Consumers | Requires WMI telemetry
Kernel-only persistence | Requires driver / ELAM telemetry
GPO-based persistence | SYSVOL / registry.pol not covered
Pure memory-only malware | No registry footprint

This rule is designed to be **paired**, not overloaded.

---

## Registry Drift Detection (New)

### Concept

**Registry Drift** identifies persistence that is *statistically rare* across the organization, regardless of whether it looks suspicious.

Instead of asking:
> “Does this look malicious?”

The hunt asks:
> “Why does only one or two machines have this persistence?”

### How It Works

- Normalizes registry ValueData to defeat trivial evasion
- Hashes normalized commands for grouping
- Computes **organizational prevalence** using `dcount(DeviceId)`
- Surfaces entries seen on ≤ 2 devices across 30 days

### Why This Is Powerful

- Attackers often use **benign-looking paths**
- Custom loaders evade signature-based rules
- Drift catches what *does not belong*, not what looks bad

---

## Registry Re-Write Detection (New)

### Concept

**Re-Write Persistence** detects registry values that are repeatedly written even though the value does not change.

This behavior strongly indicates:
- watchdog malware
- remediation resistance
- self-healing persistence

### Example

The same Run key written:
- multiple times per hour
- across logons
- immediately after deletion

Legitimate software almost never does this.

### Detection Logic

- Counts identical `RegistryValueSet` events
- Triggers on:
  - ≥ 3 writes in a short window, **or**
  - repeated writes across days
- Correlates initiator processes and users

### Why This Matters

This catches attackers who:
- expect defenders to remove persistence
- automatically re-install it
- keep their foothold alive quietly

---

## Combining Drift + Re-Write (High Confidence)

When **both** conditions occur:

- Persistence is **rare**
- Persistence is **self-healing**

➡️ This is *near-certain malicious persistence* and should be treated as **HIGH or CRITICAL**.

---

## MITRE ATT&CK Mapping

Tactic | Technique | Description
-------|-----------|------------
Persistence | T1547.001 | Registry Run / RunOnce keys
Persistence | T1547.009 | LSA / SSP credential providers
Persistence | T1543.003 | Windows services / drivers
Persistence | T1546.012 | IFEO debugger hijacking
Persistence | T1546.015 | COM hijacking
Execution | T1059.001 | PowerShell via registry
Execution | T1218.010 / .011 / .005 | regsvr32, rundll32, mshta
Defense Evasion | T1105 | External payload staging via registry

---

## Detection Logic Summary

The registry engine uses **layered evidence**, not single signals:

- Strict scope to high-risk registry paths
- Semantic normalization to defeat trivial evasion
- Organizational prevalence scoring (drift)
- Write-frequency analysis (re-write)
- Initiator and signer context
- User-writable path classification
- Cross-surface correlation (registry + startup + services + tasks)

Results are aggregated per artifact and enriched with:
- FirstSeen / LastSeen
- Duration and write counts
- Initiating process and user
- Behavioral risk score
- SOC-ready directives

---

## Analyst Hunting Directives

Each finding includes a `HunterDirective` such as:

1. Validate whether the registry entry is expected in this environment.
2. Identify whether the persistence is **rare**, **rewritten**, or both.
3. Examine the referenced binary or script (hash, signer, location).
4. Pivot on initiating process and user across the fleet.
5. If re-write behavior exists, assume a watchdog is present.
6. Correlate with process injection, network, and credential access activity.
7. Remove persistence **only after** full artifact collection.

This is designed for **L3 investigations**, not alert spam.

---

## Incident Response Guidance

For HIGH / CRITICAL findings:

1. Export the registry value and referenced payload.
2. Identify all persistence surfaces involved (Run, Service, Task).
3. Isolate host if self-healing behavior is confirmed.
4. Remove persistence after forensic capture.
5. Reset affected credentials.
6. Reimage systems if kernel or service persistence is involved.
7. Deploy hardening (WDAC, user-path execution controls).

---

## Supply-Chain & Real-World Relevance

This framework aligns with persistence observed in:

- **NotPetya / M.E.Doc** — service + Run key loaders  
- **3CX** — secondary loaders via registry persistence  
- **Red-team & APT tradecraft** — IFEO, COM, and LSA abuse  
- **Post-exploitation frameworks** — heavy use of self-healing Run keys  

Supply-chain compromise often *ends* in registry persistence.

---

## Example Output Fields

Field | Description
------|------------
DeviceName | Host with persistence
RegistryKey / ValueName / ValueData | Persistence location
Initiator / ProcUser | Who wrote the entry
ProcSigner / ProcCompany | Trust context
ProcSHA | Fleet-wide pivot key
OrgDeviceCount | How rare this persistence is
WriteCount | How often it is rewritten
RiskScore | Combined behavioral score
Severity | CRITICAL / HIGH / MEDIUM
MITRE_Techniques | ATT&CK mapping
HunterDirective | Analyst guidance

---

## Pairing & Expansion

For full persistence coverage, pair this registry engine with:

- Startup Folder Drift + Re-Write hunt
- Scheduled Task Drift + Re-Register hunt
- DLL & Driver sideloading detection
- WMI Event Consumer hunt
- OAuth / Cloud persistence detection

Together, these form a **complete persistence risk engine** suitable for advanced threat hunting, SOC enablement, and professional portfolio presentation.
