# LOLBins Defense Evasion and Follow-On Activity Pack
Author: Ala Dabat  
Version: 2025-11  
Status: Production-Ready

This pack exposes living-off-the-land binaries used for defense evasion, AMSI bypass, credential access, encoded payload execution, and security service tampering. Companion network detection covers post-evasion C2 traffic, stager retrieval, and outbound encoded loader activity.

The rule set captures:

- LSASS dumping (comsvcs.dll/MiniDump)
- AMSI bypass and reflection-based execution
- PowerShell encoded command loaders
- Security service termination and AV tampering
- mshta/regsvr32/rundll32 proxy execution abuse
- certutil/bitsadmin download staging
- Follow-on staging/C2 traffic

All detections include:
- MITRE mapping
- risk scoring
- analyst directives
- compact human-readable fields

Use this pack to anchor investigations involving:
- Initial execution footholds
- Credential theft
- Script-based loaders
- AV/EDR bypasses
- Lateral movement preparation
