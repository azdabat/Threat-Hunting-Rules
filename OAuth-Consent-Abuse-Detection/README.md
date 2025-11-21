# OAuth Consent Abuse Detection Rule (Microsoft Sentinel)
Author: Ala Dabat  
Version: 2025-11  
Detection Type: Cloud Persistence / Initial Access  
MITRE ATT&CK: TA0001 | TA0003 | T1550.001

---

## Overview
Abuse of OAuth consent flows has become a reliable way for attackers to gain persistent access to Microsoft 365 environments without needing credentials or endpoint footholds. This rule focuses on identifying malicious consent activity, privilege escalation through high-risk Graph API scopes, and post-consent token behaviour that indicates longer-term access or exfiltration.

The detection covers:

- Malicious or suspicious consent events  
- High-risk Graph permissions  
- Unknown or non-Microsoft publishers  
- Suspicious user-agents during authentication  
- Token replay and refresh-token abuse  
- Service principal sign-ins (app-only persistence)  
- Admin consent events  
- offline_access infinite persistence

---

## Real-World Attack Coverage

### SolarWinds / UNC2452
Technique: OAuth app persistence, admin consent, Graph exfiltration  
Coverage:
- Flags malicious consent  
- Detects app-only credential backdoors  
- Identifies Graph API usage after consent  
- Highlights non-Microsoft publishers and unusual user-agents

### 3CX Supply Chain (APT41)
Technique: OAuth token reuse and credential manipulation  
Coverage:
- Detects token replay via TokenUseCount  
- Correlates suspicious user-agents and IP pivots  
- Identifies offline_access persistence

### Midnight Blizzard (NOBELIUM) 2024–2025
Technique: Malicious apps requesting Mail.Read, Mail.Send, offline_access  
Coverage:
- Scores high-risk permissions  
- Flags suspicious publishers  
- Detects app-only authentication  
- Identifies token replay from unusual geography

---

## Detection Logic Summary

### 1. Consent Events (AuditLogs)
- Application creation  
- Permission grants  
- Consent initiator  
- Publisher reputation  
- Scope evaluation and risk weighting

### 2. Token Issuance (TokenIssuanceLogs)
- Token replay  
- Refresh-token usage  
- Flood patterns and excessive issuance

### 3. Graph Sign-ins (SigninLogs)
- Graph API access anomalies  
- Impossible travel and foreign pivots

### 4. Service Principal Sign-ins
- Machine-level app-only persistence  
- API activity without user context

---

## Scoring Breakdown

Component | Weight
---------|-------
High-risk permissions | +1 each
Admin consent | +2
App-only authentication | +2
Suspicious user-agent | +1
Unknown application | +1
Unknown publisher | +1
Token replay or SP sign-ins | +2

Final output sorts descending by RiskScore.

---

## Hunter Directives

Each alert generates a structured response block:

OAuth Consent Investigation: Application '<AppDisplayName>' granted <N> high-risk permissions.  
Consent Type: <Admin/User> | Grant: <Delegate/AppOnly>  
Initiator and IP: <User> from <IP>  
TokenUse: <Count> | SP Sign-ins: <Count>  
RiskScore: <Score>

Analyst Actions:
1. Confirm whether the user intentionally approved the consent.  
2. Investigate AppID and publisher reputation.  
3. Pivot on IP address and user-agent.  
4. Review full permission list and risk level.  
5. Evaluate token usage, refresh-token activity, and SP sign-ins.  
6. Revoke application access if malicious.  
7. Reset credentials if compromise is suspected.

---

## Lab Testing Guidance

For controlled validation:

- Create a dummy Azure app  
- Grant permissions such as Mail.Read or Files.ReadWrite.All  
- Perform Graph API calls using Python, curl, or Postman  
- Observe RiskScore behaviour, token replay, and SP sign-in logging  

---

## Contact
Detection engineering, threat modelling, or collaboration:  
GitHub: https://github.com/azdabat
