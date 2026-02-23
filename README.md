
# KQL-Queries-Sheet-For-Azure-Honeynet-trap

A portfolio-focused KQL query sheet built for my **Azure Honeynet / SOC Lab**, designed to help validate telemetry, hunt threats, and explain how Sentinel/Log Analytics detections are constructed.

🔗 **Original Lab (Full Build + Architecture):**  
https://github.com/reyestech/Azure-SOC-Sentinel-Honeynet-Detection-Lab-/blob/main/README.md

---

## What this repo demonstrates

This repository highlights practical experience with:

- **Threat hunting & detection engineering** using KQL  
- **Microsoft Sentinel / Log Analytics** data sources and investigation workflows  
- **Windows + Linux telemetry** (auth events, brute force patterns, endpoint signals)  
- **Azure control plane + cloud service logs** (Entra ID, Storage, Key Vault, NSG)  
- **Automation readiness** (quick validation queries for ingestion + SOC health checks)

---

## Quick Start (How to use)

1. Open **Microsoft Sentinel → Logs** (or Log Analytics workspace logs)
2. Copy any query below into the query editor
3. Adjust the time range (ex: `ago(15m)`, `ago(1h)`, `ago(24h)`)
4. Use results to:
   - validate ingestion,
   - investigate suspicious activity,
   - or convert into an **Analytics Rule** when appropriate.

> All queries are **read-only** (no data mutation commands).

---

<details>
<summary><strong>📚 Table of Contents (click to expand)</strong></summary>

- Windows Security Event Log
- Windows Security Event Log (Malware & Firewall)
- Linux Syslog
- Azure Active Directory (Entra ID)
- Azure Storage Account
- Azure Key Vault
- Network Security Groups
- Automation & Telemetry Validation Queries
- Conclusion

</details>

---

# **Query Categories**

## **Windows Security Event Log**
**Purpose:** Investigate Windows authentication activity and brute-force patterns using `SecurityEvent`.

<details>
<summary><strong>How it works</strong></summary>

- Uses Windows Security Event IDs to identify login successes/failures.
- Detects brute-force attempts by counting repeated failures from the same source IP.
- Detects brute-force success by correlating prior failures with a later success.

</details>

```kql
// Failed Authentication (RDP, SMB)
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(15m)
```

```kql
// Authentication Success (RDP, SMB)
SecurityEvent
| where EventID == 4624
| where TimeGenerated > ago(15m)
```

```kql
// Brute Force Attempt
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(60m)
| summarize FailureCount = count() by SourceIP = IpAddress, EventID, Activity
| where FailureCount >= 10
```

```kql
// Brute Force Success Windows
let FailedLogons = SecurityEvent
| where EventID == 4625 and LogonType == 3
| where TimeGenerated > ago(60m)
| summarize FailureCount = count() by AttackerIP = IpAddress, EventID, Activity, LogonType, DestinationHostName = Computer
| where FailureCount >= 5;
let SuccessfulLogons = SecurityEvent
| where EventID == 4624 and LogonType == 3
| where TimeGenerated > ago(60m)
| summarize SuccessfulCount = count() by AttackerIP = IpAddress, LogonType, DestinationHostName = Computer, AuthenticationSuccessTime = TimeGenerated;
SuccessfulLogons
| join kind = leftouter FailedLogons on DestinationHostName, AttackerIP, LogonType
| project AuthenticationSuccessTime, AttackerIP, DestinationHostName, FailureCount, SuccessfulCount
```
---

## **Windows Security Event Log (Malware & Firewall)**
**Purpose:** Review Windows Defender malware detections and firewall tampering activity.

**How it works**
- Windows Defender operational log events show detection/remediation activity.
- Firewall Advanced Security events can indicate rule or policy tampering.

```kql
// Malware Detection
Event
| where EventLog == "Microsoft-Windows-Windows Defender/Operational"
| where EventID == "1116" or EventID == "1117"
```

```kql
// Firewall Tamper Detection
Event
| where EventLog == "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
| where EventID == 2003
```

---

## **Linux Syslog**
**Purpose:** Detect Linux SSH brute force and extract attacker IPs from auth logs.

**How it works**
- Filters auth facility logs for “Failed password” and “Accepted password”.
- Extracts attacker IPs using regex.
- Detects brute-force attempts by counting repeated failures per IP/host.
- Optionally correlates failures → later success to identify compromise patterns.

```kql
// Failed logon (ip address extract)
let IpAddress_REGEX_PATTERN = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";
Syslog
| where Facility == "auth"
| where SyslogMessage startswith "Failed password for"
| project TimeGenerated, SourceIP = extract(IpAddress_REGEX_PATTERN, 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
```

```kql
// Successful logon (ip address extract)
let IpAddress_REGEX_PATTERN = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";
Syslog
| where Facility == "auth"
| where SyslogMessage startswith "Accepted password for"
| project TimeGenerated, SourceIP = extract(IpAddress_REGEX_PATTERN, 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
```

```kql
// Brute Force Attempt Linux Syslog
let IpAddress_REGEX_PATTERN = @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";
Syslog
| where Facility == "auth" and SyslogMessage startswith "Failed password for"
| where TimeGenerated > ago(1h)
| project TimeGenerated, AttackerIP = extract(IpAddress_REGEX_PATTERN, 0, SyslogMessage), DestinationHostName = HostName, DestinationIP = HostIP, Facility, SyslogMessage, ProcessName, SeverityLevel, Type
| summarize FailureCount = count() by AttackerIP, DestinationHostName, DestinationIP
| where FailureCount >= 5
```

```kql
// Brute Force Success Linux
let FailedLogons = Syslog
| where Facility == "auth" and SyslogMessage startswith "Failed password for"
| where TimeGenerated > ago(1h)
| project TimeGenerated, SourceIP = extract(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0, SyslogMessage), DestinationHostName = HostName
| summarize FailureCount = count() by AttackerIP = SourceIP, DestinationHostName
| where FailureCount >= 5;
let SuccessfulLogons = Syslog
| where Facility == "auth" and SyslogMessage startswith "Accepted password for"
| where TimeGenerated > ago(1h)
| project TimeGenerated, SourceIP = extract(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0, SyslogMessage), DestinationHostName = HostName
| summarize SuccessfulCount = count() by SuccessTime = TimeGenerated, AttackerIP = SourceIP, DestinationHostName;
SuccessfulLogons
| join kind = leftouter FailedLogons on AttackerIP, DestinationHostName
```

```kql
// Queries the linux syslog for any user accounts created (Discord: @slendymayne)// Queries the linux syslog for any user accounts created SyslogMessage contains "new user" and SyslogMessage contains "shell=/bin/bash"
| project TimeGenerated, HostIP, HostName, ProcessID, SyslogMessage
Syslog
| where Facility == "authpriv" and SeverityLevel == "info"
```

```kql
// Queries the linux syslog for any user accounts created (Discord: @slendymayne)// Queries the linux syslog for any user accounts created SyslogMessage contains "new user" and SyslogMessage contains "shell=/bin/bash"
| project TimeGenerated, HostIP, HostName, ProcessID, SyslogMessage
Syslog
| where Facility == "authpriv" and SeverityLevel == "info"
```

---

## **Azure Active Directory (Entra ID)**
**Purpose:** Monitor authentication anomalies and sensitive identity changes.

**How it works**
- Uses SigninLogs for auth failures/success and geolocation enrichment.
- Uses AuditLogs for privileged role assignments and password-related actions.
- Correlates failures → success to highlight brute-force success patterns.

```kql
// View Mass AAD Auth FailuresLogs
| where ResultDescription == "Invalid username or password or Invalid on-premise username or password."
| extend location = parse_json(LocationDetails)
| extend City = location.city, State = location.state, Country = location.countryOrRegion, Latitude = location.geoCoordinates.latitude, Longitude = location.geoCoordinates.longitude
| project TimeGenerated, ResultDescription, UserPrincipalName, AppDisplayName, IPAddress, IPAddressFromResourceProvider, City, State, Country, Latitude, Longitude
```

```kql
// View Global Administrator Assignment
AuditLogs
| where OperationName == "Add member to role" and Result == "success"
| where TargetResources[0].modifiedProperties[1].newValue == '"Global Administrator"' or TargetResources[0].modifiedProperties[1].newValue == '"Company Administrator"'
| order by TimeGenerated desc
| project TimeGenerated, OperationName, AssignedRole = TargetResources[0].modifiedProperties[1].newValue, Status = Result, TargetResources
```

```kql
// View Password Activities
AuditLogs
| where OperationName contains "password"
| order by TimeGenerated
```

```kql
// Brute Force Success Azure Active Directory
let FailedLogons = SigninLogs
| where Status.failureReason == "Invalid username or password or Invalid on-premise username or password."
| where TimeGenerated > ago(1h)
| summarize FailureCount = count() by AttackerIP = IPAddress, UserPrincipalName;
let SuccessfulLogons = SigninLogs
| where Status.errorCode == 0
| where TimeGenerated > ago(1h)
| summarize SuccessCount = count() by AuthenticationSuccessTime = TimeGenerated, AttackerIP = IPAddress, UserPrincipalName;
SuccessfulLogons
| join kind = leftouter FailedLogons on AttackerIP, UserPrincipalName
| project AttackerIP, TargetAccount = UserPrincipalName, FailureCount, SuccessCount, AuthenticationSuccessTime
```

```kql
// Excessive password resets
Auditwith "Change" or OperationName startswith "Reset"AuditLogs
| summarize count() by tostring(InitiatedBy)
| project Count = count_, InitiatorId = parse_json(InitiatedBy).user.id, InitiatorUpn = parse_json(InitiatedBy).user.userPrincipalName, InitiatorIpAddress = parse_json(InitiatedBy).user.ipAddress
| where Count >= 10
```

---

## **Azure Storage Account**
**Purpose:** Identify unusual blob operations and access issues.

```kql
// Authorization Error
StorageBlobLogs
| where MetricResponseType endswith "Error"
| where StatusText == "AuthorizationPermissionMismatch"
| order by TimeGenerated asc
```

```kql
// Reading a bunch of blobs
StorageBlobLogs
| where OperationName == "GetBlob"
```

```kql
// Deleting a bunch of blobs (in a short time period)
StorageBlobLogs
| where OperationName == "DeleteBlob"
| where TimeGenerated > ago(24h)
```

```kql
// Putting a bunch of blobs (in a short time period)
StorageBlobLogs
| where OperationName == "PutBlob"
| where TimeGenerated > ago(24h)
```

```kql
// Copying a bunch of blobs (in a short time period)
StorageBlobLogs
| where OperationName == "CopyBlob"
| where TimeGenerated > ago(24h)
```

---

## **Azure Key Vault**
**Purpose:** Monitor secret access and failed/unauthorized attempts.

```kql
// List out Secrets
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretList"
```

```kql
// Attempt to view passwords that don't exist
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretGet"
| where ResultSignature == "Not Found"
```

```kql
// Viewing an actual existing password
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretGet"
| where ResultSignature == "OK"
```

```kql
// Viewing a specific existing password
let CRITICAL_PASSWORD_NAME = "Tenant-Global-Admin-Password";
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretGet"
| where id_s contains CRITICAL_PASSWORD_NAME
```

```kql
// Updating a password Success
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretSet"
```

```kql
// Failed access attempts
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where ResultSignature == "Unauthorized"
```

---

## **Network Security Groups**
**Purpose:** Surface inbound malicious traffic allowed through NSGs.

```kql
// Allowed inbound malicious flows
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d >= 1
| project TimeGenerated, FlowType = FlowType_s, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s, DestinationPort = DestPort_d, Protocol = L7Protocol_s, NSGRuleMatched = NSGRules_s, InboundFlowCount = AllowedInFlows_d
```

# **Automation & Telemetry Validation Queries**
These queries validate ingestion and confirm security signals are available across key sources.

### Defining a Start‑Stop Time Window
```kql
range x from 1 to 1 step 1
| project StartTime = ago(24h), StopTime = now()
```

### Windows Security Events Ingestion Check
```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| count
```

### Linux Syslog Ingestion Check
```kql
Syslog
| where TimeGenerated >= ago(24h)
| count
```

### Defender for Cloud Alerts Check
```kql
SecurityAlert
| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"
| where TimeGenerated >= ago(24h)
| count
```

### Sentinel Incidents Check
```kql
SecurityIncident
| where TimeGenerated >= ago(24h)
| count
```

### Allowed Malicious NSG Flows (Count)
```kql
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0
| where TimeGenerated >= ago(24h)
| count
```

### Denied Malicious NSG Flows (Count)
```kql
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow" and DeniedInFlows_d > 0
| where TimeGenerated >= ago(24h)
| count
```

## **Conclusion**
This repo documents the KQL queries used to investigate and validate activity in my Azure Honeynet SOC Lab. It demonstrates practical experience across identity, endpoint, network, and Azure service telemetry—plus the ability to turn raw logs into repeatable hunts and automation-ready detections in Microsoft Sentinel.

