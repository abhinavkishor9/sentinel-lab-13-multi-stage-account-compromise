# Sentinel Lab 13 — Multi-Stage Account Compromise

## Overview

This lab simulates a multi-stage account compromise investigation using Microsoft Sentinel and KQL `datatable()`.

The investigation correlates authentication failures, a successful authentication from a different source, an account authentication-method change, and subsequent Azure Portal activity.

The lab does not depend on populated `SigninLogs` or `AuditLogs`. All telemetry is created using `datatable()`, making the investigation reproducible in a controlled Sentinel environment.

## Scenario

The simulated account `user1@contoso.com` experiences three failed authentication attempts from `10.10.10.25` in Hyderabad.

Four minutes after the final failure, the account successfully authenticates from `203.0.113.20`, represented in the simulated data as New York, US.

Three minutes later, an authentication method is added to the account. Shortly afterward, the account accesses the Azure Portal and views resources from the same New York source IP.

The investigation focuses on correlating these events into a single sequence rather than treating each event independently.

## Attack Chain

```text
Repeated Failed Sign-ins
        |
        v
Successful Authentication
        |
        v
New Source IP / Location
        |
        v
Authentication Method Added
        |
        v
Azure Portal Access
        |
        v
Resource Viewing
```

## Objectives

- Create simulated identity telemetry using KQL `datatable()`.
- Investigate repeated failed authentication attempts.
- Identify successful authentication following failed attempts.
- Compare source IP and location changes.
- Investigate account authentication-method modification.
- Correlate Azure Portal activity with authentication events.
- Build a chronological investigation timeline.
- Calculate time intervals between events.
- Apply MITRE ATT&CK techniques to observed behavior.
- Classify evidence as confirmed, suspicious, plausible, or unknown.
- Practice evidence-driven SOC investigation.

## Lab Data

### SigninData

Contains simulated authentication activity:

- `TimeGenerated`
- `UserPrincipalName`
- `IPAddress`
- `Location`
- `AppDisplayName`
- `ResultType`
- `ResultDescription`
- `UserAgent`

### AccountChanges

Contains simulated account modification activity:

- `TimeGenerated`
- `UserPrincipalName`
- `OperationName`
- `TargetResource`
- `InitiatedBy`
- `Result`

### ApplicationAccess

Contains simulated application activity:

- `TimeGenerated`
- `UserPrincipalName`
- `IPAddress`
- `Location`
- `Application`
- `Action`

## Investigation Flow

1. Review failed authentication activity.
2. Identify the successful authentication.
3. Compare source IPs and locations.
4. Investigate the account modification.
5. Review Azure Portal access.
6. Correlate the datasets using `union`.
7. Calculate event intervals using `serialize`, `prev()`, and `datetime_diff()`.
8. Classify the evidence.
9. Map relevant activity to MITRE ATT&CK.
10. Document investigation limitations and response considerations.

## Key Findings

The simulated dataset produced the following sequence:

```text
10:01  Failed Sign-in
10:02  Failed Sign-in
10:03  Failed Sign-in
10:07  Successful Sign-in
10:10  Account Modification
10:12  Azure Portal Login
10:13  Viewed Resources
```

The three failed authentication attempts originated from:

```text
10.10.10.25
Hyderabad, IN
```

The successful authentication at `10:07 UTC` originated from:

```text
203.0.113.20
New York, US
```

The authentication method was then added at `10:10 UTC`.

The account subsequently accessed the Azure Portal and viewed resources from the same New York source IP.

## MITRE ATT&CK

| Technique | ID | Relevance |
|---|---|---|
| Brute Force | T1110 | Repeated failed authentication attempts are simulated. |
| Valid Accounts | T1078 | Successful authentication using the target account is observed. |
| Account Manipulation | T1098 | An authentication method is added to the account. |

## Evidence Assessment

### Confirmed

- Three failed sign-ins occurred for `user1@contoso.com`.
- A successful authentication occurred at `10:07 UTC`.
- The successful authentication used `203.0.113.20`.
- An authentication method was added at `10:10 UTC`.
- Azure Portal access occurred at `10:12 UTC`.
- Resources were viewed at `10:13 UTC`.

### Suspicious

- Repeated failed authentication followed by successful authentication.
- Source IP and location change.
- Authentication method modification shortly after successful authentication.
- Azure Portal activity following the account modification.

### Plausible

- Legitimate travel.
- Approved VPN or proxy usage.
- Intentional authentication-method change.
- Authorized administrative activity.

### Unknown

- Whether the account was actually compromised.
- Whether `203.0.113.20` was malicious.
- Whether the authentication method was added by an attacker.
- Whether the resource access was unauthorized.
- Whether additional accounts were affected.

## Detection Concept

A potential correlation detection could look for:

```text
Multiple Failed Sign-ins
        +
Successful Authentication
        +
New IP / Location
        +
Account Modification
        +
Sensitive Application Access
```

Production detection logic should incorporate additional context such as known VPN ranges, device identity, MFA information, Conditional Access results, user travel information, authentication risk, and known administrative activity.

## Investigation Limitations

This lab uses simulated telemetry created with `datatable()`.

It does not contain:

- Real `SigninLogs`
- Real `AuditLogs`
- Endpoint telemetry
- Device identity
- MFA details
- Conditional Access results
- IP reputation
- Authentication risk information
- Detailed Azure resource audit activity

Therefore, the lab demonstrates event correlation and investigation methodology rather than proving a real-world account compromise.

## SOC Response Considerations

If a similar sequence appeared in a production environment, an analyst could:

1. Validate whether the successful authentication was expected.
2. Review the source IP, device, user agent, and authentication method.
3. Investigate account and authentication-method changes.
4. Review Azure Portal and resource activity.
5. Search for additional activity from the same source.
6. Investigate related accounts.
7. Validate VPN, travel, and administrative context.
8. Escalate or contain the account if additional evidence supports compromise.
9. Review and revoke suspicious sessions or credentials where appropriate.
10. Document the evidence and investigation timeline.

## Skills Demonstrated

- Microsoft Sentinel
- KQL
- `datatable()`
- `union`
- `serialize`
- `prev()`
- `datetime_diff()`
- Identity investigation
- Authentication analysis
- Event correlation
- Timeline analysis
- MITRE ATT&CK
- Evidence classification
- SOC investigation methodology
