# sentinel-lab-13-multi-stage-account-compromise
## Overview

A multi-stage account compromise occurs when an attacker gains control of a legitimate user account through a sequence of activities rather than a single obvious event.

From a SOC perspective, the important concept is event correlation. Individual events may not be enough to establish compromise:

Several failed sign-ins could be a user entering the wrong password.
A successful sign-in from an unusual location could be legitimate travel.
A change to an account could be an administrator performing routine maintenance.
Access to an application could be normal business activity.

However, when these events occur against the same account, from related sources, and within a meaningful time window, they can form a coherent attack sequence.

Example attack chain
Password Spray
      ↓
Successful Authentication
      ↓
Unusual Location / IP
      ↓
Account or Authentication Change
      ↓
Sensitive Resource Access
      ↓
Potential Account Compromise

This lab simulates a multi-stage account compromise investigation using Microsoft Sentinel and KQL `datatable()`.

The investigation correlates authentication failures, a successful authentication from a different source, an account authentication-method change, and subsequent Azure Portal activity.

The lab does not depend on populated `SigninLogs` or `AuditLogs`. All telemetry is created using `datatable()`, making the investigation reproducible in a controlled Sentinel environment.

## Scenario

A user account, `user1@contoso.com`, is showing a sequence of authentication and account activity that requires investigation. The available telemetry is simulated using KQL `datatable()` objects representing sign-in events, account changes, and application access.

The investigation begins with three consecutive failed sign-in attempts from the same internal IP address in Hyderabad. A successful sign-in then occurs a few minutes later from a different IP address associated with New York.

The investigation is expanded to determine whether additional activity followed the successful authentication. An account-change event shows that an authentication method was added to the affected account, followed shortly by successful access to the Azure Portal and subsequent resource viewing.

The analyst must correlate these events into a single timeline and determine whether the sequence is consistent with a possible account compromise.

### Investigation Focus

- Repeated failed authentication attempts against `user1@contoso.com`.
- Successful authentication following the failed attempts.
- Change in source IP address and geographic location.
- Addition of an authentication method to the account.
- Subsequent Azure Portal access and resource viewing.
- Time intervals between the individual events.
- Correlation of activity across separate simulated datasets.

The scenario is intentionally evidence-driven. The observed sequence should be treated as suspicious and investigated further rather than automatically classified as a confirmed compromise. Legitimate explanations such as VPN usage, authorized travel, administrative activity, or other changes in authentication context would need to be ruled out using additional telemetry.

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

The objective of this lab is to investigate a simulated account compromise by correlating multiple identity and application events rather than analyzing each event in isolation.

- Identify repeated failed authentication attempts associated with a single user account.
- Detect a subsequent successful authentication from a different source IP and geographic location.
- Correlate authentication activity with changes made to the affected account.
- Identify subsequent access to a sensitive administrative application.
- Construct a chronological sequence of events across multiple simulated datasets.
- Calculate time intervals between related events to understand the progression of the activity.
- Use KQL `union`, `where`, `project`, `summarize`, `serialize`, and `prev()` for investigation and correlation.
- Normalize different event schemas so authentication, account-change, and application-access data can be analyzed together.
- Classify observations as confirmed evidence, suspicious activity, plausible explanations, or unknowns.
- Map relevant investigation stages to MITRE ATT&CK techniques.
- Develop a detection concept for identifying multi-stage account compromise activity.
- Document telemetry limitations and distinguish simulated evidence from conclusions that would require additional investigation.
  
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

