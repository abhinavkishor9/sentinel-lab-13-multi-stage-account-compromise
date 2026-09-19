# Investigation Notes 

## 1. Authentication Failures

The initial authentication dataset showed three failed sign-ins:

| Time UTC | Account | IP Address | Location | Result Type | Description |
|---|---|---|---|---:|---|
| 10:01 | `user1@contoso.com` | `10.10.10.25` | Hyderabad, IN | 50126 | Invalid username or password |
| 10:02 | `user1@contoso.com` | `10.10.10.25` | Hyderabad, IN | 50126 | Invalid username or password |
| 10:03 | `user1@contoso.com` | `10.10.10.25` | Hyderabad, IN | 50126 | Invalid username or password |

The attempts occurred at one-minute intervals.

### Assessment

The dataset confirms repeated failed authentication activity against the same account.

The activity is suspicious but does not independently establish that an automated brute-force attack occurred.

## 2. Successful Authentication

At `10:07 UTC`, `user1@contoso.com` successfully authenticated.

| Field | Value |
|---|---|
| User | `user1@contoso.com` |
| IP Address | `203.0.113.20` |
| Location | New York, US |
| Application | Microsoft Office |
| User Agent | Chrome |
| Result | Success |

The successful authentication occurred four minutes after the last failed attempt.

The source IP and location differ from the preceding failed authentication activity.

### Assessment

The transition is suspicious and requires validation.

The available dataset does not establish whether the change resulted from malicious access, legitimate travel, VPN usage, proxy infrastructure, or another expected access path.

## 3. Account Modification

At `10:10 UTC`, the account recorded a successful authentication-method modification.

```text
Operation: Add authentication method
Target Resource: user1@contoso.com
Initiated By: user1@contoso.com
Result: Success
```

The event occurred three minutes after the successful authentication.

### Assessment

Adding an authentication method is a security-sensitive account change.

The dataset confirms that the modification occurred but does not identify the specific authentication method or establish whether the change was authorized.

## 4. Application Access

At `10:12 UTC`, the account successfully accessed the Azure Portal.

```text
Application: Azure Portal
Action: Successful Login
IP Address: 203.0.113.20
Location: New York, US
```

At `10:13 UTC`, the same account viewed resources.

```text
Application: Azure Portal
Action: Viewed Resources
IP Address: 203.0.113.20
Location: New York, US
```

### Assessment

The application activity is correlated with the same source IP used for the successful authentication.

This extends the suspicious sequence from authentication into cloud application activity.

## 5. Correlated Timeline

The final sequence is:

```text
10:01  Failed Sign-in
10:02  Failed Sign-in
10:03  Failed Sign-in
10:07  Successful Sign-in
10:10  Account Modification
10:12  Application Access
10:13  Resource Viewing
```

The sequence can be represented as:

```text
Authentication Failures
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
Azure Portal Login
        |
        v
Resource Viewing
```

## 6. Event Intervals

The timeline analysis used `serialize` and `prev()` to compare consecutive events.

| Event Transition | Interval |
|---|---:|
| First failed sign-in -> Second failed sign-in | 60 seconds |
| Second failed sign-in -> Third failed sign-in | 60 seconds |
| Third failed sign-in -> Successful sign-in | 240 seconds |
| Successful sign-in -> Account modification | 180 seconds |
| Account modification -> Azure Portal login | 120 seconds |
| Azure Portal login -> Resource viewing | 60 seconds |

## 7. Evidence Classification

### Confirmed

- Three failed authentication attempts occurred.
- The failures involved `user1@contoso.com`.
- A successful authentication occurred at `10:07 UTC`.
- The successful authentication originated from `203.0.113.20`.
- An authentication method was added at `10:10 UTC`.
- Azure Portal access occurred at `10:12 UTC`.
- Resources were viewed at `10:13 UTC`.

### Suspicious

- Repeated authentication failures were followed by successful authentication.
- The successful authentication used a different IP and location.
- An authentication method was added shortly after the successful authentication.
- Azure Portal access followed the account modification.
- Resource viewing continued from the same New York source IP.

### Plausible

- Legitimate travel.
- Approved VPN usage.
- Proxy infrastructure.
- Intentional authentication-method registration.
- Authorized administrative activity.

### Unknown

- Whether the credentials were compromised.
- Whether `203.0.113.20` was malicious.
- Whether the authentication-method change was unauthorized.
- Whether the Azure resources were sensitive.
- Whether the resource access was authorized.
- Whether other accounts were affected.
- Whether persistence was actually established.

## 8. MITRE ATT&CK Mapping

### T1110 — Brute Force

The three repeated failed authentication attempts are consistent with the simulated brute-force stage.

The available data does not establish the exact brute-force subtype or whether automation was involved.

### T1078 — Valid Accounts

The successful authentication demonstrates use of valid credentials associated with `user1@contoso.com`.

The event does not establish whether the credentials were stolen.

### T1098 — Account Manipulation

The `Add authentication method` event represents simulated account modification activity.

Additional telemetry would be required to determine the exact mechanism and intent.

## 9. Detection Logic

A potential detection sequence is:

```text
3+ Failed Sign-ins
        |
        v
Successful Authentication
        |
        v
New IP / Location
        |
        v
Authentication Method Change
        |
        v
Sensitive Application Access
```

A production detection should incorporate:

- Known VPN ranges
- Known corporate IP ranges
- Device identity
- MFA status
- Conditional Access results
- User travel context
- Authentication risk
- IP reputation
- Administrative activity
- Historical user behavior

## 10. Investigation Limitations

This investigation uses controlled `datatable()` telemetry.

The dataset does not contain:

- Endpoint telemetry
- Device information
- MFA details
- Conditional Access results
- IP reputation
- Authentication risk signals
- Process telemetry
- Network telemetry
- Detailed Azure resource audit events

The investigation therefore demonstrates event correlation and evidence-based analysis rather than proving a real account compromise.

