# Investigation Timeline — Multi-Stage Account Compromise

## Timeline

| Time UTC | User | Event Type | IP Address | Location | Details |
|---|---|---|---|---|---|
| 10:01 | `user1@contoso.com` | Failed Sign-in | `10.10.10.25` | Hyderabad, IN | Invalid username or password |
| 10:02 | `user1@contoso.com` | Failed Sign-in | `10.10.10.25` | Hyderabad, IN | Invalid username or password |
| 10:03 | `user1@contoso.com` | Failed Sign-in | `10.10.10.25` | Hyderabad, IN | Invalid username or password |
| 10:07 | `user1@contoso.com` | Successful Sign-in | `203.0.113.20` | New York, US | Success |
| 10:10 | `user1@contoso.com` | Account Modification | — | — | Add authentication method |
| 10:12 | `user1@contoso.com` | Application Access | `203.0.113.20` | New York, US | Successful Login |
| 10:13 | `user1@contoso.com` | Application Access | `203.0.113.20` | New York, US | Viewed Resources |

## Event Sequence

```text
10:01  Failed Sign-in
          |
          | 60 seconds
          v
10:02  Failed Sign-in
          |
          | 60 seconds
          v
10:03  Failed Sign-in
          |
          | 240 seconds
          v
10:07  Successful Sign-in
          |
          | 180 seconds
          v
10:10  Account Modification
          |
          | 120 seconds
          v
10:12  Azure Portal Login
          |
          | 60 seconds
          v
10:13  Viewed Resources
```

## Stage 1 — Failed Authentication

Three failed authentication attempts occurred against:

```text
User: user1@contoso.com
IP: 10.10.10.25
Location: Hyderabad, IN
```

The attempts occurred at one-minute intervals.

### Assessment

Repeated failed authentication activity is confirmed in the simulated dataset.

## Stage 2 — Successful Authentication

At `10:07 UTC`, authentication succeeded from:

```text
IP: 203.0.113.20
Location: New York, US
Application: Microsoft Office
User Agent: Chrome
```

This occurred four minutes after the final failed authentication.

### Assessment

The source change creates a suspicious authentication transition that requires validation.

## Stage 3 — Account Modification

At `10:10 UTC`:

```text
Operation: Add authentication method
Target: user1@contoso.com
Initiated By: user1@contoso.com
Result: Success
```

The modification occurred three minutes after the successful authentication.

### Assessment

The account security configuration changed shortly after authentication.

The dataset does not establish whether the change was malicious or authorized.

## Stage 4 — Azure Portal Access

At `10:12 UTC`:

```text
Application: Azure Portal
Action: Successful Login
IP: 203.0.113.20
Location: New York, US
```

The source IP matches the successful authentication at `10:07 UTC`.

### Assessment

The event provides additional activity associated with the same account and source.

## Stage 5 — Resource Viewing

At `10:13 UTC`:

```text
Application: Azure Portal
Action: Viewed Resources
IP: 203.0.113.20
Location: New York, US
```

### Assessment

Resource viewing continued immediately after Azure Portal login.

The dataset does not identify which resources were viewed or whether the access was authorized.

## Event Intervals

| Event Transition | Interval |
|---|---:|
| Failed Sign-in 1 -> Failed Sign-in 2 | 60 seconds |
| Failed Sign-in 2 -> Failed Sign-in 3 | 60 seconds |
| Failed Sign-in 3 -> Successful Sign-in | 240 seconds |
| Successful Sign-in -> Account Modification | 180 seconds |
| Account Modification -> Azure Portal Login | 120 seconds |
| Azure Portal Login -> Resource Viewing | 60 seconds |

## Attack Chain

```text
Repeated Failed Authentication
              |
              v
Successful Authentication
              |
              v
New Source IP / Location
              |
              v
Authentication Method Modification
              |
              v
Azure Portal Access
              |
              v
Resource Viewing
```

## MITRE ATT&CK Mapping

| Activity | Technique | ID |
|---|---|---|
| Repeated failed authentication | Brute Force | T1110 |
| Successful authentication | Valid Accounts | T1078 |
| Authentication method modification | Account Manipulation | T1098 |

## Evidence Classification

### Confirmed

- Three failed sign-ins occurred.
- A successful authentication occurred.
- The successful authentication originated from `203.0.113.20`.
- The successful authentication location was represented as New York, US.
- An authentication method was added.
- Azure Portal login occurred.
- Resources were viewed.

### Suspicious

- Failed authentication attempts were followed by successful authentication.
- The successful authentication originated from a different IP and location.
- The authentication method was modified shortly afterward.
- Azure Portal activity followed the account modification.

### Unknown

- Whether the account was compromised.
- Whether `203.0.113.20` was malicious.
- Whether the authentication-method change was unauthorized.
- Whether the Azure resource access was unauthorized.
- Whether other accounts were affected.

## Timeline Conclusion

The events form a short, correlated identity sequence involving the same account:

```text
Failure
    ->
Authentication Success
    ->
Account Modification
    ->
Application Access
    ->
Resource Viewing
```

The sequence is suitable for further SOC investigation, but the simulated telemetry alone does not establish a confirmed account compromise.
