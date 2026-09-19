# Troubleshooting Notes — Multi-Stage Account Compromise

## Issue 1 — `SigninData` Could Not Be Resolved

### Error

```text
'extend' operator: Failed to resolve table or column expression named 'SigninData'
```

### Request ID

```text
11c6c02a-550b-4782-b282-fba82018c133
```

### Cause

`SigninData` was created using a KQL `let` statement and `datatable()`.

A `let` variable is available only within the query execution where it is defined.

Running only the `union` portion without the preceding `let SigninData = ...` definition caused Sentinel to interpret `SigninData` as a table or column expression that did not exist.

### Resolution

The complete query was executed together, including all `let` definitions before the `union`:

```kusto
let SigninData = datatable(...);

let AccountChanges = datatable(...);

let ApplicationAccess = datatable(...);

union
(
    SigninData
    ...
)
```

A standalone validation query was also used:

```kusto
SigninData
```

This confirmed that the `datatable()` definition was available when the complete query was executed.

## Issue 2 — Union Schema Compatibility

The three simulated datasets had different schemas.

### SigninData

```text
ResultType
ResultDescription
AppDisplayName
UserAgent
```

### AccountChanges

```text
OperationName
TargetResource
InitiatedBy
Result
```

### ApplicationAccess

```text
Application
Action
```

Using the datasets directly inside `union` can result in inconsistent output columns or type conflicts.

### Resolution

Each dataset was normalized into a common investigation schema:

```text
TimeGenerated
UserPrincipalName
EventType
IPAddress
Location
Details
Application
```

Example:

```kusto
SigninData
| extend EventType = iff(ResultType == 0, "Successful Sign-in", "Failed Sign-in")
| project
    TimeGenerated,
    UserPrincipalName,
    EventType,
    IPAddress,
    Location,
    Details = ResultDescription,
    Application = AppDisplayName
```

The same output structure was used for `AccountChanges` and `ApplicationAccess`.

## Issue 3 — Data Type Conflicts

Different branches of a `union` need compatible column types.

The investigation used explicit type definitions in each `datatable()`.

For example:

```kusto
TimeGenerated:datetime
UserPrincipalName:string
IPAddress:string
ResultType:int
```

Where necessary, the final query also used explicit conversions:

```kusto
TimeGenerated = todatetime(TimeGenerated)
```

```kusto
UserPrincipalName = tostring(UserPrincipalName)
```

This helped maintain a consistent schema across the union branches.

## Issue 4 — Empty Columns in Union Branches

`AccountChanges` does not contain an IP address, location, or application field.

Those fields were therefore supplied as empty strings:

```kusto
IPAddress = ""
Location = ""
Application = ""
```

This allowed the account modification events to use the same investigation schema as the authentication and application events.

## Issue 5 — Unrelated `user2` Event

The `SigninData` dataset contains a successful authentication for:

```text
user2@contoso.com
```

at:

```text
10:04 UTC
```

This event demonstrates that the simulated authentication dataset contains activity for multiple users.

However, the investigation focuses on:

```text
user1@contoso.com
```

The final correlation therefore filters the timeline:

```kusto
| where UserPrincipalName =~ "user1@contoso.com"
```

This removes the unrelated `user2` event from the final investigation.

## Issue 6 — Timeline Result Did Not Initially Show 10:13

The complete `ApplicationAccess` dataset contains:

```text
10:12 — Successful Login
10:13 — Viewed Resources
```

The interval-analysis result shown during the investigation ended at the `10:12` event.

The separate `ApplicationAccess` query confirmed that the `10:13` event existed.

Therefore, the complete investigation timeline includes the `10:13` resource-viewing event.

## Issue 7 — Avoiding False Conclusions From Location Changes

The simulated authentication activity changes from:

```text
10.10.10.25
Hyderabad, IN
```

to:

```text
203.0.113.20
New York, US
```

This should not automatically be treated as proof of account compromise.

Possible explanations include:

- VPN usage
- Proxy infrastructure
- Legitimate travel
- Remote access
- Simulated attacker activity

The correct SOC approach is to flag the transition for investigation and validate it using additional telemetry.

## Issue 8 — Production Tables Were Not Required

The lab was intentionally built with:

```kusto
datatable()
```

instead of depending on populated Sentinel tables such as:

```text
SigninLogs
AuditLogs
AADRiskyUsers
AADUserRiskEvents
```

This made the investigation reproducible in a workspace where production-like identity telemetry was unavailable.

## Validation Checklist

- [x] `SigninData` defined before it is referenced.
- [x] `AccountChanges` defined before it is referenced.
- [x] `ApplicationAccess` defined before it is referenced.
- [x] All `let` statements executed as part of the same query.
- [x] Union branches use a consistent schema.
- [x] `TimeGenerated` is defined as `datetime`.
- [x] User identity fields are defined as `string`.
- [x] Missing fields are supplied with compatible values.
- [x] `user2` is excluded from the final user-specific timeline.
- [x] The `10:13` resource-viewing event is included in the complete dataset.

## Lessons Learned

The main troubleshooting lesson was that KQL `let` variables created with `datatable()` are query-scoped.

When building a multi-dataset Sentinel investigation:

1. Define each dataset first.
2. Test each dataset independently.
3. Normalize the schemas.
4. Combine the datasets with `union`.
5. Filter to the investigation target.
6. Order the events chronologically.
7. Perform timeline and interval analysis.

This workflow makes simulated Sentinel investigations easier to troubleshoot and reduces schema-related errors.
