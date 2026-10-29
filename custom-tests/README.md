# Vipr custom tests

Paste-ready tests for the Vipr custom connection, built in the Drata UI. Control mapping is a suggestion; confirm the control names in your tenant.

## Create a test

1. Monitoring > Create test. Enter the name and description below.
2. Category Custom. Provider: the connection name. Resource: the resource name.
3. Evaluation threshold: All results must pass.
4. Filtering criteria > Add > Inclusion. Paste the filter into the Advanced editor.
5. Condition group > Advanced editor. Paste the condition. Tests marked Builder can also be entered field by field; Advanced tests need the Advanced editor.
6. Save the draft, run it, publish, then map it to the controls.

The guided builder lists top-level facts only. Fields inside `findings[]` and `assets[]`, such as `isActive`, are not listed; test them in the Advanced editor with a nested rule (Drata keeps array items out of the guided builder by design).

Each record is one result. A failing partition fails the test; records outside the filter are not scored.

## Facts

Records: S scanSummary, F findingPartition, A assetPartition.

| Fact | Type | Records |
|---|---|---|
| `id` | string | SFA |
| `recordType` | string | SFA |
| `displayName` | string | SFA |
| `severity` | string | F |
| `generatedAt` | string | SFA |
| `sourceAsOf` | string | SFA |
| `sourceAgeDays` | number | SFA |
| `sourceFresh` | boolean | SFA |
| `findingsSourceAsOf` | string | S |
| `assetsSourceAsOf` | string | S |
| `tenableSourceAsOf` | string | S |
| `partition` | number | FA |
| `partitionCount` | number | FA |
| `itemCount` | number | FA |
| `findingPartitionCount` | number | S |
| `assetPartitionCount` | number | S |
| `findingCount` | number | S |
| `openFindingCount` | number | SF |
| `openSlaBreachedCount` | number | SF |
| `openSlaUnknownCount` | number | SF |
| `openMissingTicketCount` | number | SF |
| `openTicketUnknownCount` | number | SF |
| `severityChangedCount` | number | S |
| `closedFindingsExcludedCount` | number | S |
| `rejectedCount` | number | S |
| `assetCount` | number | S |
| `inactiveAssetCount` | number | SA |
| `staleAssetCount` | number | SA |
| `tenableStaleAssetCount` | number | SA |
| `tenableUnmatchedAssetCount` | number | SA |
| `findings` | array | F |
| `assets` | array | A |

`findings[]` items (Advanced editor, nested rule):

| Fact | Type |
|---|---|
| `id` | string |
| `displayId` | string |
| `viprSeverity` | string |
| `scannerSeverity` | string |
| `severityChanged` | boolean |
| `severityDirection` | string |
| `toolSeverities` | string |
| `open` | boolean |
| `ignored` | boolean |
| `hasTicket` | boolean |
| `missingTicket` | boolean |
| `slaDate` | string |
| `slaBreached` | boolean |
| `closedAfterSla` | boolean |
| `firstSeen` | string |
| `closedAt` | string |
| `assetId` | string |
| `assetName` | string |
| `cves` | array |
| `cveCount` | number |

`assets[]` items (Advanced editor, nested rule):

| Fact | Type |
|---|---|
| `id` | string |
| `name` | string |
| `assetType` | string |
| `isActive` | boolean |
| `lastSeen` | string |
| `daysSinceSeen` | number |
| `viprLastSeenStale` | boolean |
| `openFindingsCount` | number |
| `tenableMatch` | string |
| `tenableLastScan` | string |
| `tenableDaysSinceScan` | number |
| `tenableScanStale` | boolean |
| `tenableLastAuthenticatedScan` | string |

## Operators

| Field type | Operators |
|---|---|
| string | `equal`, `notEqual`, `in`, `notIn`, `contains`, `doesNotContain`, `startsWith`, `endsWith`, `exist`, `empty`, `isBefore`, `isAfter`, `withinLastDays`, `withinNextDays`, `withinLastHours`, `olderThanDays` |
| number | `equal`, `notEqual`, `in`, `notIn`, `lessThan`, `lessThanOrEqual`, `greaterThan`, `greaterThanOrEqual`, `exist`, `isBefore`, `isAfter`, `withinLastDays`, `withinNextDays`, `withinLastHours`, `olderThanDays` |
| boolean | `equal`, `notEqual`, `in`, `notIn`, `exist` |
| array of objects | `contains`, `doesNotContain`, `exist`, `empty`, `all`, `any`, `none`, `notAll` |

Operator names are exact: `equal` and `exist`, never `equals` or `exists`. Booleans and numbers are JSON values, not strings.

Date strings stay plain strings, so they offer the string operators and the date operators. Day operators use UTC calendar days: `withinLastDays` includes today and the day N days ago; `olderThanDays` is strictly older. `isBefore` and `isAfter` compare instants. A null or unparseable date is expected to fail every date operator.

Nullable fields (`string` or `null`) offer the same operators as their base type plus a null comparison. `equal true` and `equal false` both fail on null.

Array items are reachable only in the Advanced editor, through `all`, `any`, `none` or `notAll` with a nested rule whose facts are item properties. `all` and `none` pass on an empty array; `any` and `notAll` fail. Use `{"fact":"findings","path":"length","operator":"greaterThan","value":0}` to require items.

Limits: 7 conditions and 70 lines per code block; conditions inside a nested array rule are not counted.

## Tests

### 1. Vipr Scan Data Is Current

- Controls: DCF-18 Vulnerability Scans; DCF-455 Quarterly Internal Vulnerability Scans
- Editor: Builder
- Description: Vipr vulnerability data was refreshed within the allowed age and the nightly sync ran in the last 2 days.
- Note: Tests 2-8 also require a sync within the last 2 days, so a stopped job fails them.

Filtering criteria, Inclusion:

```json
{"all":[
  {"fact":"recordType","operator":"equal","value":"scanSummary"}
]}
```

Condition:

```json
{"all":[
  {"fact":"sourceFresh","operator":"equal","value":true},
  {"fact":"generatedAt","operator":"withinLastDays","value":2}
]}
```

### 2. Vipr Critical Vulnerabilities Addressed

- Controls: DCF-18 Vulnerability Scans; DCF-160 Service Level Agreements (SLAs) for Security; DCF-456 Vulnerabilities Identified and Resolved
- Editor: Builder
- Description: No open critical vulnerability is past its SLA date, and none has an undetermined SLA status.

Filtering criteria, Inclusion:

```json
{"all":[
  {"fact":"recordType","operator":"equal","value":"findingPartition"},
  {"fact":"severity","operator":"equal","value":"critical"}
]}
```

Condition:

```json
{"all":[
  {"fact":"sourceFresh","operator":"equal","value":true},
  {"fact":"generatedAt","operator":"withinLastDays","value":2},
  {"fact":"openSlaBreachedCount","operator":"equal","value":0},
  {"fact":"openSlaUnknownCount","operator":"equal","value":0}
]}
```

### 3. Vipr High Vulnerabilities Addressed

- Controls: DCF-18 Vulnerability Scans; DCF-160 Service Level Agreements (SLAs) for Security; DCF-456 Vulnerabilities Identified and Resolved
- Editor: Builder
- Description: No open high vulnerability is past its SLA date, and none has an undetermined SLA status.

Filtering criteria, Inclusion:

```json
{"all":[
  {"fact":"recordType","operator":"equal","value":"findingPartition"},
  {"fact":"severity","operator":"equal","value":"high"}
]}
```

Condition:

```json
{"all":[
  {"fact":"sourceFresh","operator":"equal","value":true},
  {"fact":"generatedAt","operator":"withinLastDays","value":2},
  {"fact":"openSlaBreachedCount","operator":"equal","value":0},
  {"fact":"openSlaUnknownCount","operator":"equal","value":0}
]}
```

### 4. Vipr Medium and Low Vulnerabilities Within SLA

- Controls: DCF-160 Service Level Agreements (SLAs) for Security; DCF-456 Vulnerabilities Identified and Resolved
- Editor: Advanced
- Description: No open medium or low vulnerability is past its SLA date, and none has an undetermined SLA status.

Filtering criteria, Inclusion:

```json
{"all":[
  {"fact":"recordType","operator":"equal","value":"findingPartition"},
  {"fact":"severity","operator":"in","value":["medium","low"]}
]}
```

Condition:

```json
{"all":[
  {"fact":"sourceFresh","operator":"equal","value":true},
  {"fact":"generatedAt","operator":"withinLastDays","value":2},
  {"fact":"openSlaBreachedCount","operator":"equal","value":0},
  {"fact":"openSlaUnknownCount","operator":"equal","value":0}
]}
```

### 5. Vipr Critical and High Vulnerabilities Are Ticketed

- Controls: DCF-18 Vulnerability Scans; DCF-315 Management of Security Vulnerabilities
- Editor: Advanced
- Description: Every open critical and high vulnerability has a ticket, so it is tracked to resolution.

Filtering criteria, Inclusion:

```json
{"all":[
  {"fact":"recordType","operator":"equal","value":"findingPartition"},
  {"fact":"severity","operator":"in","value":["critical","high"]}
]}
```

Condition:

```json
{"all":[
  {"fact":"sourceFresh","operator":"equal","value":true},
  {"fact":"generatedAt","operator":"withinLastDays","value":2},
  {"fact":"openMissingTicketCount","operator":"equal","value":0},
  {"fact":"openTicketUnknownCount","operator":"equal","value":0}
]}
```

### 6. Vipr Assets Seen Recently

- Controls: DCF-18 Vulnerability Scans
- Editor: Builder
- Description: Every asset in the Vipr inventory was seen within the stale window.
- Note: The stale window is SCAN_STALE_DAYS (default 7). Assets with no last-seen date are not counted.

Filtering criteria, Inclusion:

```json
{"all":[
  {"fact":"recordType","operator":"equal","value":"assetPartition"}
]}
```

Condition:

```json
{"all":[
  {"fact":"sourceFresh","operator":"equal","value":true},
  {"fact":"generatedAt","operator":"withinLastDays","value":2},
  {"fact":"staleAssetCount","operator":"equal","value":0}
]}
```

### 7. Vipr Critical and High Findings Within SLA (Item Level)

- Controls: DCF-18 Vulnerability Scans; DCF-160 Service Level Agreements (SLAs) for Security
- Editor: Advanced
- Description: No open critical or high finding is past its SLA date, checked finding by finding.

Filtering criteria, Inclusion:

```json
{"all":[
  {"fact":"recordType","operator":"equal","value":"findingPartition"},
  {"fact":"severity","operator":"in","value":["critical","high"]}
]}
```

Condition:

```json
{"all":[
  {"fact":"sourceFresh","operator":"equal","value":true},
  {"fact":"generatedAt","operator":"withinLastDays","value":2},
  {"fact":"findings","operator":"none","value":{"all":[
    {"fact":"open","operator":"equal","value":true},
    {"fact":"slaBreached","operator":"equal","value":true}
  ]}}
]}
```

### 8. Vipr Open Critical Findings Not Older Than 30 Days

- Controls: DCF-160 Service Level Agreements (SLAs) for Security; DCF-456 Vulnerabilities Identified and Resolved
- Editor: Advanced
- Description: No open critical finding was first seen more than 30 days ago.
- Note: The 30-day window is a placeholder; set the day count to the policy window.

Filtering criteria, Inclusion:

```json
{"all":[
  {"fact":"recordType","operator":"equal","value":"findingPartition"},
  {"fact":"severity","operator":"equal","value":"critical"}
]}
```

Condition:

```json
{"all":[
  {"fact":"sourceFresh","operator":"equal","value":true},
  {"fact":"generatedAt","operator":"withinLastDays","value":2},
  {"fact":"findings","operator":"none","value":{"all":[
    {"fact":"open","operator":"equal","value":true},
    {"fact":"firstSeen","operator":"olderThanDays","value":30}
  ]}}
]}
```
