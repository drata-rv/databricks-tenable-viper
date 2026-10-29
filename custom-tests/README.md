# Vipr custom tests

Paste-ready tests for the Vipr custom connection, built in the Drata UI. Control mapping is a suggestion; confirm the control names in your tenant.

## Create a test

1. Monitoring > Create test. Enter the name and description below.
2. Category Custom. Provider: the connection name. Resource: the resource name.
3. Evaluation threshold: All results must pass.
4. Filtering criteria > Add > Inclusion. Paste the filter into the Advanced editor.
5. Condition group > Advanced editor. Paste the condition. Tests marked Builder can also be entered field by field; Advanced tests need the Advanced editor.
6. Save the draft, run it, publish, then map it to the controls.

Each record is one result. A failing partition fails the test; records outside the filter are not scored.

## Facts

Records: S scanSummary, F findingPartition, A assetPartition.

| Fact | Type | Records | Description |
|---|---|---|---|
| `id` | string | SFA | Record id: vipr-summary, vipr-findings-{severity}-NNN, vipr-assets-NNN |
| `recordType` | string | SFA | scanSummary / findingPartition / assetPartition |
| `displayName` | string | SFA | Record name |
| `severity` | string | F | Vipr severity of the findings in this partition |
| `generatedAt` | string | SFA | Run time, UTC |
| `sourceAsOf` | string | SFA | Ingest time of the oldest source table |
| `sourceAgeDays` | number | SFA | Age of the oldest source table at run time, days |
| `sourceFresh` | boolean | SFA | Oldest source table within MAX_SOURCE_AGE_DAYS |
| `findingsSourceAsOf` | string | S | Ingest time of the findings table |
| `assetsSourceAsOf` | string | S | Ingest time of the assets table |
| `tenableSourceAsOf` | string | S | Ingest time of the Tenable assets table |
| `partition` | number | FA | Partition number, from 1 |
| `partitionCount` | number | FA | Partitions of this kind |
| `itemCount` | number | FA | Items in this record |
| `findingPartitionCount` | number | S | Finding partitions, all severities |
| `assetPartitionCount` | number | S | Asset partitions |
| `findingCount` | number | S | Findings submitted |
| `openFindingCount` | number | SF | Open findings |
| `openSlaBreachedCount` | number | SF | Open findings past SLA |
| `openSlaUnknownCount` | number | SF | Findings not known to be closed whose SLA status is undetermined |
| `openMissingTicketCount` | number | SF | Open findings without a ticket |
| `openTicketUnknownCount` | number | SF | Open findings with undetermined ticket state |
| `severityChangedCount` | number | S | Findings whose Vipr severity differs from the scanner |
| `closedFindingsExcludedCount` | number | S | Closed findings older than the lookback, not submitted |
| `rejectedCount` | number | S | Source rows rejected during transform |
| `assetCount` | number | S | Assets submitted |
| `inactiveAssetCount` | number | SA | Assets not marked active |
| `staleAssetCount` | number | SA | Assets not seen by Vipr within SCAN_STALE_DAYS |
| `tenableStaleAssetCount` | number | SA | Assets not scanned by Tenable within SCAN_STALE_DAYS |
| `tenableUnmatchedAssetCount` | number | SA | Assets with no or ambiguous Tenable match |
| `findings` | array | F | Finding items |
| `assets` | array | A | Asset items |

`findings[]` items (Advanced editor, nested rule):

| Fact | Type | Description |
|---|---|---|
| `id` | string | Vipr finding id |
| `displayId` | string | Display id |
| `viprSeverity` | string | Vipr severity: info / low / medium / high / critical |
| `scannerSeverity` | string | Scanner severity, same scale |
| `severityChanged` | boolean | Vipr severity differs from the scanner |
| `severityDirection` | string | downgraded / upgraded |
| `toolSeverities` | string | Raw per-tool ratings |
| `open` | boolean | Finding is open |
| `ignored` | boolean | Finding is ignored |
| `hasTicket` | boolean | Ticket linked |
| `missingTicket` | boolean | Open without a ticket |
| `slaDate` | string | SLA due date |
| `slaBreached` | boolean | Open past SLA |
| `closedAfterSla` | boolean | Closed after the SLA date |
| `firstSeen` | string | First seen |
| `closedAt` | string | Closed at |
| `assetId` | string | Asset id |
| `assetName` | string | Asset name |
| `cves` | array | CVE ids, capped |
| `cveCount` | number | CVE count before the cap |

`assets[]` items (Advanced editor, nested rule):

| Fact | Type | Description |
|---|---|---|
| `id` | string | Vipr asset id |
| `name` | string | Asset name |
| `assetType` | string | Asset type |
| `isActive` | boolean | Asset is active |
| `lastSeen` | string | Last seen by Vipr |
| `daysSinceSeen` | number | Days since last seen |
| `viprLastSeenStale` | boolean | Not seen within SCAN_STALE_DAYS |
| `openFindingsCount` | number | Open findings on the asset |
| `tenableMatch` | string | matched / none / ambiguous / not_configured / no_data |
| `tenableLastScan` | string | Last Tenable scan |
| `tenableDaysSinceScan` | number | Days since the last Tenable scan |
| `tenableScanStale` | boolean | Tenable scan older than SCAN_STALE_DAYS |
| `tenableLastAuthenticatedScan` | string | Last authenticated Tenable scan |

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
