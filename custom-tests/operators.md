Operator names are exact: `equal` and `exist`, never `equals` or `exists`. Booleans and numbers are JSON values, not strings.

Date strings stay plain strings, so they offer the string operators and the date operators. Day operators use UTC calendar days: `withinLastDays` includes today and the day N days ago; `olderThanDays` is strictly older. `isBefore` and `isAfter` compare instants. A null or unparseable date is expected to fail every date operator.

Nullable fields (`string` or `null`) offer the same operators as their base type plus a null comparison. `equal true` and `equal false` both fail on null.

Array items are reachable only in the Advanced editor, through `all`, `any`, `none` or `notAll` with a nested rule whose facts are item properties. `all` and `none` pass on an empty array; `any` and `notAll` fail. Use `{"fact":"findings","path":"length","operator":"greaterThan","value":0}` to require items.

Limits: 7 conditions and 70 lines per code block; conditions inside a nested array rule are not counted.
