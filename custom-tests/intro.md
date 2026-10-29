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
