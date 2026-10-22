# Peer Review Checklist (internal, v3.0)

## ECU-REV-01 Before the review
Confirm the change compiles without new warnings at the project warning level, unit tests pass, and the
static analysis report has no new required-rule violations. Link the change to its requirement and to the
change request.

## ECU-REV-02 Review focus areas
Check pointer validation on all external interfaces, bounds of every buffer copy, initialisation of
locals, handling of every switch value, error propagation of return codes, and shared data accessed from
interrupts. For diagnostics and communication code, also check the secure coding guideline.

## ECU-REV-03 Disposition of findings
Each finding is accepted (true defect, to be fixed), rejected (false positive, with a reason), or marked
fixed (with the commit reference). Rejected findings are remembered so the same evidence is not reported
again. Only accepted findings are exported to the defect tracking workflow.

## ECU-REV-04 Build log triage
Group compiler warnings by root cause before fixing them; many warnings usually share one cause, such as a
missing include or a wrong type in a shared header. Fix errors first, then warnings that indicate undefined
behaviour (uninitialised, bounds, overflow), then style warnings.
