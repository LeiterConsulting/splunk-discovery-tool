# Public App Readiness Remediation Issue Template

Use this template when converting a finding from `FINDINGS_REGISTER.md` into an implementation task.

## Summary

- Finding ID:
- Severity:
- Surface:
- Owner:

## User-Facing Problem

Describe what a public user sees, what is confusing or inaccessible, and why the issue matters.

## Current Behavior

- observed behavior:
- current UI label or control text:
- whether the issue is deterministic or state-dependent:

## Evidence

- live evidence:
- source evidence:
- supporting screenshots or DOM checks:

## Acceptance Criteria

1. The affected control or surface behaves correctly in the live app.
2. Semantic markup and accessible naming are correct where applicable.
3. Contrast meets the expected threshold for the affected text or control.
4. Public-facing labels are clear and non-ambiguous.
5. Regression evidence is recorded after the fix.

## Implementation Notes

- shared pattern affected:
- likely file(s):
- root cause category:
- related findings:

## Validation Plan

- manual verification steps:
- browser evidence to capture:
- code or test follow-up:

## Out of Scope

State what this issue will not fix so the implementation slice stays tight.