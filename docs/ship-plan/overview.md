# Ship Plan Overview

This bundle documents the remaining 5 % of the weekly plan.  
Each file is meant to be handed off to Claude-Code (or another coding agent).  
Open the files in order and treat each one as a runbook for a dedicated terminal.

## File Map

| Sequence | Terminal | Purpose | File |
| --- | --- | --- | --- |
| 1 | Terminal 1 | Finish compliance admin API hardening + tests | `docs/ship-plan/terminal1.md` |
| 2 | Terminal 2 | Full repo verification (tests, lint, typechecks) | `docs/ship-plan/terminal2.md` |
| 3 | Terminal 3 | Release prep, docs + communication | `docs/ship-plan/terminal3.md` |

## General Expectations

* Start from repo root unless otherwise specified.  
* All shell directions assume Windows PowerShell (`pwsh`) in this workspace.  
* Commands use `npx vitest` / `npm run` and should respect existing lockfiles.  
* When editing, prefer `apply_patch` (Codex CLI helper) so diffs stay focused.
* Keep an eye on `git status` after every major operation; abort on dirty surprises.

> **Hand-off**: Tell your assistant “Open `docs/ship-plan/terminal1.md` in Terminal 1 and follow it.”  
Once complete, do the same for Terminal 2 and Terminal 3 in sequence.

