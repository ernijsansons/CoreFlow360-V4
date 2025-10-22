# Backend-to-UI Audit Overview

We have backend capabilities that never surfaced in the UI.  
This playbook walks through a structured audit to discover, prioritise, and integrate those gaps end-to-end.

## Audit Phases / Terminals

| Step | Terminal | Focus | File |
| --- | --- | --- | --- |
| 1 | Terminal X | Catalogue backend features | `docs/ui-backlog-audit/terminalX.md` |
| 2 | Terminal Y | Trace UI coverage & identify gaps | `docs/ui-backlog-audit/terminalY.md` |
| 3 | Terminal Z | Define integration work & acceptance tests | `docs/ui-backlog-audit/terminalZ.md` |

## General Notes

* Each file assumes repo root (`pwsh` shell).
* Use existing tooling (`apply_patch`, `rg`, `npm run`) to gather evidence.
* Document findings in markdown so PM/design can review.
* Audit is exploratory—record everything, do not delete backend features yet.

> Handoff: tell your assistant “Open `docs/ui-backlog-audit/terminalX.md` in Terminal X and follow the instructions.” Then proceed to Terminal Y and Terminal Z.

