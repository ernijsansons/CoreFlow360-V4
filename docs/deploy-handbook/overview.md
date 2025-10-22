# Deployment Handbook Overview

Use this playbook after engineering sign‑off to ship the build into the live environment.  
Each markdown file is a runbook for a single terminal. Execute them sequentially.

## File Map

| Step | Terminal | Purpose | File |
| --- | --- | --- | --- |
| 1 | Terminal A | Pre-deploy validation & artifact prep | `docs/deploy-handbook/terminalA.md` |
| 2 | Terminal B | Staging deployment & smoke checks | `docs/deploy-handbook/terminalB.md` |
| 3 | Terminal C | Production deployment & post checks | `docs/deploy-handbook/terminalC.md` |

## General Guidance

* Commands assume repo root and PowerShell (`pwsh`) unless noted.
* Use `apply_patch` or editor when instructed to edit files.
* Stop immediately and escalate if any step fails unexpectedly.
* Keep terminal logs for post‑deployment audit.

> **Hand-off**: Tell Claude-Code “Open `docs/deploy-handbook/terminalA.md` in Terminal A and follow it,” then proceed to Terminal B and Terminal C.

