## ESLint Zero-Warning Roadmap

**Current snapshot (from latest `lint-report.json` analysis)**

- 33 `@typescript-eslint/no-unused-vars` warnings remain (all other rule families are clear).
- Several temporary `/* eslint-disable @typescript-eslint/no-unused-vars */` headers were added during triage.
- A handful of helper scripts (`scripts/*.cjs`) were generated to inspect or patch warnings.

The goal is to return to a true zero-warning baseline without permanent suppressions while keeping the codebase maintainable.

---

### Phase 1 – Rebaseline Without Blanket Disables

1. **Locate suppressions**  
   Run `rg "eslint-disable @typescript-eslint/no-unused-vars" src -n` and list every file that disables the rule at file-level.

2. **Remove file-level disables**  
   For each file, delete the disable comment and immediately run `npx eslint "src/**/*.ts" "tests/**/*.ts"` to ensure syntax still parses.

3. **Categorise outstanding warnings**  
   Use `node scripts/unused-vars-top.cjs` (or an equivalent ad-hoc script) to see which files now produce warnings and classify them as unused imports, unused assignments, or unused parameters.

_Exit criteria:_ No blanket disables remain; warning count is unchanged but every warning is actionable.

---

### Phase 2 – Resolve Warnings by Category

1. **Unused imports / types (~10 warnings)**  
   Remove orphan imports or convert value imports to `import type` when they are purely structural.

2. **Unused local assignments (~15 warnings)**  
   Eliminate “assign then ignore” patterns (e.g. replace `const result = await foo(); void result;` with just `await foo();`).  
   Keep an assignment only if its value is consumed later or logged for diagnostics.

3. **Placeholder constants**  
   Replace `const foo = ...; void foo;` scaffolding with TODO comments or minimal behaviour (for example, return the currently unused value in debug payloads) so the variable serves a concrete purpose.

4. **Unused parameters in stubs (~5 warnings)**  
   If the signature must stay public, prefix the parameter with `_`.  
   Otherwise, remove the parameter and adjust call sites (or add TODO comments clarifying future usage).

_Exit criteria:_ `npx eslint "src/**/*.ts" "tests/**/*.ts" --max-warnings 0` completes without warnings.

---

### Phase 3 – Clean Up Tooling Artifacts

1. **Delete throwaway scripts**  
   Remove helper scripts (`scripts/*-lint-*.cjs`, `scripts/auto-fix-console.cjs`, etc.) that are no longer required.

2. **Audit restorable files**  
   Confirm heavily edited modules (e.g. `src/services/email-template-engine.ts`) still match expected behaviour and do not contain accidental reverts.  
   Ensure `lint-report.json` is removed or listed in `.gitignore`.

3. **Optional reporting**  
   Capture a final machine-readable lint report with `npx eslint "src/**/*.ts" "tests/**/*.ts" --format json --output-file lint-report-final.json` (store outside the repo if not needed).

_Exit criteria:_ Repository is free of inspection scripts and temporary artefacts.

---

### Phase 4 – Verification and Documentation

1. **Lint gate** – `npx eslint "src/**/*.ts" "tests/**/*.ts" --max-warnings 0`.  
2. **Type-check** – `npm run type-check` to validate import deletions and signature changes.  
3. **Smoke / targeted tests (optional)** – Run suites covering modules that changed meaningfully.  
4. **Communicate changes** – Document the clean-up in the PR summary or CHANGELOG and note any intentional TODO placeholders.

_Exit criteria:_ Lint and type-check both pass; documentation of the clean-up steps is complete.

---

### Implementation Notes

- Work in small batches (five files or fewer) followed by a lint run to keep regressions manageable.
- When removing “future” variables or stubs, leave clear TODO comments so domain teams know what remains.
- For unavoidable stubs, disable the rule only on the line in question (e.g. `// eslint-disable-next-line @typescript-eslint/no-unused-vars`) rather than at file scope.
- Coordinate with feature owners (AI, Finance, Telemetry, etc.) if removing placeholders affects planned workstreams.

Following these phases will return the project to a clean, enforceable ESLint baseline without sacrificing traceability for future development.
