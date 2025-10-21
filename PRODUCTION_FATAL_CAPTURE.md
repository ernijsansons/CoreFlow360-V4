# Breaking the Silence – Capturing the Real Production Error

The first recovery run did not expose the failing stack trace because the thrown value occurs **before** our `window.onerror` hook is registered and TanStack Router’s boundary swallows the exception. This document lays out the next iteration—moving the instrumentation earlier and forcing the boundary to show the payload—so we can finally see the root cause.

---

## Phase 1 – Move Fatal Reporting Ahead of Module Evaluation

React error boundaries only catch render-time errors; any synchronous exception during module evaluation (e.g., when importing `App` or a route module) happens **before** `frontend/src/main.tsx` runs. To catch those:

1. **Inline the Fatal Logger in `index.html`**
   - At the top of `<body>`, before the `<script type="module" src="/src/main.tsx"></script>`, inject a script that:
     - Defines a `surfaceFatal(label, detail)` function identical to the one we used in `main.tsx`.
     - Writes directly to the DOM (`document.body.prepend`) and fires `alert()` so the signal is visible even if the console is silent.
     - Assigns that function to `window.__CF360_FATAL__` so late hooks can reuse it.
2. **Register Early Handlers**
   - In the same inline script, wire `window.onerror` and `window.onunhandledrejection` **immediately** to call `surfaceFatal`. This ensures any exception thrown during ES-module evaluation (before `main.tsx` executes) is surfaced.
3. **Re-export for Later Code**
   - In `frontend/src/main.tsx`, replace the local `surfaceFatal` implementation with:
     ```ts
     const surfaceFatal =
       window.__CF360_FATAL__ ??
       ((label, detail) => console.error(`[CoreFlow360] ${label}:`, detail));
     ```
     so `main.tsx` and any later code reuse the same mechanism.

**Why this works:** ES modules evaluate imports top-to-bottom. The inline script executed from `index.html` runs before `/src/main.tsx` loads, guaranteeing the fatal logger exists before any React/Vite module executes.

---

## Phase 2 – Force the Router Boundary to Show the Payload

Even once we have early hooks, TanStack Router may still hand the boundary non-Error values. Update `frontend/src/routes/__root.tsx` so that:

1. `errorDetails` is derived using a helper that tries multiple strategies in order:
   ```ts
   const describeError = (value: unknown): string => {
     if (value instanceof Error) return `${value.name}: ${value.message}\n${value.stack ?? ''}`;
     if (typeof value === 'string') return value;
     try {
       return JSON.stringify(value, null, 2);
     } catch {
       return String(value);
     }
   };
   ```
2. Render both `errorDetails` and any nested `cause`, `data`, or `response` fields so nothing is hidden.
3. Skip the generic “An unexpected error occurred” fallback—display `describeError(error)` verbatim so the UI matches what actually arrived.

**Goal:** Even if the global hook misses something, the boundary’s `<details>` block will still show a meaningful payload.

---

## Phase 3 – Redeploy and Capture Evidence

1. `cd frontend && npm run build`
2. Deploy a preview or production build as before.
3. Load the broken URL in a fresh incognito session.
4. The inline script should fire immediately, showing an alert and inserting the red `<pre>` block at the top of the DOM. If the router boundary also renders, its `<details>` section will now display the same payload.
5. Copy the contents of the alert/DOM block into `fatal-dump-v2.txt`.
6. Record console output and Network tab activity for completeness.

---

## Phase 4 – Clean Up After Diagnosis

Once the stack trace is secured:

1. **Revert Temporary Instrumentation**
   - Remove the inline script from `index.html`.
   - Strip the shared `surfaceFatal` logic if no longer needed.
2. **Restore Router Boundary Messaging**
   - Keep any improved diagnostics that are production-safe, but remove loud alerts before final deployment.

---

## Quick Checklist

| Step | Description | Status (✓/✗) |
| ---- | ----------- | ------------- |
| 1a | Inline fatal logger added to `index.html` | |
| 1b | `window.onerror`/`unhandledrejection` wired immediately | |
| 1c | `main.tsx` reuses `window.__CF360_FATAL__` | |
| 2  | Router boundary prints `describeError(error)` | |
| 3  | Build, deploy, reproduce, capture `fatal-dump-v2.txt` | |
| 4  | Instrumentation removed post-diagnosis | |

Complete every row, capture the stack trace, and move on to implementing the permanent fix.
