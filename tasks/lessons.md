# Lessons

Self-improvement log (AGENTS.md §3). After any user correction, record the pattern and a
rule that prevents recurrence.

## 2026-06-16 — Always get plan approval before implementing (issue #10)

**Mistake:** On a non-trivial task (issue #10 fix + v1.0.1 bump), I went straight from
research into editing source/tests/version files without presenting a plan for approval.
The user stopped me mid-edit and was rightly angry.

**Why it happened:** I let AGENTS.md §6 ("Autonomous Bug Fixing — just fix it, don't ask
for hand-holding") override §1 ("Plan Mode Fault — enter plan mode for ANY non-trivial
task") and the Task Management rule "Verify Plan: Check in before starting implementation."

**The rule for myself:**
- §6 means *don't ask how to fix it / don't need babysitting on mechanics*. It does NOT
  override §1. Plan approval is still required for non-trivial work.
- A task is non-trivial (→ plan + explicit approval BEFORE any edit) when it is 3+ steps,
  touches multiple files, changes a public API or version, or **reverses a prior decision**
  (especially a security one). Issue #10 was all of these.
- The sequence is: research read-only → present plan → WAIT for "yes" → implement.
  Creating a branch, a todo file, or any source/test edit all count as "implement."
- When two instructions appear to conflict, the more conservative/process-protective one
  wins unless the user has said otherwise in this session.
