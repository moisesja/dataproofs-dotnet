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

## 2026-06-22 — A side-channel fix must close every channel, not just the headline one (issue #12)

**Mistake:** Fixing the issue-#12 recipient-key enumeration *timing* oracle, I implemented the
constant-work (decoy ECDH) half and shipped it as "done" — but left the **exception
type/message** distinguishable (held key → AEAD-stage `MalformedJoseException`/"AEAD decryption
failed"; unheld key → unwrap-stage `JoseCryptoException`/"AES-KW unwrap failed"). The
adversarial review caught it: timing was equal, but a length-corrupted captured envelope still
enumerated possession through the exception channel.

**Why it happened:** I fixated on the issue *title* ("timing side-channel") and under-weighted
the issue's own "Recommended fix" list, whose **"Uniform failure"** bullet was as load-bearing
as the constant-work bullet. I treated the timing fix as the whole fix.

**The rule for myself:**
- For any information-disclosure / side-channel fix, enumerate **all** observable channels —
  **time, exception type, exception message, inner exception, status code, log lines, response
  shape** — and make held/unheld (or secret/non-secret) indistinguishable across **every** one.
  A constant-time fix with a leaky exception is not a fix.
- Read the issue's "recommended fix" as a checklist; implement **every** clause, not just the
  one matching the title.
- Always run the adversarial subagent on a security fix *before* declaring done — and when it
  finds a residual in the same threat class, treat it as in-scope, not a follow-up.
- Uniform-failure pattern: one exception type, one fixed message, no secret-derived detail
  (kid/stage), **no inner cause** (the inner can re-leak the stage). See
  `JweParser.DecryptFailureMessage`.
