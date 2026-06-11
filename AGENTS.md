# Agent & Contributor Instructions

This file provides instructions for AI agents and human contributors working in this codebase.

## Project Overview

`DataProofsDotnet` secures a document with a proof. It is the single home for both proof families defined by the W3C and IETF securing-mechanism landscape:

- **Embedded proofs** — W3C Data Integrity: a `proof` block carried inside a JSON-LD document, produced by the transform → canonicalize → hash → sign → encode pipeline, including proof sets and proof chains.
- **Enveloping proofs** — JOSE, COSE, and SD-JWT: the document is wrapped in a signed and/or encrypted container (JWS, JWE, COSE_Sign1, SD-JWT), including the VC-JOSE-COSE binding for carrying VCDM 2.0 payloads.

## Requirements and Design

For the overall vision use [`dataproofs-concept.md`](dataproofs-concept.md) as the goal to achieve. See [`dataproofs-prd.md`](dataproofs-prd.md) for requirements and instructions on how to build the system. This document must be maintained as it will be the main source of truth for functionality details.

## Workflow Orchestration

### 1. Plan Mode Fault

- Enter plan mode for ANY non-trivial task defined as a task that takes 3 steps or more or that requires architectural decisions.
- If something goes sideways, STOP and re-plan immediately - don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy

- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- Always use adversarial agents to attempt to exploit the code that is being generated. The adversarial agents must report in detail about any findings
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 2a. Workflow Orchestration (Multi-Agent)

- **Opt-in only**: launch a Workflow ONLY when the user explicitly asks (says
  "workflow", "fan out", "orchestrate with subagents") or runs a skill that
  calls it. Otherwise use a single subagent, or describe the workflow and its
  rough token cost and let the user decide. Never auto-launch — workflows can
  spawn dozens of agents and consume a large token budget.
- **High-value workflows in this repo**:
  - _Security review_ — fan out review dimensions (chain validation, caveat
    inheritance, attenuation, replay/nonce, revocation), then spawn N skeptics
    per finding to refute it; keep only findings that survive a majority vote.
  - _Spec-compliance sweep_ — one agent per normative requirement cluster →
    verify implementation + `tests/Compliance/` coverage → completeness critic
    flags untested MUST/SHOULD.
  - _Cross-package migration_ — discover call sites across Core / AspNetCore /
    examples / tests → transform each in worktree isolation → verify it builds.
  - _Test-gap analysis_ — multi-modal sweep by requirement, public API surface,
    and error path.
- **Default to `pipeline()` over barriers**: verify each finding as its review
  lands; only use a barrier when a stage genuinely needs all prior results
  (e.g. dedup before expensive verification).
- **Always adversarially verify security findings** — a plausible-but-wrong
  auth-bypass claim is worse than none.

### 3. Self-Improvement Loop

- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done

- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this?"
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)

- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes - don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing

- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests - then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

# Task Management

1. **Plan First**: Write plan to `tasks/todo{timestamp}.md` with checkable items
2. **Verify Plan**: Check in before starting implementation
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Document Results**: Add a review section to 'tasks/todo{timestamp}.md'
6. **Capture Lessons**: Update 'tasks/lessons.md' after corrections
7. **Update Documents and Examples**: Always keep any relevant documentation and examples current with your code changes

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Staff Engineer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.
