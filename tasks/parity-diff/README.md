# parity-diff (AC-5)

Console tool enforcing **didcomm JWS/JWE behavior parity**: for every ported→source pair recorded
in `tests/DataProofsDotnet.Jose.Tests/Parity/PARITY.md`, it extracts the assertion statements from
both the ported file and its didcomm source (at the SHA recorded in PARITY.md), normalizes
identifiers per the recorded rename map, and fails on any difference in asserted literals or
structure.

```
dotnet run --project tasks/parity-diff/ParityDiff.csproj -c Release -- \
  [--parity-md <PARITY.md>] [--ported-root <dir>] [--didcomm-repo <dir>] [-v]
```

## What it does

1. **Parses PARITY.md** (`ParityManifest`): the source commit SHA, the file-map table
   (ported `.cs` → didcomm source path), the machine-readable `parity-rename-map` fenced block, and
   the "Intentionally omitted source tests" section (method names not ported).
2. **Reads the didcomm source** at the recorded SHA via `git show <sha>:tests/DidComm.Core.Tests/<path>`
   from the read-only didcomm clone (default `/Users/moises/Projects/didcomm-dotnet`, override with
   `--didcomm-repo`). The SHA's existence is verified before any read.
3. **Extracts assertions** (`AssertionExtractor`): splits each file into statements at `;` outside
   strings/comments/parens (curly depth is not a guard, so multi-line FluentAssertions chains stay
   intact), keeps statements containing `.Should()` or `Assert.`, and tags each with its enclosing
   test-method name.
4. **Normalizes** (`RenameNormalizer`): the recorded token renames are applied to the **source**
   side only (lifting didcomm identifiers up to the new public-API vocabulary; the ported side
   already uses it), longest-LHS-first. Two classes of assertion are set aside from the strict diff,
   exactly as PARITY.md sanctions:
   - **structural adaptations** — rename-map entries whose RHS is prose (e.g.
     `result.Message.Id -> JsonDocument payload property "id"`); the source assertion and its
     reshaped ported counterpart (reading `GetProperty("id")`) are recognized and excluded;
   - **omitted source tests** — assertions inside methods named in the "Intentionally omitted"
     section (the DIDComm-only FR-SIG-06 / FR-CONSIST-03 tests and the companion the table elides
     with `…_passes_when_present`).
5. **Diffs** the remaining assertions as a multiset (test reordering is an allowed modification;
   adding/removing/changing an assertion's literals or structure is not). Any mismatch fails.

## Exit codes

- `0` — zero assertion differences (parity holds)
- `1` — one or more assertion differences
- `2` — usage / environment error (PARITY.md missing, SHA not in the didcomm repo, etc.)

## Result against the current repo

ZERO assertion differences. 16 file pairs; 125 source / 125 ported strict assertions match; 2
sanctioned structural adaptations + 3 omitted-test assertions set aside. The detector was
verified non-vacuous (changing one ported expected literal produces a 2-line DIFF naming both the
absent source assertion and the unexpected ported one).

## CI note

In CI the didcomm source is provided at a pinned SHA (the same `e98570cd…` recorded in PARITY.md),
either as a sibling checkout or a vendored read-only clone; pass its path via `--didcomm-repo`. The
tool needs only `git show` against that clone and the checked-in ported files — no build of either
project. The matching half of AC-5 ("the parity suite passes") is the `Jose.Tests` Parity test run;
this tool is the assertion-equivalence half.
