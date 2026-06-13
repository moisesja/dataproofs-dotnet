# Tracked dependency: NetCrypto BBS `header` parameter

**Status:** ✅ RESOLVED (2026-06-13) — fixed upstream in NetCrypto 1.0.0-preview.2 and applied here.
**Upstream issue:** [moisesja/crypto-dotnet#2](https://github.com/moisesja/crypto-dotnet/issues/2) (shipped in 1.0.0-preview.2)
**Affects:** `DataProofsDotnet.Rdfc` — `bbs-2023` cryptosuite (FR-12)
**Severity:** Critical (security guarantee — now enforced)
**Filed:** 2026-06-13 · **Resolved:** 2026-06-13

## Resolution

NetCrypto 1.0.0-preview.2 added the BBS `header` parameter to `IBbsCryptoProvider`
(`Sign`/`Verify`/`DeriveProof`/`VerifyProof`). `Bbs2023Cryptosuite` now binds
`bbsHeader = SHA-256(proofConfig) ‖ SHA-256(mandatory N-Quads)` at sign and derive, and
**recomputes it at verify from the revealed mandatory messages** (never from the holder-controlled
derived proofValue). A holder that drops or alters a mandatory statement changes the recomputed
header, so it no longer matches the one the proof commits to and verification fails — the
mandatory-disclosure guarantee is cryptographically enforced. Regression test:
`Verify_MandatoryStatementReclassifiedAsSelective_FailsClosed`. The original tracking content is
retained below for history.

---

## What

NetCrypto v1's `IBbsCryptoProvider` (`Sign`/`Verify`/`DeriveProof`/`VerifyProof`) does not expose
the BBS **`header`** parameter — it is hardcoded empty at the FFI boundary. The W3C `bbs-2023`
cryptosuite binds the **mandatory disclosure group** into that header
(`header = SHA-256(proofHash) ‖ SHA-256(mandatoryHash)`); without it, the mandatory group cannot
be cryptographically bound.

## Impact on this repo

`Bbs2023Cryptosuite` cannot enforce that a holder discloses the issuer-designated mandatory
statements. An adversarial review proved a **malicious holder can drop a mandatory claim and the
derived proof still verifies**. The create→derive→verify lifecycle is otherwise correct (BBS
proves the revealed messages were issuer-signed); the gap is specifically the mandatory-group
binding.

This is an upstream limitation, not a defect in this repository's logic: the binding must live in
the BBS `header`, which only NetCrypto can surface.

## Interim handling (until the upstream fix ships)

- `bbs-2023` remains registered and functional for the full create→derive→verify lifecycle.
- The limitation is documented on the `Bbs2023Cryptosuite` type (XML `<remarks>`), in
  [`SECURITY.md`](../../SECURITY.md), and in [`CHANGELOG.md`](../../CHANGELOG.md).
- The suite is treated as **experimental** for v1 (it is pinned to a Candidate Recommendation
  *draft*, per PRD §12.3).

## Resolution plan (when moisesja/crypto-dotnet#2 ships)

1. Bump the `NetCrypto` pin in `Directory.Packages.props` to the release exposing `header`.
2. In `Bbs2023Cryptosuite`, compute `bbsHeader = SHA-256(proofHash) ‖ SHA-256(mandatoryHash)` and
   pass it to `Sign` (base proof), `DeriveProof`, and `VerifyProof` — the conformant binding.
3. Remove the interim limitation notes and add an adversarial regression test that a derived proof
   dropping a mandatory statement **fails** verification.
4. Close this tracker.
