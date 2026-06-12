# Provenance: RFC 8392 Appendix A — CWT examples

- **Origin URL:** https://www.rfc-editor.org/rfc/rfc8392.txt
- **Document version:** RFC 8392, "CBOR Web Token (CWT)", May 2018, Standards
  Track (RFCs are immutable; no errata affect Appendix A as of retrieval)
- **Retrieved:** 2026-06-11
- **Consumed by:** AC-4 (PRD §9) — CWT claims validation against the Appendix A
  claim sets including expiry handling

## File naming

Each Appendix A artifact is extracted into two machine-readable files:

- `<name>.hex.txt` — the CBOR encoding as a single line of lowercase hex
  (no whitespace), exactly the bytes given in the RFC's "as Hex String" figure.
- `<name>.diag.txt` — the extended CBOR diagnostic notation from the matching
  "in CBOR Diagnostic Notation" figure, verbatim (including the RFC's `/ … /`
  comments and `<< … >>` embedded-CBOR notation).

| Appendix | Figures | Files | Content |
|---|---|---|---|
| A.1 | 2, 3 | `a1-claims-set.*` | CWT Claims Set (80 bytes; iss/sub/aud/exp/nbf/iat/cti) |
| A.2.1 | 4, 5 | `a2_1-key-symmetric-128.*` | 128-bit symmetric COSE_Key (AES-CCM-16-64-128) |
| A.2.2 | 6, 7 | `a2_2-key-symmetric-256.*` | 256-bit symmetric COSE_Key (HMAC 256/64) |
| A.2.3 | 8, 9 | `a2_3-key-ecdsa-p256.*` | ECDSA P-256 COSE_Key (private + public parts) |
| A.3 | 10, 11 | `a3-signed-cwt.*` | Signed CWT (tag 18 COSE_Sign1, ES256) |
| A.4 | 12, 13 | `a4-maced-cwt.*` | MACed CWT with CWT tag (tag 61 + tag 17 COSE_Mac0, HMAC 256/64) |
| A.5 | 14, 15 | `a5-encrypted-cwt.*` | Encrypted CWT (tag 16 COSE_Encrypt0, AES-CCM-16-64-128) |
| A.6 | 16, 17 | `a6-nested-cwt.*` | Nested CWT: A.3 signed CWT encrypted with the A.2.1 key |
| A.7 | 18, 19 | `a7-maced-cwt-float.*` | MACed CWT with floating-point `iat` (tag 17 COSE_Mac0) |

## Local transformations

1. **Hex blobs:** the RFC wraps hex strings across lines for display ("Line
   breaks are for display purposes only"). Wrapped lines were joined into one
   continuous lowercase hex string per file (programmatic extraction from the
   plain-text RFC; no characters altered).
2. **Diagnostic notation:** copied verbatim from the RFC figures with (a) page
   headers/footers and form feeds removed where a figure crossed a page break,
   and (b) the RFC's uniform 3-space body indent stripped. Line breaks inside
   `h'…'` literals are the RFC's own display wrapping and were retained as
   printed; consumers should strip whitespace inside hex literals when parsing.
3. No other edits. Figure captions and surrounding prose are not included.

## Extraction verification (performed at vendoring time, 2026-06-11)

- Every `.hex.txt` blob parses as a single well-formed CBOR item whose encoding
  consumes exactly the stated byte count.
- The A.1 claims-set bytes appear verbatim as the payload byte string inside
  the A.3 and A.4 CWTs.
- A.3: the ES256 signature **cryptographically verifies** over the COSE
  `Sig_structure` using the A.2.3 public key, and the A.2.3 private scalar
  regenerates that public point.
- A.4 and A.7: the HMAC-SHA-256 tags (truncated to 64 bits) **recompute
  exactly** with the A.2.2 key over the COSE `MAC_structure`.
- A.5 and A.6: AES-CCM-16-64-128 decryption with the A.2.1 key and the stated
  13-byte nonces succeeds; A.5 plaintext equals the A.1 claims set and A.6
  plaintext equals the A.3 signed CWT, as the RFC specifies.

## Fixture counts (for count assertions)

- Total files: **18** (9 `.hex.txt` + 9 `.diag.txt`)
- Claims sets: **1** (A.1) · Keys: **3** (A.2.1–A.2.3) · CWT messages: **5**
  (A.3–A.7: signed, MACed, encrypted, nested, MACed-float)
