# Provenance — RFC 9901 (SD-JWT) fixtures

- **Origin URL:** https://www.rfc-editor.org/rfc/rfc9901.txt
- **Document:** RFC 9901, "Selective Disclosure for JSON Web Tokens (SD-JWT)", D. Fett / K. Yasuda / B. Campbell, November 2025 (Standards Track)
- **Retrieval date:** 2026-06-12 (`curl` of the plain-text RFC from rfc-editor.org)
- **Local transformations:** manual extraction with line-unwrapping. The RFC hard-wraps long base64url strings and JSON examples to its line-length limit; values were reassembled by stripping line breaks and leading whitespace only. All base64url payloads are decode-verified (every JWT splits into 3 non-empty dot-separated parts whose header and payload decode to valid JSON; every Disclosure string decodes to a valid 2- or 3-element JSON array), every disclosure digest stated in the RFC was recomputed as base64url(SHA-256(ASCII(disclosure))) and matched, and each `sd_hash` was recomputed over the presented SD-JWT (up to and including the final `~`) and matched the KB-JWT payload. KB-JWT headers are not printed separately in the RFC; they were obtained by base64url-decoding the KB-JWT embedded in the presentation string (noted in the fixture). 345 automated checks across both fixture directories passed, 0 failures.

## Fixture count: 11 files

| File | Source section | Contents |
|---|---|---|
| `disclosure-format.json` | §4.2.1–4.2.4.2 | family_name "Möbius" object-property Disclosure (+3 equivalent alternative encodings) with stated digest; "FR" array-element Disclosure with stated digest; the payload fragments embedding both digests |
| `example1-user-claims.json` | §5.1 | Main worked example: input JWT Claims Set and the SD-JWT payload built from it |
| `example1-disclosures.json` | §5.1 | All 10 Disclosures (8 object properties + 2 nationalities array elements), each with `disclosure_b64`, `decoded` salt/name/value array, and `sha256_digest_b64url` |
| `example1-sd-jwt.json` | §5.1 | Issuer-signed JWT (ES256, `typ: example+sd-jwt`) and the complete SD-JWT compact serialization (`<jwt>~<10 disclosures>~`) |
| `kb-jwt.json` | §5.2 | SD-JWT+KB presentation (4 disclosures), KB-JWT compact/header/payload, `sd_hash`, and the Processed SD-JWT Payload |
| `section6-flat.json` | §6 / §6.1 | Flat SD-JWT: whole-address Disclosure, shared input claims set, payload |
| `section6-structured.json` | §6 / §6.2 | Structured SD-JWT: 4 address sub-claim Disclosures, plus the variant payload with `country` permanently disclosed |
| `section6-recursive.json` | §6 / §6.3 | Recursive Disclosures: 4 sub-claim Disclosures + the address Disclosure containing their digests in a nested `_sd` array |
| `appendix-a1-simple-structured.json` | Appendix A.1 | Simple Structured SD-JWT (non-ASCII values): input, payload, 10 Disclosures, 6 decoy digests, presentation (region+country, no KB-JWT), processed payload |
| `appendix-a2-complex-structured.json` | Appendix A.2 | Complex Structured SD-JWT (OIDC-IDA `verified_claims`, recursive array-element Disclosure for `evidence`): input, payload, 16 Disclosures, presentation (6 disclosures, no KB-JWT), processed payload |
| `appendix-a5-issuer-public-key.json` | Appendix A.5 | The P-256 public JWK that validates the Issuer signatures of all RFC 9901 examples |

## Not vendored (and why)

- **§4.2.6 recursive nationalities example:** the spec abbreviates the digests/Disclosures (`PmnlrRj... = ["16_mAd0GiwaZokU26_0i0h","DE"]`) and never prints the full base64url Disclosure strings, so exact fixtures cannot be extracted. Recursive-disclosure coverage comes from §6.3, Appendix A.2 and the sd-jwt-vc-16 Appendix B.1 fixtures instead.
- **Appendix A.3 (SD-JWT VC) and A.4 (W3C VCDM 2.0):** A.3 duplicates the SD-JWT VC material vendored from draft-ietf-oauth-sd-jwt-vc-16 (see `../sd-jwt-vc-16/`); A.4 is a large W3C VCDM illustration outside the current SD-JWT test scope. Both are non-normative illustrations.
- **Section 8 (JWS JSON serialization):** the RFC defines the format but its examples are not complete worked vectors with stated digests; compact-serialization coverage above exercises the same Disclosure/digest pipeline.
