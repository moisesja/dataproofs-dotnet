# Provenance — RFC 7520 (JOSE Cookbook) fixtures

- **Origin URL:** https://github.com/ietf-jose/cookbook (machine-readable JSON of the RFC 7520 examples, maintained by the IETF JOSE WG editors)
- **Git commit SHA:** `13692b68bfc18b99557a5b1ed311fd5077bfff04` (commit date 2016-11-12)
- **Underlying document:** RFC 7520, "Examples of Protecting Content Using JSON Object Signing and Encryption (JOSE)", May 2015
- **Retrieval date:** 2026-06-11 (shallow `git clone` of the repository at the SHA above)
- **Local transformations:**
  - Files under `jws/` and `jwe/` are **byte-identical copies** of the repository files (same relative paths and names). No content was modified.
  - The two files under `curve25519/` are byte-identical copies of the repository's `curve25519/jws.json` and `curve25519/ecdh-es.json`, **renamed** to `eddsa_ed25519_jws.json` and `ecdh-es_x25519.json` for self-description. Note: these two are repository extras illustrating draft-ietf-jose-cfrg-curves (published as RFC 8037), not examples that appear in RFC 7520 itself; they are vendored here because they live in the cookbook repository and cover the EdDSA-adjacent algorithms (Ed25519 JWS, X25519 ECDH-ES).

## Fixture count: 10 files

| File | Algorithms | SHA-256 of vendored copy |
|---|---|---|
| `jws/4_3.ecdsa_signature.json` | ES512 (P-521) — the cookbook's only pure-ECDSA JWS example | `22626cf81d7b3c25e6a22108af1ccc6c51ee4d7f5822ccce6c55b47d36e5c819` |
| `jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json` | ECDH-ES+A128KW / A128GCM | `7d41160d7168c4696255db7dfba2f6652ada15d4466519a30422e8773c0f212f` |
| `jwe/5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json` | ECDH-ES / A128CBC-HS256 | `18702a20ddc4510a1cee0ed3a8e97c8f85e9357e696f4acbf16c8f4334904785` |
| `jwe/5_6.direct_encryption_using_aes-gcm.json` | dir / A128GCM | `6a2a527e4b2c0f84d53cf0f3782aa4b33a43e2faa371b8e691a1f3a9e6a63e34` |
| `jwe/5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json` | A128KW / A128GCM | `e0da5b710dc697984cb7aa93c8bad6fe97db74b6507af087a4ceae8bf70d13e4` |
| `jwe/5_10.including_additional_authentication_data.json` | A128KW / A128GCM (JWE AAD) | `4a294adec448e697c16640eef781f66f1dfc1e0eb495aaf88566fcfc14094ff9` |
| `jwe/5_11.protecting_specific_header_fields.json` | A128KW / A128GCM (split protected/unprotected headers) | `2fd1f245c429ee9e891d44eeef7a8c4f921d5762faf7e87446966ed0682d7d2e` |
| `jwe/5_12.protecting_content_only.json` | A128KW / A128GCM (no protected header) | `1ec7c0db6e374767b85f7606f3bff90362aef1b64c4f4f9f4ae6b816fa181cd8` |
| `curve25519/eddsa_ed25519_jws.json` | EdDSA (Ed25519) | `5c07444361c66c8ea212d8316cf78f1bf370ec8df62b95e2acb2c53f5d74be94` |
| `curve25519/ecdh-es_x25519.json` | ECDH-ES (X25519) / A128GCM | `45dcbc498e0207dbcfa6b4d2bd173db9a42982989b5e9d29316cb86769a416e1` |

Each file is self-contained: `input` carries the payload/plaintext and full key material (JWK, private part included), intermediate values (`signing`/`generated`/`encrypting_key`/`encrypting_content`) are included, and `output` carries `compact`, `json` (general JWE/JWS JSON serialization), and `json_flat` forms.

RFC 7520 carries no exact A256GCM / A256CBC-HS512 / A256KW vectors outside the RSA examples; the cookbook's AES-family coverage at the 128-bit sizes above exercises the same code paths (AES-GCM content encryption, AES-CBC-HMAC-SHA2 content encryption, AES Key Wrap, ECDH-ES direct and +KW). 256-bit-parameter coverage comes from the RFC 8037 / RFC 7518 / ECDH-1PU fixture directories and the oracle cross-verification of AC-3.

## Files deliberately NOT vendored (and why)

- **RSA examples (skipped per AC-3 scope, which excludes RSA):** `jws/4_1.rsa_v15_signature.json` (RS256), `jws/4_2.rsa-pss_signature.json` (PS384), `jwe/5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2.json` (RSA1_5), `jwe/5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json` (RSA-OAEP), `6.nesting_signatures_and_encryption.json` (PS256 + RSA-OAEP), `jwk/3_3.rsa_public_key.json`, `jwk/3_4.rsa_private_key.json`.
- **PBES example (skipped per AC-3 scope):** `jwe/5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json` (PBES2-HS512+A256KW).
- `jws/4_4` – `jws/4_7`: HS256 (HMAC) examples — HS* is outside the targeted algorithm set (ES256/ES384/EdDSA-adjacent, A256GCM, A256CBC-HS512, A256KW, ECDH-ES).
- `jws/4_8.multiple_signatures.json`: mixes RS256 and HS256 with ES512; cannot be consumed without RSA support.
- `jwe/5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json`: A256GCMKW (AES-GCM key wrap), a distinct algorithm from A256KW and outside the targeted set.
- `jwe/5_9.compressed_content.json`: exercises JWE `zip: DEF` compression, not a targeted algorithm feature.
- `jwe/5_13.encrypting_to_multiple_recipients.json`: one of its three recipients uses RSA1_5 (skipped per AC-3 RSA exclusion). Multi-recipient JWE coverage is instead provided by `tests/fixtures/ietf/ecdh-1pu-04/appendix-b-complete-jwe.json`. (Note: this cookbook file also contains a known typo, `"enc":"A128CBC-H256"`, in an intermediate value.)
- `jwk/3_1`, `jwk/3_2`, `jwk/3_5`, `jwk/3_6`: the key material of every vendored example is already embedded in the example file itself (`input.key`), so the standalone JWK files are redundant.
- `rfc7797/`: RFC 7797 `b64=false` examples (HS256), out of scope.
