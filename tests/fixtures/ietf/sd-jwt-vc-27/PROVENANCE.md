# Provenance — draft-ietf-oauth-sd-jwt-vc-27 (SD-JWT VC) fixtures

- **Origin URL:** https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-27.txt
- **Document:** draft-ietf-oauth-sd-jwt-vc-27, "SD-JWT-based Verifiable Digital Credentials (SD-JWT VC)", O. Terbu / D. Fett / B. Campbell, 16 November 2026 (Internet-Draft, expires 20 May 2027; Intended status: Standards Track; Updates: 7800 (if approved))
- **Retrieval date:** 2026-11-19 (plain-text Internet-Draft from ietf.org)
- **Replaces:** the `sd-jwt-vc-16` fixtures, moved here with `git mv` so the diff shows each value -27 changed (issue #49). **Next re-pin** (the RFC): follow PRD §12.2.
- **Local transformations:** scripted extraction with line-unwrapping. Long base64url strings and JSON examples are hard-wrapped in the draft and some span page breaks; page footers/headers and form feeds were removed and values reassembled by stripping line breaks and leading whitespace only. Outside JSON strings a line break is JSON whitespace and was left as is (in -27 many Type Metadata members are wrapped between the member name and its value). The only JSON strings broken mid-string are in the `portrait` data URI of Figure 23 (5 joins), rejoined the same way. Figure 16 is an excerpt: its `...` line and the comma before it were dropped. Every base64url payload is decode-verified: every JWT splits into 3 non-empty dot-separated parts whose header and payload decode to valid JSON objects, and every Disclosure string decodes to a valid 2- or 3-element JSON array. Every disclosure digest stated in the draft was recomputed as base64url(SHA-256(ASCII(disclosure))) and matched, and each `sd_hash` was recomputed over the presented SD-JWT (up to and including the final `~` before the KB-JWT) and matched the KB-JWT payload. Where the draft does not print the KB-JWT header/payload separately (Figure 8), they were obtained by base64url-decoding the KB-JWT embedded in the presentation string (noted in the fixture). The Appendix A.1 KB-JWT header is likewise decoded from Figure 26; its payload is the literal Figure 27.

## Checks: 742 automated checks, 742 passed, 0 failed

| Check | Count |
|---|---|
| JWT structure (3 non-empty parts; header/payload decode to JSON objects; signature decodes) | 7 |
| Disclosure structure (decodes to a 2- or 3-element JSON array), in compact forms and listings | 81 |
| Stated disclosure digest recomputes as base64url(SHA-256(ASCII(disclosure))) | 37 |
| Stated digest appears in the SD-JWT payload or a parent Disclosure | 37 |
| Every Disclosure in a compact form is referenced by a digest | 44 |
| Every `_sd` digest resolves to a Disclosure (issuance examples) | 2 |
| `claim_name` equals the decoded Disclosure claim name | 37 |
| `sd_hash` recomputes over the presented SD-JWT and matches the KB-JWT payload | 2 |
| KB-JWT header is `alg: ES256`, `typ: kb+jwt` | 2 |
| Stored decoded header/payload/Disclosure/compact element equals the decoded compact form | 52 |
| Processed payload recomputed by SD-JWT processing equals the stored figure (Figs. 9, 11, 28) | 3 |
| Unsecured payload (Figs. 5, 23) equals the fully processed issued SD-JWT, which adds only `iss`/`iat`/`exp`/`cnf` (§2.3.1) or `iat`/`exp`/`cnf` (A.1) | 4 |
| Presentations reuse the issued issuer-signed JWT; presented Disclosures are a subset of the issued ones | 4 |
| Issuer-signed JWT ES256 signature verifies against the RFC 9901 Appendix A.5 issuer key (`../rfc9901/appendix-a5-issuer-public-key.json`) | 5 |
| KB-JWT ES256 signature verifies against the `cnf.jwk` of its SD-JWT payload | 2 |
| Negative control: a signature with one bit flipped is rejected | 7 |
| Every stored JSON figure re-serializes (whitespace-insensitive) to a substring of the draft text; every compact form and Hash/Disclosure pair occurs verbatim | 55 |
| Every stored string value occurs in the draft text (whitespace-insensitive) | 331 |
| `registered-claims.json` entries and the "including any of their subclaims" wording occur in §2.2.2.3 | 11 |
| `#integrity` values are `sha256-` + standard base64 of 32 bytes | 10 |
| Miscellaneous (counts of Disclosures, `vct` of Fig. 16 equals Fig. 29, Fig. 10 has no `cnf`, trailing `~`) | 9 |

Signature verification used a self-contained P-256 ECDSA verifier written against the Python standard library, because the Python `cryptography` package was not importable (`python3 -I`, `ModuleNotFoundError`); nothing was installed. The same checker, run over the -16 fixture set, also accepts every -16 signature with the same issuer key.

Additional observation (not counted): the `vct#integrity` in Figure 16 recomputes exactly as SHA-256 over the Figure 17 document bytes as printed (draft indent removed, LF line ends, trailing LF). The `vct#integrity` in Figure 29 does not recompute from Figure 30 as printed; the draft does not give the exact bytes of that document.

## Fixture count: 12 files

| File | Source section | Contents |
|---|---|---|
| `vct-unsecured-payload.json` | §2.2.2.1, Fig. 3 | Example Unsecured Payload with the `vct` claim identifying `https://credentials.example.com/identity_credential` |
| `example-unsecured-payload.json` | §2.3.1, Fig. 5 | User data comprising the Unsecured Payload of the main SD-JWT VC example |
| `example-sd-jwt-payload.json` | §2.3.1, Fig. 6 | SD-JWT payload of the main example (9 `_sd` digests, `iss`/`iat`/`exp`/`vct`, `_sd_alg`, `cnf`) |
| `example-disclosures.json` | §2.3.1 | All 9 Disclosures, each with `disclosure_b64`, `decoded`, `sha256_digest_b64url` |
| `example-sd-jwt-vc.json` | §2.3.1, Fig. 7 | The issued SD-JWT VC compact serialization (`typ: dc+sd-jwt`, `kid: doc-signer-05-25-2022`), plus the issuer-signed JWT (its first tilde-separated element) and decoded header |
| `example-presentation-kb-jwt.json` | §2.3.2, Figs. 8–9 | SD-JWT+KB presentation disclosing `address` and `is_over_65`; KB-JWT compact/header/payload (decoded from the presentation), `sd_hash`; processed SD-JWT payload |
| `example-presentation-no-kb.json` | §2.3.2, Figs. 10–11 | Presentation of a similar SD-JWT without `cnf`/KB-JWT, and its processed payload |
| `registered-claims.json` | §2.2.2.3 | Registered JWT claim rules: claims that, including any of their subclaims, MUST NOT be selectively disclosed (`iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `aka_vcts`, `status`) vs. claims that MAY be (`sub`, `iat`), with requirement levels |
| `type-metadata-example.json` | §5.1, Figs. 16–17 | `vct` + `vct#integrity` payload excerpt and the Type Metadata document retrieved from the vct URL (with `extends` + `extends#integrity`) |
| `appendix-a1-pid-issuance.json` | App. A.1, Figs. 23–25 | PID credential issuance: citizen input data (incl. PNG-portrait data URI, non-ASCII values), issued SD-JWT (28 disclosures), SD-JWT payload, and all 28 Disclosures (recursive for `address`, `place_of_birth`, `age_equal_or_over`) |
| `appendix-a1-pid-presentation.json` | App. A.1, Figs. 26–28 | PID SD-JWT+KB presentation (nationalities + `age_equal_or_over.18` via recursive Disclosures), KB-JWT payload (literal Figure 27) and header, processed payload |
| `appendix-a2-type-metadata.json` | App. A.2, Figs. 29–30 | Education-credential SD-JWT VC payload and the complete Type Metadata document (display metadata with `simple`/`svg_templates` renderings and locales; claim metadata with paths incl. `null` array selectors, `sd`, `mandatory`, `svg_id`) |

## Changes from the -16 fixtures

File renames: `appendix-b1-pid-issuance.json` → `appendix-a1-pid-issuance.json`, `appendix-b1-pid-presentation.json` → `appendix-a1-pid-presentation.json`, `appendix-b2-type-metadata.json` → `appendix-a2-type-metadata.json` (Appendix B became Appendix A). In every file `source_section` changed to the -27 numbering, and `description` changed wherever it cites a figure or section number. No file is byte-identical to its -16 counterpart, because of those references. Values compared below exclude `description` and `source_section`.

"Re-signed" means the issuer-signed JWT's header and payload are byte-identical to -16 and only its signature differs. All 5 issuer signatures in the draft are new; every Disclosure string (44 in the five compact forms, 37 in the two Disclosure listings) is byte-identical to -16.

| File | Changed values | Unchanged values |
|---|---|---|
| `vct-unsecured-payload.json` | `unsecured_payload.email`: `sorryfolks@ww.example` → `sorryfolks@parksclosed.example` | all other values |
| `example-unsecured-payload.json` | none | all values identical |
| `example-sd-jwt-payload.json` | none (the `description` no longer notes a wrong caption: -27 captions Figure 6 "SD-JWT Payload Example") | all values identical |
| `example-disclosures.json` | none | all values identical (9 Disclosures, decoded forms and digests) |
| `example-sd-jwt-vc.json` | re-signed: `sd_jwt_vc`, `issuer_signed_jwt` | `issuer_signed_jwt_header`; all 9 Disclosures in `sd_jwt_vc` |
| `example-presentation-kb-jwt.json` | re-signed: `presentation` (issuer signature); KB-JWT re-issued: `kb_jwt.compact` (new payload and signature), `kb_jwt.payload.iat` `1777056848` → `1794825844`, `kb_jwt.payload.sd_hash` and `kb_jwt.sd_hash` `h28cich0OJXvc9F9XOdMRPuPE0eXB1PxpqSNybMrLLU` → `QH6s-JbhU68vWrcLFujf6A4PUCUb_LbiNYzyDAiH1dQ`; `kb_jwt.note` cites Figure 8 | `disclosed_claims`, `kb_jwt.header`, `kb_jwt.payload.nonce`/`aud`, presented Disclosures, `processed_sd_jwt_payload` |
| `example-presentation-no-kb.json` | re-signed: `presentation` (issuer signature) | presented Disclosures, `processed_sd_jwt_payload` |
| `registered-claims.json` | added `must_not_be_selectively_disclosed.aka_vcts`: `OPTIONAL` (listed between `vct#integrity` and `status`) | all other claims and requirement levels |
| `type-metadata-example.json` | `sd_jwt_vc_payload_excerpt.vct#integrity`: `sha256-1odmyxoVQCuQx8SAym8rWHXba41fM/Iv/V1H8VHGN00=` → `sha256-5qAmRHgxiSHIPqS+mLzrVKVWliOBm955Oj86pMrc5g4=` | `vct`; the whole `type_metadata_document` |
| `appendix-a1-pid-issuance.json` | re-signed: `issued_sd_jwt` | `input_data`, `sd_jwt_payload`, all 28 Disclosures (strings, decoded forms, digests) |
| `appendix-a1-pid-presentation.json` | re-signed: `presentation` (issuer signature); KB-JWT re-issued: `kb_jwt.compact` (new payload and signature), `kb_jwt.payload.iat` `1777056848` → `1794825844`, `kb_jwt.payload.sd_hash` and `kb_jwt.sd_hash` `hwQH4nICSf_-be6IA6RD0GCeT4txntVNc153T0MTVgk` → `pV8mYucHAaFEBbKPod-KXh2PJCz7xmgQ1i3ERp5zX8w` | `disclosed_claims`, `kb_jwt.header`, `kb_jwt.payload.nonce`/`aud`, presented Disclosures, `processed_sd_jwt_payload` |
| `appendix-a2-type-metadata.json` | `sd_jwt_vc_payload.vct#integrity`: `sha256-1odmyxoVQCuQx8SAym8rWHXba41fM/Iv/V1H8VHGN00=` → `sha256-dPPy/f63dtwl0FcbK8Pr9t2uCrF83zHnfInSPDdHaZc=`; `type_metadata_document.name`: `Betelgeuse Education Credential - First Version` → `Betelgeuse Education Credential - Version 42`; `type_metadata_document.description`: `This is our first version of the education credential. Don't panic.` → `This is our education credential. Don't panic.`; `display[0].description`: `An education credential for all carbon-based life forms on Betelgeuse.` → `Education credential for all carbon-based life forms on Betelgeuse.`; `display[0].rendering.simple.background_image.uri`: `https://betelgeuse.example.com/public/credential-background.png` → `https://betelgeuse.example.com/public/cred-background.png`; `display[1].description`: `Ein Bildungsnachweis für alle kohlenstoffbasierten Lebensformen auf Betelgeuse.` → `Ldungsnachweis für kohlenstoffbasierten Lebensformen auf Betelgeuse.` (copied as printed; it looks like an editorial truncation in -27); `display[1].rendering.simple.background_image.uri`: `https://betelgeuse.example.com/public/credential-background-de.png` → `https://betelgeuse.example.com/public/cred-background-de.png`; `display[1].rendering.simple.background_image.uri#integrity`: `sha256-9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1ULmXfh=` → `sha256-9c/mAd0G1WaZOkU+lJNN/dACk3L+PmjZ5t0W5caxXfh=` (the -16 value was not valid base64 of 32 bytes; the -27 value is) | `sd_jwt_vc_payload` apart from `vct#integrity`; `vct`, `extends`, `extends#integrity`; all other display values; all `claims` metadata |

In -16 the excerpt in §4.1 (Figure 15) and the full payload (Figure 28) carried the same `vct#integrity`. In -27 they differ: Figure 16 refers to the short Figure 17 document and Figure 29 to the full Figure 30 document.

## Not vendored (and why)

- **Figure 16 is an excerpt by design:** the draft elides the remaining payload claims with `...`; only the literal `vct` and `vct#integrity` members are captured. The full payload is Figure 29, vendored in `appendix-a2-type-metadata.json`; its `vct#integrity` differs because it refers to the full Type Metadata document of Figure 30.
- **§2.2.2.2 `aka_vcts` excerpt (Fig. 4), new in -27:** a two-member Unsecured Payload excerpt (`vct: urn:example:eudi:pid:aendgard:1`, `aka_vcts: ["urn:example:eudi:pid"]`) without cryptographic material; the claim's selective-disclosure rule is captured in `registered-claims.json`.
- **§3 Retrieving Documents and Resources via HTTP (new in -27), §4 JWT VC Issuer Metadata (Figs. 12–15) and §5.5.1.2.2 SVG template (Fig. 18):** prose, HTTP request traces, issuer-metadata configuration and an SVG document; not SD-JWT/Disclosure test vectors, so out of scope for these fixtures.
- **§5.6.1.1 claim-path example (Fig. 19) and §5.6.5.2 extends example (Figs. 20–22):** illustrative metadata-processing fragments without cryptographic material; the vendored Figure 30 already covers claim paths and `extends`.
- **Appendix C (Document History):** prose only.
