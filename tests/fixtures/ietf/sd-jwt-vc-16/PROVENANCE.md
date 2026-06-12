# Provenance — draft-ietf-oauth-sd-jwt-vc-16 (SD-JWT VC) fixtures

- **Origin URL:** https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-16.txt
- **Document:** draft-ietf-oauth-sd-jwt-vc-16, "SD-JWT-based Verifiable Digital Credentials (SD-JWT VC)", O. Terbu / D. Fett / B. Campbell, 24 April 2026 (Internet-Draft, expires 26 October 2026; Intended status: Standards Track)
- **Retrieval date:** 2026-06-12 (`curl` of the plain-text Internet-Draft from ietf.org)
- **Local transformations:** manual extraction with line-unwrapping. Long base64url strings and JSON examples are hard-wrapped in the draft and some span page breaks; page footers/headers and form feeds were removed and values reassembled by stripping line breaks and leading whitespace only (JSON strings broken mid-string, e.g. the `portrait` data URI in Figure 22, were rejoined the same way). All base64url payloads are decode-verified (every JWT splits into 3 non-empty dot-separated parts whose header and payload decode to valid JSON; every Disclosure string decodes to a valid 2- or 3-element JSON array), every disclosure digest stated in the draft was recomputed as base64url(SHA-256(ASCII(disclosure))) and matched, and each `sd_hash` was recomputed over the presented SD-JWT (up to and including the final `~`) and matched the KB-JWT payload. Where the draft does not print KB-JWT header/payload separately (Figure 7), they were obtained by base64url-decoding the KB-JWT embedded in the presentation string (noted in the fixture). 345 automated checks across both fixture directories passed, 0 failures.

## Fixture count: 12 files

| File | Source section | Contents |
|---|---|---|
| `vct-unsecured-payload.json` | §2.2.2.1, Fig. 3 | Example Unsecured Payload with the `vct` claim identifying `https://credentials.example.com/identity_credential` |
| `example-unsecured-payload.json` | §2.3.1, Fig. 4 | User data comprising the Unsecured Payload of the main SD-JWT VC example |
| `example-sd-jwt-payload.json` | §2.3.1, Fig. 5 | SD-JWT payload of the main example (9 `_sd` digests, `iss`/`iat`/`exp`/`vct`, `_sd_alg`, `cnf`) |
| `example-disclosures.json` | §2.3.1 | All 9 Disclosures, each with `disclosure_b64`, `decoded`, `sha256_digest_b64url` |
| `example-sd-jwt-vc.json` | §2.3.1, Fig. 6 | The issued SD-JWT VC compact serialization (`typ: dc+sd-jwt`, `kid: doc-signer-05-25-2022`), plus the issuer-signed JWT (its first tilde-separated element) and decoded header |
| `example-presentation-kb-jwt.json` | §2.3.2, Figs. 7–8 | SD-JWT+KB presentation disclosing `address` and `is_over_65`; KB-JWT compact/header/payload (decoded from the presentation), `sd_hash`; processed SD-JWT payload |
| `example-presentation-no-kb.json` | §2.3.2, Figs. 9–10 | Presentation of a similar SD-JWT without `cnf`/KB-JWT, and its processed payload |
| `registered-claims.json` | §2.2.2.2 | Registered JWT claim rules: claims that MUST NOT be selectively disclosed (`iss`, `nbf`, `exp`, `cnf`, `vct`, `vct#integrity`, `status`) vs. claims that MAY be (`sub`, `iat`), with requirement levels |
| `type-metadata-example.json` | §4.1, Figs. 15–16 | `vct` + `vct#integrity` payload excerpt and the Type Metadata document retrieved from the vct URL (with `extends` + `extends#integrity`) |
| `appendix-b1-pid-issuance.json` | App. B.1, Figs. 22–24 | PID credential issuance: citizen input data (incl. PNG-portrait data URI, non-ASCII values), issued SD-JWT (28 disclosures), SD-JWT payload, and all 28 Disclosures (recursive for `address`, `place_of_birth`, `age_equal_or_over`) |
| `appendix-b1-pid-presentation.json` | App. B.1, Figs. 25–27 | PID SD-JWT+KB presentation (nationalities + `age_equal_or_over.18` via recursive Disclosures), KB-JWT payload (literal Figure 26) and header, processed payload |
| `appendix-b2-type-metadata.json` | App. B.2, Figs. 28–29 | Education-credential SD-JWT VC payload and the complete Type Metadata document (display metadata with `simple`/`svg_templates` renderings and locales; claim metadata with paths incl. `null` array selectors, `sd`, `mandatory`, `svg_id`) |

## Not vendored (and why)

- **Figure 15 is an excerpt by design:** the draft elides the remaining payload claims with `...`; only the literal `vct` and `vct#integrity` members are captured (the full equivalent payload is Figure 28, vendored in `appendix-b2-type-metadata.json`).
- **§3 JWT VC Issuer Metadata (Figs. 11–14) and §4.5.1.2 SVG template (Fig. 17):** HTTP request traces, issuer-metadata configuration and an SVG document — not SD-JWT/Disclosure test vectors; out of scope for these fixtures.
- **§4.6.1.1 claim-path example (Fig. 18) and §4.6.5.2 extends example (Figs. 19–21):** illustrative metadata-processing fragments without cryptographic material; the vendored Figure 29 already covers claim paths and `extends`.
- **Appendix D (Document History):** prose only.
