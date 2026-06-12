# Provenance — `tests/fixtures/contexts/`

Version-pinned copies of the core W3C JSON-LD contexts required by the offline
document loader (PRD FR-10). The `Rdfc` package embeds copies of these as
assembly resources; this directory is the provenance-tracked source of record.

- **Retrieval date:** 2026-06-11 (local; HTTP `Date` response headers read
  `Fri, 12 Jun 2026 00:12 GMT`).
- **Retrieval method:** `curl -sSL` with `Accept: application/ld+json`,
  following redirects. Each file was saved **byte-exact as served** — no
  reformatting, re-serialization, or whitespace changes (byte fidelity matters
  for canonicalization).
- **Local transformations:** none, other than choosing the local filename
  (`<slug>.jsonld`).
- **Pin verification:** for every file, the served bytes were additionally
  fetched from the upstream git repository at the pinned commit listed below
  and confirmed **SHA-256-identical** to the bytes served at the canonical URL.
- **Fixture count: 7** context files (`*.jsonld`). Any test asserting on this
  directory should expect exactly 7 context documents.

## Files

### 1. `credentials-v2.jsonld` — VCDM 2.0 context

- Requested URL: `https://www.w3.org/ns/credentials/v2` (no redirect; final URL identical)
- Served `Content-Type`: `application/ld+json`
- Server `Last-Modified`: `Tue, 11 Mar 2025 14:35:30 GMT`; `ETag: W/"2793-6301200217080;63f8f63e17458"`
- Spec: Verifiable Credentials Data Model v2.0 (W3C Recommendation)
- Git pin (byte-identical): `w3c/vc-data-model` @ `08b83e46c10ee37b0f4fb44b31459e611e521da0` (2025-02-25), path `contexts/credentials/v2`
- SHA-256: `59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734` (10131 bytes)

### 2. `data-integrity-v2.jsonld` — Data Integrity v2 context

- Requested URL: `https://w3id.org/security/data-integrity/v2`
- Final URL after redirect: `https://www.w3.org/2025/credentials/vcdi/context/v2.jsonld`
- Served `Content-Type`: `application/ld+json`
- Server `Last-Modified`: `Tue, 11 Mar 2025 15:32:06 GMT`; `ETag: W/"a31-63012ca8c4980"`
- Spec: Verifiable Credential Data Integrity 1.0 (W3C Recommendation)
- Git pin (byte-identical): `w3c/vc-data-integrity` @ `2b2788232d28d201773dda3b43e0127db9fbf96a` (2025-01-18), path `contexts/data-integrity/v2`
- SHA-256: `67f21e6e33a6c14e5ccfd2fc7865f7474fb71a04af7e94136cb399dfac8ae8f4` (2609 bytes)

### 3. `multikey-v1.jsonld` — Multikey v1 context

- Requested URL: `https://w3id.org/security/multikey/v1`
- Final URL after redirect: `https://www.w3.org/2025/credentials/vcdi/multikey/context/v1.jsonld`
- Served `Content-Type`: `application/ld+json`
- Server `Last-Modified`: `Tue, 11 Mar 2025 15:46:42 GMT`; `ETag: W/"3f2-63012fec2fc80"`
- Spec: Controlled Identifiers / Data Integrity (Multikey verification-method type)
- Git pin (byte-identical): `w3c/vc-data-integrity` @ `2b2788232d28d201773dda3b43e0127db9fbf96a` (2025-01-18), path `contexts/multikey/v1`
- SHA-256: `ba2c182de2d92f7e47184bcca8fcf0beaee6d3986c527bf664c195bbc7c58597` (1010 bytes)

### 4. `data-integrity-v1.jsonld` — Data Integrity v1 context (legacy; used by many W3C test vectors)

- Requested URL: `https://w3id.org/security/data-integrity/v1`
- Final URL after redirect: `https://w3c.github.io/vc-data-integrity/contexts/data-integrity/v1.jsonld`
- Served `Content-Type`: `application/ld+json`
- Server `Last-Modified`: `Thu, 09 Apr 2026 00:45:14 GMT` (GitHub Pages build date); `ETag: "69d6f69a-958"`
- Git pin (byte-identical): `w3c/vc-data-integrity` @ `2b2788232d28d201773dda3b43e0127db9fbf96a` (2025-01-18), path `contexts/data-integrity/v1`
  (note: the repo's `contexts/data-integrity/v1.jsonld` is a symlink to `v1`; the pinned path is the real file)
- SHA-256: `b5d829bd09aa7c42abc6efa0c8ed7635313b5487f37ccfce3ecd149ca9418554` (2392 bytes)

### 5. `bbs-v1.jsonld` — BBS v1 context (legacy 2020-era BBS+ terms — see caveat)

- Requested URL: `https://w3id.org/security/bbs/v1`
- Final URL after redirect: `https://w3c.github.io/vc-di-bbs/contexts/v1/`
- Served `Content-Type`: `application/json; charset=utf-8`
- Server `Last-Modified`: `Tue, 07 Apr 2026 16:10:48 GMT` (GitHub Pages build date); `ETag: "69d52c88-fa6"`
- Git pin (byte-identical): `w3c/vc-di-bbs` @ `ef682f0c5fd2825231b61dda8b76e8143122b8b9` (2021-05-21), path `contexts/v1/index.json`
- SHA-256: `65f03b15242ee97861039faec7a73297da4dd6880257fe4fd18edf1fc363a58d` (4006 bytes)
- **Caveat:** this resolves to the **legacy BBS+ LD-signatures context**
  (`BbsBlsSignature2020`, `BbsBlsSignatureProof2020`, `Bls12381G1Key2020`,
  `Bls12381G2Key2020`). The current Data Integrity BBS Cryptosuites spec
  (`https://www.w3.org/TR/vc-di-bbs/`, CRD dated 2026-04-07, checked
  2026-06-11) defines **no dedicated bbs-2023 context**: its `bbs-2023`
  examples use only `https://www.w3.org/ns/credentials/v2`,
  `https://w3id.org/security/data-integrity/v2`, and
  `https://w3id.org/security/multikey/v1` — all vendored here (files 1–3).
  This file is kept because `https://w3id.org/security/bbs/v1` resolves and
  some older BBS fixtures reference it; it is **not** required by `bbs-2023`.

### 6. `credentials-v1.jsonld` — VCDM 1.1 context (many W3C test vectors still use it)

- Requested URL: `https://www.w3.org/2018/credentials/v1` (no redirect; final URL identical)
- Served `Content-Type`: `application/ld+json`
- Server `Last-Modified`: `Fri, 19 Jul 2024 06:24:51 GMT`; `ETag: W/"1e07-61d93c0b8d2c0;61d93f37f1341"`
- Spec: Verifiable Credentials Data Model v1.1 (W3C Recommendation)
- Git pin (byte-identical): `w3c/vc-data-model` @ `cd28fa0ed92d50eed107f43ff441d7fd84ddcf50` (2019-06-30), path `contexts/credentials/v1`
- SHA-256: `ab4ddd9a531758807a79a5b450510d61ae8d147eab966cc9a200c07095b0cdcc` (7687 bytes)

### 7. `jws-2020-v1.jsonld` — JSON Web Signature 2020 suite context (optional extra)

- Requested URL: `https://w3id.org/security/suites/jws-2020/v1`
- Final URL after redirect: `https://w3c.github.io/vc-jws-2020/contexts/v1/`
- Served `Content-Type`: `application/json; charset=utf-8`
- Server `Last-Modified`: `Thu, 29 Jun 2023 12:36:12 GMT`; `ETag: "649d7abc-9a9"`
- Git pin (byte-identical): `w3c/vc-jws-2020` @ `189e9544262b6940a6900318606e1125111b5e7d` (2022-08-05), path `contexts/v1/index.json`
- SHA-256: `d648e05ddc6577827ca2bfd5e931f53e9ebc6e52a57a8da81df4ec8c46ffcd1e` (2473 bytes)
