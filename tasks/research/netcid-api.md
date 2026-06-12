# Research note: NetCid public API surface (for dataproofs-dotnet)

**Source audited:** `/Users/moises/Projects/net-cid` (read-only), HEAD = `10341a6` ("Preparing for shipping"), 2026-06-11.
**Package:** `NetCid` 1.6.0, nuget.org. **TFM:** `net10.0` only. **Sole dependency:** `SimpleBase 5.6.0`.
**Namespace:** everything lives in the single flat namespace `NetCid` (file-scoped `namespace NetCid;`).

This note covers the parts dataproofs needs per PRD §1.4 / FR-5 / FR-7 / FR-8 / FR-11 / FR-12: Multibase, Multicodec, Multihash, Multikey, and the JCS (RFC 8785) canonicalizer. CID itself is peripheral and summarized briefly.

---

## 1. CRITICAL — version provenance: the local NuGet cache is STALE

Verified facts (all checked 2026-06-11):

- nuget.org publishes versions `1.0.0 … 1.6.0`. The **nuget.org 1.6.0** nupkg's nuspec records `commit="10341a624f00fbeac0da23b1018264d5ea3b4f29"` — **exactly the source HEAD and the `v1.6.0` tag**. So the source tree at `/Users/moises/Projects/net-cid` HEAD is byte-authoritative for the published 1.6.0, and **everything documented in this note is present in nuget.org's 1.6.0**.
- The **local cache** at `/Users/moises/.nuget/packages/netcid/1.6.0` is **NOT the nuget.org package**. Its `.nupkg.metadata` says `"source": "/tmp/pack-adversarial"` (a local `dotnet pack`), its nuspec records commit `c6fe1078…` — a pre-merge branch commit far behind HEAD — and its SHA-512 content hash (`bKxzwYbM1Oa…`) differs from nuget.org's (`LxmfvGnRbsw…`).
- The stale cached package is **missing**, relative to real 1.6.0: the JCS recursion-depth limit, duplicate-member rejection, unpaired-surrogate rejection, and `maxOutputBytes` overloads (#16–#18); base64url canonical-trailing-bit pinning (#19); base32/base36 string-malleability fixes (#42, #43); culture/`tr-TR` hardening (#44); **`Multikey` SEC1 compressed-point validation (#45)**; and the JCS NaN-in-CLR-object exception translation (#47). Its `JcsCanonicalizer` has only three `Canonicalize` overloads (no `maxOutputBytes`), and its `Cid.FromCanonicalJson` lacks the `maxOutputBytes` parameter.

**Action required before dataproofs' first restore:** purge the stale cache so NuGet re-downloads the real package:

```bash
rm -rf ~/.nuget/packages/netcid/1.6.0
# or: dotnet nuget locals all --clear (heavier hammer)
```

NuGet keys the cache by id+version and will silently use the stale local copy otherwise. If dataproofs uses lock files with `RestoreLockedMode`, the hash mismatch would instead *fail* restore — equally confusing if unexplained.

One more compat note: 1.6.0 carries `NetCid/CompatibilitySuppressions.xml` because `Cid.FromCanonicalJson` gained an optional `maxOutputBytes` parameter vs 1.5.0 — a *binary* (not source) breaking change. Irrelevant unless mixing assemblies compiled against 1.5.0.

---

## 2. Multibase — `NetCid.Multibase` (static class)

File: `/Users/moises/Projects/net-cid/NetCid/Multibase.cs`. Exact public surface:

```csharp
public static class Multibase
{
    public const int DefaultMaxInputLength = 4096;

    public static string Encode(ReadOnlySpan<byte> bytes, MultibaseEncoding encoding, bool includePrefix = true);
    public static string EncodeBase58Btc(ReadOnlySpan<byte> bytes, bool includePrefix = false);   // NOTE default!

    public static byte[] Decode(string text);                                                     // default 4096 limit
    public static byte[] Decode(string text, out MultibaseEncoding encoding);
    public static byte[] Decode(string text, out MultibaseEncoding encoding, int maxInputLength);

    public static bool TryDecode(string text, out byte[] bytes, out MultibaseEncoding encoding);
    public static bool TryDecode(string text, out byte[] bytes, out MultibaseEncoding encoding, int maxInputLength);

    public static byte[] DecodeBase58Btc(string payload);                  // payload WITHOUT 'z' prefix
    public static byte[] DecodeBase58Btc(string payload, int maxInputLength);

    public static bool TryGetEncoding(char prefix, out MultibaseEncoding encoding);
    public static char GetPrefix(MultibaseEncoding encoding);
}
```

```csharp
public enum MultibaseEncoding
{
    Base32Lower,   // prefix 'b'
    Base32Upper,   // prefix 'B'
    Base36Lower,   // prefix 'k'
    Base36Upper,   // prefix 'K'
    Base58Btc,     // prefix 'z'
    Base64Url      // prefix 'u'
}
```

### Semantics and gotchas

- **Prefix-default asymmetry (trap):** `Encode(..., encoding)` includes the multibase prefix char **by default** (`includePrefix = true`), but `EncodeBase58Btc(bytes)` **omits it by default** (`includePrefix = false` — it exists for CIDv0 strings). For Data Integrity `proofValue` (`z…`) use `Multibase.Encode(sig, MultibaseEncoding.Base58Btc)` or `EncodeBase58Btc(sig, includePrefix: true)`.
- Correspondingly, `Decode`/`TryDecode` **require** the prefix char (first char dispatches via `TryGetEncoding`), while `DecodeBase58Btc` takes the bare payload with **no** `z`.
- **Base64Url is unpadded** RFC 4648 §5 (`System.Buffers.Text.Base64Url.EncodeToString` / `DecodeFromChars`) — exactly what multibase `u` requires (relevant to `bbs-2023` proofValues, which use base64url-no-pad multibase). Decode rejects non-canonical trailing bits and `=` padding.
- **Errors:** `Decode`/`DecodeBase58Btc` throw `NetCid.CidFormatException` (`: FormatException`) on any invalid input (unknown prefix, bad chars, over-limit, malleable/non-canonical forms). `TryDecode` returns `false` and never throws for data errors (it still throws `ArgumentOutOfRangeException` for `maxInputLength < 1`). `DecodeBase58Btc` throws `ArgumentException` (`ArgumentException.ThrowIfNullOrEmpty`) on null/empty.
- **Input length cap:** `DefaultMaxInputLength = 4096` characters (including the prefix char) on all decode paths. **A large `bbs-2023` derived proofValue or a big multibase blob can exceed 4096 chars** — pass an explicit `maxInputLength` on those paths.
- Decoding an empty payload after a valid prefix (e.g. `"z"`) yields `Array.Empty<byte>()` — not an error.
- Base58btc alphabet is the standard Bitcoin one: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`; chars are pre-validated against the alphabet before SimpleBase decodes, so error type is always `CidFormatException`.
- Hardening (all in real 1.6.0): base32 incomplete-trailing-symbol rejection (#42), base36 pre-fold ASCII validation (#43), invariant-culture SimpleBase warm-up in the static ctor so `tr-TR`-style cultures can't poison decoding (#44). None of these change the happy path for base58btc/base64url.

---

## 3. Multicodec — `NetCid.Multicodec` (static class)

File: `/Users/moises/Projects/net-cid/NetCid/Multicodec.cs`. Codecs are plain `public const ulong` values — there is no enum and no codec object. Key-type constants dataproofs needs:

```csharp
public const ulong Secp256k1Pub   = 0xE7;     // "secp256k1-pub"
public const ulong Bls12381G1Pub  = 0xEA;     // "bls12_381-g1-pub"
public const ulong Bls12381G2Pub  = 0xEB;     // "bls12_381-g2-pub"   <- bbs-2023 public keys
public const ulong X25519Pub      = 0xEC;     // "x25519-pub"
public const ulong Ed25519Pub     = 0xED;     // "ed25519-pub"
public const ulong P256Pub        = 0x1200;   // "p256-pub"
public const ulong P384Pub        = 0x1201;   // "p384-pub"
public const ulong P521Pub        = 0x1202;   // "p521-pub"
```

(Also present: content codecs `Raw = 0x55`, `DagPb = 0x70`, `DagCbor = 0x71`, `DagJson = 0x0129`, etc. — irrelevant here.)

Lookup / prefix API:

```csharp
public static IEnumerable<KeyValuePair<ulong, string>> Entries { get; }
public static bool TryGetName(ulong code, out string? name);     // 0xED -> "ed25519-pub"
public static bool TryGetCode(string name, out ulong code);      // ordinal, exact-case match
public static byte[] Prefix(ulong codec, ReadOnlySpan<byte> rawBytes);            // varint(codec) || rawBytes
public static (ulong Codec, byte[] RawBytes) Decode(ReadOnlySpan<byte> prefixedBytes); // throws CidFormatException
public static bool TryDecode(ReadOnlySpan<byte> prefixedBytes, out ulong codec, out byte[]? rawBytes);
```

- Name strings match the multicodec registry exactly — note the underscore spelling **`bls12_381-g2-pub`** (not `bls12-381…`).
- Varint encoding is via `NetCid.Varint` (public): canonical unsigned LEB128, max value `0x7FFF_FFFF_FFFF_FFFF`, ≤ 9 bytes; decode rejects non-minimal encodings. `Varint.GetEncodedLength(ulong)`, `Encode(ulong)`, `Write(ulong, Span<byte>)`, `Decode(ReadOnlySpan<byte>, out int bytesRead)`, `TryDecode(...)` are all public if dataproofs ever needs raw varints. For the key codecs above: `0xE7…0xED` encode as 2 varint bytes, `0x1200…0x1202` also 2 bytes.
- `Multicodec.TryDecode` accepts **any** varint codec (no allowlist) and hands back the remainder; key-type policing happens in `Multikey`, not here.

---

## 4. Multihash — `NetCid.Multihash`, `MultihashDigest`, `MultihashCode`

Files: `Multihash.cs`, `MultihashDigest.cs`, `MultihashCode.cs`. Wire format `varint(code) || varint(len) || digest`.

```csharp
public static class Multihash
{
    public static byte[] Encode(ulong hashFunctionCode, ReadOnlySpan<byte> digest);
    public static (ulong Code, byte[] Digest) Decode(ReadOnlySpan<byte> multihash);   // throws CidFormatException
    public static bool TryDecode(ReadOnlySpan<byte> multihash, out ulong code, out byte[]? digest);
}

public readonly struct MultihashDigest : IEquatable<MultihashDigest>
{
    public MultihashDigest(ulong code, ReadOnlySpan<byte> digest);   // copies digest
    public ulong Code { get; }
    public int DigestLength { get; }
    public ReadOnlySpan<byte> DigestSpan { get; }
    public static MultihashDigest Parse(ReadOnlySpan<byte> source, out int bytesRead);   // throws CidFormatException
    public static bool TryParse(ReadOnlySpan<byte> source, out MultihashDigest digest, out int bytesRead);
    public byte[] GetDigestBytes();      // copy
    public byte[] ToByteArray();         // full multihash bytes
    public static MultihashDigest Sha2_256(ReadOnlySpan<byte> bytes);  // hashes content with SHA256.HashData
    public static MultihashDigest Sha2_512(ReadOnlySpan<byte> bytes);
    // value equality, ==/!= operators, GetHashCode over code+digest
}

public static class MultihashCode   // public const ulong codes
{
    Identity = 0x00; Sha1 = 0x11; Sha2_256 = 0x12; Sha2_512 = 0x13;
    Sha3_512 = 0x14; Sha3_384 = 0x15; Sha3_256 = 0x16; Sha3_224 = 0x17;
    Shake128 = 0x18; Shake256 = 0x19; Keccak224..Keccak512 = 0x1A..0x1D; Blake3 = 0x1E;
}
```

Note: only SHA2-256/512 have *hashing* helpers; `Multihash.Encode` itself takes a pre-computed digest with any registered code. SHA-384 (needed for `ecdsa-*-2019` P-384 hashing) has no multihash constant here — irrelevant for Data Integrity, which never multihash-wraps digests; dataproofs uses `SHA384.HashData` directly and multihash is unlikely to appear in any v1 code path.

---

## 5. Multikey — `NetCid.Multikey` (static class — NOT a data type)

File: `/Users/moises/Projects/net-cid/NetCid/Multikey.cs`. Implements W3C Controlled Identifiers 1.0 `publicKeyMultibase` / `did:key`: `base58btc( varint(keyCodec) || rawPublicKey )` with leading `z`.

```csharp
public static class Multikey
{
    public static string Encode(ulong keyCodec, ReadOnlySpan<byte> rawKey);
    public static (ulong KeyCodec, byte[] RawKey) Decode(string publicKeyMultibase);   // throws CidFormatException
    public static bool TryDecode(string publicKeyMultibase, out ulong keyCodec, out byte[]? rawKey);
}
```

### Construction / encode
`Encode(Multicodec.Ed25519Pub, raw32)` → `"z6Mk…"`. Throws `ArgumentException` when:
- `keyCodec` is not one of the **eight** supported key codecs (ed25519, x25519, secp256k1, p256, p384, p521, bls12_381-g1, bls12_381-g2 — exact list in the exception message);
- `rawKey` length is wrong for the codec;
- (Weierstrass codecs only) `rawKey[0]` is not the SEC1 compressed-point prefix `0x02`/`0x03`, or P-521's x-coordinate top byte exceeds `0x01`.

### Decode / key-type detection / raw key extraction
`TryDecode` returns `false` (and `Decode` throws `CidFormatException("Invalid publicKeyMultibase value.")`) for: any non-base58btc multibase (the encoding is checked, not just the payload), any non-key-type codec, wrong raw length, or invalid SEC1 shape. On success you get the codec as `ulong` — **key type detection is a `switch` on that value against the `Multicodec` constants**; there is no enum or type object. `rawKey` is the raw public key with the codec prefix already stripped.

### Expected raw-key lengths (enforced both directions; from private `ExpectedLength`)

| codec | const | raw length | form |
|---|---|---|---|
| ed25519-pub | `0xED` | 32 | raw Edwards point |
| x25519-pub | `0xEC` | 32 | raw Montgomery u |
| secp256k1-pub | `0xE7` | 33 | SEC1 **compressed** |
| p256-pub | `0x1200` | 33 | SEC1 **compressed** |
| p384-pub | `0x1201` | 49 | SEC1 **compressed** |
| p521-pub | `0x1202` | 67 | SEC1 **compressed** |
| bls12_381-g1-pub | `0xEA` | 48 | canonical G1 |
| bls12_381-g2-pub | `0xEB` | 96 | canonical G2 |

### Implications for dataproofs
- **There is no `Multikey` value/record type.** PRD FR-7/FR-8 say resolver results carry "`Multikey` (NetCid) canonical" key material — the natural representations are either the `publicKeyMultibase` **string** or the decoded `(ulong keyCodec, byte[] rawKey)` pair. dataproofs will need its own small wrapper (e.g. `record PublicKeyMultikey(ulong Codec, byte[] RawKey)`) or to pass the string and decode at the boundary. Do **not** invent a competing multicodec table; switch on `Multicodec.*` constants.
- **EC keys come out SEC1-compressed.** NetCrypto/JWK paths need the affine X,Y. NetCid provides **no point decompression** — converting `p256-pub`/`p384-pub`/`secp256k1-pub` raw keys to JWK `x`/`y` (FR-15 JWK↔Multikey conversion) requires decompression elsewhere (e.g. `ECCurve`/BCL `ECPoint` import of compressed points where supported, or NetCrypto). Conversely, JWK→Multikey requires compressing the point (prefix `0x02 | (y & 1)`, X big-endian, fixed width). This conversion code lives in dataproofs (or NetCrypto), not NetCid.
- Encode-side validation means dataproofs can rely on `Multikey.Encode` to reject malformed material loudly; verify-side `TryDecode` is the right call in resolvers (structured failure, no exceptions on hostile input).

---

## 6. JCS (RFC 8785) — `NetCid.JcsCanonicalizer` (static class)

File: `/Users/moises/Projects/net-cid/NetCid/JcsCanonicalizer.cs`. **Operates exclusively on `System.Text.Json` types** (`System.Text.Json.Nodes.JsonNode` and `System.Text.Json.JsonElement`). Output is **UTF-8 bytes**, never a `string`. Thread-safe, all-static, stateless.

Exact public surface (all five overloads, plus the const):

```csharp
public static class JcsCanonicalizer
{
    public const int DefaultMaxOutputByteLength = 1_048_576;   // 1 MiB output cap

    public static byte[] Canonicalize(JsonNode? node);
    public static byte[] Canonicalize(JsonNode? node, int maxOutputBytes);
    public static byte[] Canonicalize(JsonElement element);
    public static byte[] Canonicalize(JsonElement element, int maxOutputBytes);
    public static void   Canonicalize(JsonNode? node, IBufferWriter<byte> destination);
    public static void   Canonicalize(JsonNode? node, IBufferWriter<byte> destination, int maxOutputBytes);
}
```

(Yes — six including the writer+limit overload; the `JsonElement` family has no `IBufferWriter` variant.)

- **Input:** parse strings yourself first — `JsonNode.Parse(json)` or `JsonDocument.Parse(json).RootElement`. A `null` `JsonNode?` canonicalizes to the literal `null`.
- **Output:** canonical UTF-8 `byte[]`, or streamed into an `IBufferWriter<byte>` (zero intermediate array — feed it an `ArrayBufferWriter<byte>` or hash directly). For the string form, `Encoding.UTF8.GetString(bytes)`.
- **Errors:** everything non-canonicalizable throws `NetCid.JcsFormatException : FormatException` (two ctors: `(string)`, `(string, Exception)`):
  - NaN / ±Infinity (RFC 8785 §3.2.2.3);
  - duplicate object member names (RFC 7493 §2.3 — `JsonDocument` preserves duplicates, so this is an explicit guard; message names the key);
  - nesting deeper than **64** levels (DoS guard — checked before STJ ever recurses);
  - output exceeding `maxOutputBytes` (default 1 MiB; the crossing byte is rejected *before* commit, so a caller-supplied writer never receives more than the limit);
  - unpaired UTF-16 surrogates in strings or member names (rejected rather than silently folded to U+FFFD).
  - `ArgumentOutOfRangeException` only for `maxOutputBytes < 1`; `ArgumentNullException` for a null `destination`.
- **Conformance details that matter for `eddsa-jcs-2022`/`ecdsa-jcs-2019`:** member sort is UTF-16 code-unit order (`string.CompareOrdinal`); numbers go through ECMA-262 §6.1.6.1.20 shortest-round-trip serialization (internal `EcmaScriptNumber.ToCanonicalString(double)`, validated against cyberphone's 100M-vector set in CI with a pinned SHA); integers with |x| ≤ 2^53 are emitted as integer text; escaping is the RFC-minimal set (the seven short escapes + `\u00XX` for <0x20; solidus NOT escaped; non-ASCII emitted as raw UTF-8).
- **Trap (documented in the type's remarks):** a `JsonValue` wrapping a raw CLR object (`JsonValue.Create(poco)`, a `Dictionary`, etc.) is expanded by `JsonSerializer` *before* surrogate validation can see it, so U+FFFD substitution can occur silently on that path; NaN/Inf hidden in such objects still throw `JcsFormatException` (#47, real-1.6.0 only). **For untrusted input, always pass parsed JSON (`JsonNode.Parse`/`JsonElement`), never CLR-object-wrapping nodes.** dataproofs' pipeline should standardize on parsed `JsonNode`/`JsonElement` documents anyway.
- **Sizing:** very large credentials (> 1 MiB canonical) need the `maxOutputBytes` overload; depth > 64 is unsupported, period (no knob). Both limits are fine for any realistic VC but must be surfaced in dataproofs' error mapping (`PROOF_TRANSFORMATION_ERROR` seems the right bucket for `JcsFormatException` during transformation).

### Fit for the JCS-suite pipeline (FR-5)
`hashData = SHA-x(JcsCanonicalizer.Canonicalize(proofConfigNode)) ‖ SHA-x(JcsCanonicalizer.Canonicalize(documentNode))` — direct. The `IBufferWriter` overload composes with `IncrementalHash` via a small adapter if allocation matters; the `byte[]` overloads are simplest and fine.

---

## 7. Peripheral: `Cid`, `CidVersion`, exceptions

Likely unused by dataproofs v1, but present in the namespace (avoid name collisions):

- `public sealed class Cid : IEquatable<Cid>` — `CreateV0/CreateV1/FromContent/FromCanonicalJson(JsonNode?, ulong codec = Multicodec.Raw, ulong hashCode = MultihashCode.Sha2_256, int maxOutputBytes = JcsCanonicalizer.DefaultMaxOutputByteLength)`, `Parse/TryParse(string[, int maxInputStringLength, int maxInputByteLength])`, `Decode/TryDecode(ReadOnlySpan<byte>[, int])`, `ToV0()/ToV1(ulong?)`, `ToByteArray()`, `ToString(MultibaseEncoding)` (CIDv1 default `ToString()` is base32-lower), `Version/Codec/CodecName/Multihash/Bytes`; consts `DefaultMaxInputStringLength = 4096`, `DefaultMaxInputByteLength = 1_048_576`.
- `public enum CidVersion : byte { V0 = 0, V1 = 1 }`.
- `public sealed class CidFormatException : FormatException` — thrown by **all** multibase/multicodec/multihash/multikey/CID parse failures (single normalized error type; ctors `(string)` and `(string, Exception)`).
- `public sealed class JcsFormatException : FormatException` — all JCS failures.
- `internal static class EcmaScriptNumber` — NOT public (the XML doc file documents it anyway; don't be fooled).

Complete public type list in the assembly: `Cid`, `CidVersion`, `CidFormatException`, `JcsCanonicalizer`, `JcsFormatException`, `Multibase`, `MultibaseEncoding`, `Multicodec`, `Multihash`, `MultihashCode`, `MultihashDigest`, `Multikey`, `Varint`.

---

## 8. Ready-made recipes for dataproofs

```csharp
using NetCid;

// proofValue encode (eddsa/ecdsa suites: base58-btc multibase, 'z' prefix)
string proofValue = Multibase.Encode(signature, MultibaseEncoding.Base58Btc);   // includePrefix defaults true

// proofValue decode + header policing (vc-di-eddsa REQUIRES 'z'; bbs-2023 uses 'u')
if (!Multibase.TryDecode(proofValue, out var sigBytes, out var enc) || enc != MultibaseEncoding.Base58Btc)
    return ProofResult.Error("PROOF_VERIFICATION_ERROR", "proofValue is not base58-btc multibase");

// bbs-2023 derived proofValue (can be long — raise the 4096-char default cap)
byte[] bbsProof = Multibase.Decode(bbsProofValue, out var bbsEnc, maxInputLength: 1_048_576);

// publicKeyMultibase -> (key type, raw key)
if (!Multikey.TryDecode(vm.PublicKeyMultibase, out var codec, out var raw))
    return ProofResult.Error("INVALID_VERIFICATION_METHOD", "bad publicKeyMultibase");
var keyType = codec switch
{
    Multicodec.Ed25519Pub      => KeyType.Ed25519,
    Multicodec.P256Pub         => KeyType.P256,       // raw = 33B SEC1 compressed
    Multicodec.P384Pub         => KeyType.P384,       // raw = 49B SEC1 compressed
    Multicodec.Secp256k1Pub    => KeyType.Secp256k1,  // raw = 33B SEC1 compressed
    Multicodec.Bls12381G2Pub   => KeyType.Bls12381G2, // raw = 96B G2
    _ => /* unsupported for this suite */ ...
};

// raw key -> publicKeyMultibase (e.g., emitting a Multikey verification method)
string pkMb = Multikey.Encode(Multicodec.Ed25519Pub, rawEd25519PublicKey);

// JCS canonicalization for eddsa-jcs-2022 (FR-5)
byte[] canonicalConfig = JcsCanonicalizer.Canonicalize(proofConfigNode);    // JsonNode? -> UTF-8 bytes
byte[] canonicalDoc    = JcsCanonicalizer.Canonicalize(documentElement);    // JsonElement overload
byte[] hashData = [.. SHA256.HashData(canonicalConfig), .. SHA256.HashData(canonicalDoc)];
```

---

## 9. Risks / PRD-assumption impacts

1. **Stale local NuGet cache (HIGH, environmental).** `~/.nuget/packages/netcid/1.6.0` is a locally packed, pre-hardening build (source `/tmp/pack-adversarial`, commit `c6fe107`), not nuget.org's 1.6.0 (commit `10341a6` = HEAD = `v1.6.0` tag). Until purged, any dataproofs build on this machine compiles against an API **missing the JCS `maxOutputBytes` overloads** and the Multikey SEC1 validation, and its behavior diverges from CI. Purge before first restore; consider committing a lock file so the hash mismatch fails loudly everywhere.
2. **PRD's "`Multikey` canonical" is a string/tuple, not a type.** NetCid's `Multikey` is a static codec; FR-7/FR-8's resolver result needs a dataproofs-defined carrier (string `publicKeyMultibase` or `(ulong codec, byte[] raw)` record). Small design decision the coding agent must make deliberately.
3. **No EC point decompression.** Multikey EC raw keys are SEC1-compressed; JWK↔Multikey conversion (FR-15) needs (de)compression from BCL/NetCrypto, not NetCid. Verify NetCrypto accepts compressed points or expose a decompress helper in dataproofs.
4. **Multibase 4096-char default decode cap** can reject legitimate large `bbs-2023` proofValues; always pass an explicit `maxInputLength` on proofValue decode paths sized to the document policy.
5. **JCS limits:** 64-level depth (hard, no knob) and 1 MiB default output cap (knob via `maxOutputBytes`). Map `JcsFormatException` to `PROOF_TRANSFORMATION_ERROR`; for >1 MiB documents the pipeline must thread a larger cap through.
6. **`EncodeBase58Btc` prefix default is `false`** (CIDv0 legacy) — opposite of `Encode(...)`'s `true`. Easy source of a missing-`z` proofValue bug; prefer `Multibase.Encode(bytes, MultibaseEncoding.Base58Btc)`.
7. **net10.0-only TFM.** Fine for this stack (PRD targets .NET 10), but NetCid cannot be consumed by anything older if package TFMs ever broaden.
8. **JCS untrusted-input caveat:** only parsed JSON (`JsonNode.Parse`/`JsonElement`) gets full surrogate validation; CLR-object-wrapping `JsonValue`s can silently U+FFFD-fold. dataproofs' pipeline must standardize on parsed `System.Text.Json` values (it should anyway).
9. **SHA-384 multihash constant absent** (`MultihashCode` stops at standard codes without Sha2_384). Irrelevant to Data Integrity (no multihash wrapping), but if anything ever multihash-wraps a P-384 digest, the code (0x20) must be supplied as a raw `ulong`.
