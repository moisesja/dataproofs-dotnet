# NetCrypto API map (for DataProofsDotnet)

Research note mapping the complete public API surface of **NetCrypto** relevant to
dataproofs-dotnet. Source audited: `/Users/moises/Projects/crypto-dotnet` (repo `crypto-dotnet`,
project `src/NetCrypto/`), 2026-06-11. This note is self-contained: a coding agent should not
need to open the NetCrypto source.

## 1. Package identity, TFM, dependencies

- **PackageId:** `NetCrypto`. **Version:** `1.0.0-preview.1`
  (default of `$(NetCryptoVersion)` in `/Users/moises/Projects/crypto-dotnet/Directory.Build.props`,
  line 8; CI can override at pack time). Published on nuget.org per the dataproofs PRD.
- **TFM:** `net10.0` only (`Directory.Build.props` line 3). Root namespace and assembly: `NetCrypto`.
  **Everything public lives in the single namespace `NetCrypto`** (plus `NetCrypto.Native` which is
  entirely `internal`).
- **Runtime dependencies** (from `Directory.Packages.props` + `src/NetCrypto/NetCrypto.csproj`):
  `NetCid 1.6.0`, `NSec.Cryptography 26.4.0`, `NBitcoin.Secp256k1 4.0.0`,
  `Nethermind.Crypto.Bls 1.0.5`, `Microsoft.IdentityModel.Tokens 8.19.1`,
  `Microsoft.Extensions.DependencyInjection.Abstractions 10.0.8`.
  dataproofs gets NSec/NBitcoin/Nethermind *transitively* — it must never reference them directly
  (its AC-6 forbids them), and it never needs to: NetCrypto fully wraps them.
- **Public API is locked** by `Microsoft.CodeAnalysis.PublicApiAnalyzers` via
  `src/NetCrypto/PublicAPI.Shipped.txt` (the authoritative full surface; `PublicAPI.Unshipped.txt`
  is empty). Every signature quoted below was verified against that file and the source.
- **XML docs:** `CS1591` is errors-as-warnings, so every public member is documented; the package
  ships `NetCrypto.xml`.

### Native binaries (BBS)

- The only native dependency is **zkryptium-ffi** (Rust, `native/zkryptium-ffi/` in the repo),
  P/Invoked through `internal static partial class ZkryptiumNative`
  (`src/NetCrypto/Native/ZkryptiumNative.cs`, `LibraryImport`-generated, hence
  `AllowUnsafeBlocks`).
- Packaging: `NetCrypto.csproj` packs `runtimes\**\native\*` → `PackagePath="runtimes"`,
  `CopyToOutputDirectory="PreserveNewest"`. The folder is **empty in git; release CI populates it
  at pack time**. Supported RIDs (from the `BbsUnavailableException` message):
  **osx-arm64, osx-x64, linux-x64, linux-arm64, win-x64**.
- Running **without** the native library is a supported mode (see §7): everything non-BBS works,
  `IBbsCryptoProvider.IsAvailable` is `false`, and only BBS operations throw
  `BbsUnavailableException`.

## 2. `ISigner` — the signing abstraction dataproofs must consume

File: `src/NetCrypto/ISigner.cs`. Complete interface:

```csharp
namespace NetCrypto;

public interface ISigner
{
    KeyType KeyType { get; }
    ReadOnlyMemory<byte> PublicKey { get; }          // raw public key bytes; always available, even HSM-backed
    string MultibasePublicKey { get; }               // multicodec-prefixed, base58-btc multibase ("z6Mkf...")
    Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default);
}
```

Two shipped implementations:

```csharp
// src/NetCrypto/KeyPairSigner.cs — in-memory "simple path"
public sealed class KeyPairSigner : ISigner
{
    public KeyPairSigner(KeyPair keyPair, ICryptoProvider crypto);
    // SignAsync body: Task.FromResult(_crypto.Sign(_keyPair.KeyType, _keyPair.PrivateKey, data.Span));
}

// src/NetCrypto/KeyStoreSigner.cs — store/HSM-backed "secure path"
public sealed class KeyStoreSigner : ISigner
{
    public KeyStoreSigner(IKeyStore store, string alias, KeyType keyType, byte[] publicKey);
    // SignAsync body: _store.SignAsync(_alias, data, ct);
}
```

### CRITICAL gotcha: `ISigner` has no `EcdsaSignatureFormat` parameter

`ISigner.SignAsync` and `IKeyStore.SignAsync` take only `(data, ct)`. Both shipped signers route
to the **default** `ICryptoProvider.Sign(keyType, privateKey, data)` overload, which returns
NIST-curve ECDSA (P-256/P-384/P-521) signatures in **DER** (see §4). There is **no way through the
current `ISigner`/`IKeyStore` surface to request IEEE P1363**. Ed25519 (64-byte) and secp256k1
(64-byte compact R‖S, already P1363-shaped) are unaffected. Consequence for dataproofs FR-2/FR-5/
FR-11/FR-13 ("a signer backed by a non-exporting IKeyStore MUST be sufficient for every suite",
"ES256/ES384 MUST use the IeeeP1363 overload"): for P-256/P-384 suites, dataproofs must either
(a) transcode the DER signature returned by `ISigner.SignAsync` to fixed-width R‖S itself (pure
ASN.1 byte parsing — no crypto primitive, so AC-6-clean), or (b) get a format-aware
`ISigner`/`IKeyStore` member added to NetCrypto (concept §6: missing primitive = NetCrypto work
item). Verification is unaffected: dataproofs verifies with `ICryptoProvider.Verify(...,
EcdsaSignatureFormat.IeeeP1363)` against P1363 bytes it decoded from `proofValue`/JWS.
P1363 fixed widths per curve: 2×32 (P-256), 2×48 (P-384), 2×66 (P-521).

## 3. `IKeyStore` — non-exporting key storage

File: `src/NetCrypto/IKeyStore.cs`. Complete interface — **confirmed: there is NO key-export
member**; private key material can enter (`ImportAsync`) but can never leave
(`StoredKeyInfo` carries the public key only):

```csharp
public interface IKeyStore
{
    Task<StoredKeyInfo> GenerateAsync(string alias, KeyType keyType, CancellationToken ct = default);
    Task<StoredKeyInfo> ImportAsync(string alias, KeyPair keyPair, CancellationToken ct = default);
    Task<StoredKeyInfo?> GetInfoAsync(string alias, CancellationToken ct = default);   // null when alias unknown
    Task<byte[]> SignAsync(string alias, ReadOnlyMemory<byte> data, CancellationToken ct = default);
    Task<ISigner> CreateSignerAsync(string alias, CancellationToken ct = default);
    Task<IReadOnlyList<string>> ListAsync(CancellationToken ct = default);
    Task<bool> DeleteAsync(string alias, CancellationToken ct = default);
}
```

`StoredKeyInfo` (`src/NetCrypto/StoredKeyInfo.cs`) — sealed record, never contains private key
material; defensively copies the public key on get/init; content-based equality:

```csharp
public sealed record StoredKeyInfo
{
    public required string Alias { get; init; }
    public required KeyType KeyType { get; init; }
    public required byte[] PublicKey { get; init; }   // get returns a fresh clone every call
    public string MultibasePublicKey { get; }          // Multibase.Encode(Multicodec.Prefix(KeyType.GetMulticodec(), pk), Base58Btc)
    public bool Equals(StoredKeyInfo? other);          // Alias + KeyType + PublicKey *content*
    public override int GetHashCode();
}
```

`InMemoryKeyStore` (`src/NetCrypto/InMemoryKeyStore.cs`) — `ConcurrentDictionary`-backed,
explicitly "NOT for production", ideal for dataproofs tests/samples:

```csharp
public sealed class InMemoryKeyStore : IKeyStore
{
    public InMemoryKeyStore(IKeyGenerator keyGenerator, ICryptoProvider cryptoProvider);
}
```

Behavioral details that matter for tests:
- `GenerateAsync`/`ImportAsync` throw `InvalidOperationException` on duplicate alias.
- `SignAsync`/`CreateSignerAsync` throw `KeyNotFoundException` for an unknown alias;
  `GetInfoAsync` returns `null` instead.
- `SignAsync` body: `_cryptoProvider.Sign(entry.KeyPair.KeyType, entry.KeyPair.PrivateKey, data.Span)`
  — i.e. the **DER-default** overload (the §2 gotcha).
- `CreateSignerAsync` returns a `KeyStoreSigner(this, alias, info.KeyType, info.PublicKey)`.
- DI: `ServiceCollectionExtensions.AddNetCrypto(this IServiceCollection)` registers
  `ICryptoProvider → DefaultCryptoProvider`, `IBbsCryptoProvider → DefaultBbsCryptoProvider`,
  `IKeyGenerator → DefaultKeyGenerator` via `TryAddSingleton` (consumer registrations made
  *before* the call win). **`IKeyStore` is intentionally NOT registered** — consumers bring
  their own.

## 4. `ICryptoProvider` / `DefaultCryptoProvider` — sign/verify/ECDH

Files: `src/NetCrypto/ICryptoProvider.cs`, `src/NetCrypto/DefaultCryptoProvider.cs`
(`public sealed class DefaultCryptoProvider : ICryptoProvider`, public parameterless ctor).

```csharp
public interface ICryptoProvider
{
    byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data);                                  // NIST ECDSA → DER (back-compat default)
    byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, EcdsaSignatureFormat format);
    bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);     // expects DER for NIST ECDSA
    bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, EcdsaSignatureFormat format);
    byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey);                                      // X25519-only convenience; returns HKDF-SHA256-derived 32-byte key
    byte[] DeriveSharedSecret(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey);               // raw ECDH "Z", no KDF
}
```

```csharp
public enum EcdsaSignatureFormat   // src/NetCrypto/EcdsaSignatureFormat.cs
{
    Der = 0,        // ASN.1 SEQUENCE{r,s}. THE DEFAULT (X.509/CMS back-compat).
    IeeeP1363 = 1,  // fixed-width R‖S, zero-padded to field length (32/48/66). Required by JOSE/COSE/WebAuthn.
}
```

`format` is only meaningful for **P-256/P-384/P-521**. Non-NIST types ignore it:
Ed25519 → 64-byte EdDSA; secp256k1 → **always 64-byte compact R‖S** (RFC 6979 deterministic
nonces; data is SHA-256'd internally before signing — `ES256K`-compatible); BLS12-381 G1/G2 →
compressed point signature (G1-pubkey variant signs into G2, 96 bytes; G2-pubkey variant signs
into G1, 48 bytes; CFRG BLS DSTs). `Sign`/`Verify` with `KeyType.X25519` throws
`ArgumentException` ("key agreement algorithm, not a signing algorithm").

Per-curve hashing inside `Sign`/`Verify` (dataproofs never pre-hashes for these):
P-256 → SHA-256, P-384 → SHA-384, P-521 → SHA-512, secp256k1 → SHA-256, Ed25519 → pure EdDSA
(no prehash), BLS → hash-to-curve.

**Verify semantics (JOSE convention, important for FR-13):** a malformed signature, wrong-format
signature (DER passed as P1363 or vice versa), wrong-length P1363 signature, or off-curve/
malformed-but-well-formed-length public key returns **`false`**, not an exception
(`CryptographicException` is caught internally; verified in `VerifyEcDsa`). A wrong-*length*/
wrong-*prefix* public key encoding still throws `ArgumentException` (caller bug). secp256k1
`Verify` returns `false` for an unparseable key or non-compact signature.

### `DeriveSharedSecret` exact semantics

```csharp
byte[] DeriveSharedSecret(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey);
```

- **Supported `keyType`:** `X25519`, `P256`, `P384`, `P521` (the XML doc lags — it says "P-521
  added in issue #61", but the implementation switch already handles `KeyType.P521`). Anything
  else → `ArgumentException`.
- **Input encodings:** X25519 → raw 32-byte public key; NIST curves → SEC1 compressed
  (`0x02/0x03‖X`) or uncompressed (`0x04‖X‖Y`) point. Off-curve points are rejected
  (invalid-curve defense via `EcPointValidator`, surfacing as `CryptographicException`).
- **Output:** the raw ECDH shared secret **Z** — the X-coordinate of the shared point; **no KDF,
  no truncation**: 32 bytes (X25519, P-256), 48 bytes (P-384), 66 bytes (P-521).
- Pairs with `ConcatKdf.DeriveKey` for JOSE ECDH-ES (RFC 7518 §4.6) and ECDH-1PU
  (pass `Ze ‖ Zs` as `sharedSecret`).
- `KeyAgreement(priv, pub)` is the *legacy* X25519-only convenience that bakes in
  HKDF-SHA256 → 32 bytes. For JWE, dataproofs should use `DeriveSharedSecret` + `ConcatKdf`,
  not `KeyAgreement`.

## 5. Key model, key generation, key formats

```csharp
public enum KeyType   // src/NetCrypto/KeyType.cs — exact members and underlying values
{
    Ed25519 = 0, X25519 = 1, P256 = 2, P384 = 3, Secp256k1 = 4,
    Bls12381G1 = 5, Bls12381G2 = 6, P521 = 7
}
```

Keys are **raw `byte[]`** wrapped in small classes; there is no opaque key handle type.

```csharp
public sealed class KeyPair          // src/NetCrypto/KeyPair.cs
{
    public required KeyType KeyType { get; init; }
    public required byte[] PublicKey { get; init; }    // get returns a fresh defensive clone
    public required byte[] PrivateKey { get; init; }   // get returns a fresh defensive clone (zeroing caveat in docs)
    public string MultibasePublicKey { get; }
    public JsonWebKey ToPublicJwk();
    public JsonWebKey ToPrivateJwk();
}

public sealed class PublicKeyReference   // src/NetCrypto/PublicKeyReference.cs — public-only, returned by IKeyGenerator.FromPublicKey
{
    public required KeyType KeyType { get; init; }
    public required byte[] PublicKey { get; init; }
    public string MultibasePublicKey { get; }
}

public interface IKeyGenerator       // src/NetCrypto/IKeyGenerator.cs; impl: public sealed class DefaultKeyGenerator
{
    KeyPair Generate(KeyType keyType);
    KeyPair FromPrivateKey(KeyType keyType, ReadOnlySpan<byte> privateKey);
    PublicKeyReference FromPublicKey(KeyType keyType, ReadOnlySpan<byte> publicKey);   // validates length + EC on-curve
    KeyPair DeriveX25519FromEd25519(KeyPair ed25519KeyPair);
    PublicKeyReference DeriveX25519PublicKeyFromEd25519(ReadOnlySpan<byte> ed25519PublicKey);
}
```

**Canonical key encodings** (what `Generate`/`FromPrivateKey` produce, what `FromPublicKey`
demands, and what `KeyTypeExtensions.IsValidKeyLength` enforces):

| KeyType | Private key | Public key (canonical) |
|---|---|---|
| Ed25519 | 32-byte seed | raw 32 bytes |
| X25519 | raw 32 bytes | raw 32 bytes |
| P256 | raw 32-byte scalar `D` | **compressed SEC1**, 33 bytes |
| P384 | raw 48-byte scalar | compressed SEC1, 49 bytes |
| P521 | raw 66-byte scalar | compressed SEC1, 67 bytes |
| Secp256k1 | raw 32-byte scalar | compressed SEC1, 33 bytes |
| Bls12381G1 | 32-byte scalar (big-endian) | 48 bytes compressed G1 |
| Bls12381G2 | 32-byte scalar (big-endian) | 96 bytes compressed G2 |

Verify/ECDH inputs also accept uncompressed SEC1 (`0x04‖X‖Y`), but the key *model* stores
compressed only; `KeyTypeExtensions.NormalizeToCompressed` converts.

### Multikey/multicodec interop (via NetCid)

`public static class KeyTypeExtensions` (`src/NetCrypto/KeyTypeExtensions.cs`):

```csharp
public static ulong GetMulticodec(this KeyType keyType);            // → NetCid.Multicodec.Ed25519Pub / X25519Pub / P256Pub / P384Pub / P521Pub / Secp256k1Pub / Bls12381G1Pub / Bls12381G2Pub
public static KeyType FromMulticodec(ulong codec);                  // inverse; ArgumentException on unknown
public static bool IsValidKeyLength(this KeyType keyType, int length);
public static byte[] NormalizeToCompressed(this KeyType keyType, byte[] publicKey);
public static bool IsValidEcPoint(this KeyType keyType, byte[] rawKey);
```

Every `MultibasePublicKey` property is computed as
`NetCid.Multibase.Encode(NetCid.Multicodec.Prefix(KeyType.GetMulticodec(), publicKey), MultibaseEncoding.Base58Btc)`
— i.e. exactly the W3C **Multikey** `publicKeyMultibase` encoding. dataproofs decoding direction:
`Multibase.Decode` → strip/inspect multicodec via NetCid → `KeyTypeExtensions.FromMulticodec` →
raw key bytes. (NetCid also ships a `Multikey` type per the dataproofs PRD; that is NetCid
research, not covered here.)

### JWK boundary (`Microsoft.IdentityModel.Tokens.JsonWebKey`)

`public static class JwkConverter` (`src/NetCrypto/JwkConverter.cs`):

```csharp
public static JsonWebKey ToPublicJwk(KeyType keyType, byte[] publicKey);
public static JsonWebKey ToPublicJwk(KeyPair keyPair);
public static JsonWebKey ToPrivateJwk(KeyPair keyPair);                          // = ToPublicJwk + jwk.D (base64url, no padding)
public static (KeyType KeyType, byte[] PublicKey) ExtractPublicKey(JsonWebKey jwk);  // inverse of ToPublicJwk
```

- Mapping: Ed25519/X25519/BLS → `kty:"OKP"` with `crv` `"Ed25519"`/`"X25519"`/`"BLS12381G1"`/
  `"BLS12381G2"`, raw key in `x`; EC → `kty:"EC"`, `crv` `"P-256"`/`"P-384"`/`"P-521"`/
  `"secp256k1"`, decompressed `x`+`y` coordinates (compressed SEC1 input is decompressed
  internally). All coordinates base64url without prefix via NetCid.
- `ExtractPublicKey` reconstructs the canonical **compressed** SEC1 key
  (left-pads base64url-trimmed coordinates to the curve field width) and runs the
  **invalid-curve defense** (`EcPointValidator.EnsureOnCurve`) before returning — safe to feed
  its output straight into `DeriveSharedSecret`. Malformed JWKs throw `ArgumentException`
  (normalized, never `FormatException`).
- This is the `JsonWebKey` "boundary type" the dataproofs PRD allowlists in Core's public API
  (AC-7). NetCrypto's JWKs carry only `kty/crv/x/y/d` — `alg`/`kid`/`use` are dataproofs'
  responsibility.

Related public helper: `public static class EcPointValidator` with one public member,
`static void EnsureOnCurve(KeyType keyType, ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)` —
throws `CryptographicException` for off-curve/out-of-range/infinity points (P-256/P-384/P-521/
secp256k1; no-op for other key types).

## 6. Hashing and KDF statics

All in namespace `NetCrypto`; all stateless and thread-safe.

```csharp
public static class Hash    // src/NetCrypto/Hash.cs — SHA-2 (FIPS 180-4)
{
    public static byte[] Sha256(ReadOnlySpan<byte> data);                                         // 32 bytes
    public static bool   TrySha256(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten);
    public static byte[] Sha384(ReadOnlySpan<byte> data);                                         // 48 bytes
    public static bool   TrySha384(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten);
    public static byte[] Sha512(ReadOnlySpan<byte> data);                                         // 64 bytes
    public static bool   TrySha512(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten);
}
```

No SHA-3, no HMAC, and no incremental hashing are exposed. (Keccak below is *original* Keccak,
not FIPS 202.) If a suite ever needs SHA3-* or a standalone HMAC, that is a NetCrypto work item.

```csharp
public static class Keccak256   // src/NetCrypto/Keccak256.cs — ORIGINAL Keccak (Ethereum), NOT SHA3-256
{
    public static byte[] Hash(ReadOnlySpan<byte> data);                                           // 32 bytes
    public static bool   TryHash(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten);
}
```

```csharp
public static class Hkdf        // src/NetCrypto/Hkdf.cs — RFC 5869, SHA-256/384/512 only
{
    public static byte[] Extract(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt = default);
    public static byte[] Expand(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> prk, int outputLength, ReadOnlySpan<byte> info = default);
    public static byte[] DeriveKey(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> ikm, int outputLength, ReadOnlySpan<byte> salt = default, ReadOnlySpan<byte> info = default);
}
```

**Note:** the `hashAlgorithm` parameter is `System.Security.Cryptography.HashAlgorithmName`
(only `SHA256`/`SHA384`/`SHA512` accepted; anything else → `ArgumentException`). Calling `Hkdf`
therefore pulls the `HashAlgorithmName` *type* (a name struct, not a primitive) into dataproofs
source — the AC-6 hygiene gate must treat it like `CryptographicOperations.FixedTimeEquals`
(allowlisted symbol) or the gate will false-positive.

```csharp
public static class ConcatKdf   // src/NetCrypto/ConcatKdf.cs — NIST SP 800-56A §5.8.1 with SHA-256, per RFC 7518 §4.6
{
    public static byte[] DeriveKey(
        ReadOnlySpan<byte> sharedSecret,   // raw Z from DeriveSharedSecret; Ze‖Zs for ECDH-1PU
        ReadOnlySpan<byte> algorithmId,    // UTF-8 of JOSE "enc"/"alg" name, UNPREFIXED — 4-byte BE length prefix added internally
        ReadOnlySpan<byte> partyUInfo,     // apu, raw — length-prefixed internally; empty = absent
        ReadOnlySpan<byte> partyVInfo,     // apv, raw — length-prefixed internally; empty = absent
        ReadOnlySpan<byte> suppPubInfo,    // keydatalen in BITS as 32-bit BE int; ECDH-1PU appends the AEAD tag after it. Passed through VERBATIM (no prefix)
        ReadOnlySpan<byte> suppPrivInfo,   // verbatim; almost always empty for JOSE
        int keyDataLen);                   // output length in BYTES (16 for A128KW, 32 for A256GCM, ...)
}
```

Subtlety dataproofs' JWE port must respect: `algorithmId`/`partyUInfo`/`partyVInfo` get the
4-byte big-endian length prefix **inside** `DeriveKey` — pass raw values, not pre-prefixed ones
(didcomm-dotnet's own Concat-KDF prefixes manually; do not double-prefix when rerouting).
`suppPubInfo` is verbatim — the caller builds `[bits as 4-byte BE]` (e.g. `[0,0,0,0x80]` for 128).

## 7. AEAD / cipher / key-wrap statics

Uniform contract: `Encrypt` returns the named tuple `(byte[] Ciphertext, byte[] Tag)` —
ciphertext same length as plaintext (except CBC, which is PKCS#7-padded), tag separate.
`Decrypt` takes ciphertext and tag separately and throws
`System.Security.Cryptography.CryptographicException` on tag failure (all three AEADs normalize
to this; dataproofs' JWE decrypt path must catch it). Wrong key/nonce/tag *lengths* throw
`ArgumentException`. `associatedData` defaults to empty.

```csharp
public static class AesGcmCipher    // A256GCM, RFC 7518 §5.3 — key 32 B, nonce 12 B, tag 16 B
{
    public static (byte[] Ciphertext, byte[] Tag) Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default);
    public static byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> associatedData = default);
}

public static class AesCbcHmacCipher    // A256CBC-HS512, RFC 7518 §5.2.2 — key 64 B (MAC_KEY=first 32 ‖ ENC_KEY=last 32), IV 16 B, tag 32 B
{
    public static (byte[] Ciphertext, byte[] Tag) Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default);
    public static byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> associatedData = default);
    // tag = first 32 bytes of HMAC-SHA-512(MAC_KEY, AAD ‖ IV ‖ ciphertext ‖ AL), AL = AAD bit-length as 64-bit BE.
    // Decrypt verifies tag in constant time BEFORE any CBC decryption (no padding oracle).
}

public static class XChaCha20Poly1305Cipher    // XC20P, draft-irtf-cfrg-xchacha-03 — key 32 B, nonce 24 B, tag 16 B
{
    public static (byte[] Ciphertext, byte[] Tag) Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default);
    public static byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> associatedData = default);
    // NSec's combined [ciphertext‖tag] buffer is split/recombined internally; the public contract stays (ciphertext, tag).
}

public static class AesKeyWrap    // A256KW, RFC 3394 — 32-byte KEK only
{
    public static byte[] Wrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> keyData);     // keyData: multiple of 8, >= 16 bytes; output = keyData.Length + 8
    public static byte[] Unwrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> wrappedKey); // wrappedKey: multiple of 8, >= 24; CryptographicException on IV-integrity failure (constant-time)
}
```

Only the JOSE "256-strength" variants exist: there is **no A128GCM/A192GCM, no
A128CBC-HS256, no A128KW/A192KW**. dataproofs v1 JWE `enc`/`alg` support must be scoped to
`A256GCM`, `A256CBC-HS512`, `XC20P`, `A256KW` (+ ECDH-ES via §4/§6) or the gaps become NetCrypto
work items.

## 8. BBS — `IBbsCryptoProvider` / `DefaultBbsCryptoProvider`

Interface (bottom of `src/NetCrypto/ICryptoProvider.cs`):

```csharp
public interface IBbsCryptoProvider
{
    BbsCiphersuite Ciphersuite { get; }
    bool IsAvailable { get; }   // capability probe — NEVER throws; false ⇒ ops below throw BbsUnavailableException
    byte[] Sign(ReadOnlySpan<byte> privateKey, IReadOnlyList<byte[]> messages);
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature, IReadOnlyList<byte[]> messages);
    byte[] DeriveProof(ReadOnlySpan<byte> publicKey, byte[] signature, IReadOnlyList<byte[]> messages,
                       IReadOnlyList<int> revealedIndices, ReadOnlySpan<byte> nonce);
    bool VerifyProof(ReadOnlySpan<byte> publicKey, byte[] proof, IReadOnlyList<byte[]> revealedMessages,
                     IReadOnlyList<int> revealedIndices, ReadOnlySpan<byte> nonce);
}

public enum BbsCiphersuite { Bls12381Sha256 = 0 }   // BLS12-381-SHA-256 of draft-irtf-cfrg-bbs-signatures-10; only value in v1
```

Implementation `public sealed class DefaultBbsCryptoProvider : IBbsCryptoProvider`
(`src/NetCrypto/DefaultBbsCryptoProvider.cs`):

- **Obtain an instance:** `new DefaultBbsCryptoProvider()` (defaults to `Bls12381Sha256`;
  any other suite → `NotSupportedException`), or DI via `AddNetCrypto()`
  (`IBbsCryptoProvider` singleton).
- **Ciphersuite parameterization** is constructor-only:
  `public DefaultBbsCryptoProvider(BbsCiphersuite ciphersuite = BbsCiphersuite.Bls12381Sha256)`.
- **Capability model when native binaries are absent:** a static ctor probes
  `ZkryptiumNative.bbs_sk_to_pk` once per process; `DllNotFoundException` /
  `EntryPointNotFoundException` / `BadImageFormatException` ⇒ `IsAvailable == false` and every
  signature/proof operation throws
  **`NetCrypto.BbsUnavailableException : System.Security.Cryptography.CryptographicException`**
  (sealed; ctors `(string message)` and `(string message, Exception? innerException)`; the
  original load error rides as `InnerException`). `IsAvailable` itself never throws. dataproofs'
  `bbs-2023` suite should surface this as "suite unavailable on this platform", and its CI needs a
  BBS-absent leg mirroring NetCrypto's `no-native` job (`.github/workflows/build.yml`).
- **Sizes (BLS12-381-SHA-256, draft-10):** secret key 32 B, public key 96 B (G2), signature 80 B;
  proof = 272 + 32·U bytes (U = undisclosed count). `nonce` is arbitrary-length (the
  presentation header passed to proof_gen/proof_verify; the BBS *header* parameter is pinned
  empty inside the implementation).
- Validation: wrong pk size → `ArgumentException`; wrong signature size: `Sign`'s output is
  fixed, `Verify` returns `false`, `DeriveProof` throws; out-of-range or duplicate
  `revealedIndices` → `ArgumentOutOfRangeException`/`ArgumentException`; internal native failures
  → `CryptographicException`. `Verify`/`VerifyProof` return `bool` (rc==0), never throw for
  merely-invalid crypto.

## 9. Randomness

**NetCrypto exposes NO public randomness API.** The only randomness in the library is internal
(`System.Security.Cryptography.RandomNumberGenerator.Fill` inside `DefaultKeyGenerator` for
secp256k1/BLS key generation; NSec generates the rest). Confirmed against the full
`PublicAPI.Shipped.txt` — no `Random`/`Rng`/`SecureRandom` type exists.

Consequence: dataproofs' NFR-5 ("salts, IVs, ephemeral keys … MUST come from NetCrypto's
randomness, never `System.Random`") **cannot be satisfied as written today.** Options:
(a) file a NetCrypto work item for a `NetCrypto.SecureRandom`-style static (concept §6 route);
(b) amend the dataproofs allowlist to admit `System.Security.Cryptography.RandomNumberGenerator`
(a CSPRNG access point, not a keyed primitive — same category as `FixedTimeEquals`); ephemeral
*keys* specifically can already come from `IKeyGenerator.Generate(KeyType.X25519/P256/...)`,
which is the right call for JWE `epk` anyway. Salts/nonces/IVs are the open gap.

## 10. Samples-coverage tooling (the FR-17 precedent for dataproofs FR-21)

- **Tool:** `/Users/moises/Projects/crypto-dotnet/tools/ApiCoverageCheck/Program.cs`
  (+ `ApiCoverageCheck.csproj`). Top-level program that reflects over
  `typeof(NetCrypto.KeyType).Assembly.GetExportedTypes()` and requires every public type name and
  every public **declared** method/property name (BindingFlags `Public|Instance|Static|DeclaredOnly`;
  skips `IsSpecialName`, compiler-generated, and a fixed `inheritedNames` list of
  `Object`/`Enum`/`Delegate`/`Exception` members; enums and delegates need only the type name) to
  appear as an ordinal **substring** of the concatenation of `samples/**/*.cs`. The exemption
  list is an empty `string[] exemptions = [];` with a comment requiring a written
  `// justification:` per entry. Exit codes: 0 = covered, 1 = uncovered members (each printed as
  `UNCOVERED: Type.Member`), 2 = samples dir missing. `args[0]` = samples dir (default `samples`).
- **CI wiring:** `.github/workflows/build.yml` — (1) every `samples/*/` project is `dotnet run`
  and must exit 0 on all three OS legs; (2) then
  `dotnet run --project tools/ApiCoverageCheck --configuration Release --no-build -- samples`
  (line 67). A fourth `no-native` leg proves the BBS-absent supported mode.
- **Samples layout:** ten projects `samples/NetCrypto.Samples.{Keys,Signing,Signers,Hashing,KeyAgreement,Encryption,Jwk,EvmSigning,Bbs,DependencyInjection}`,
  indexed with a "start here" order in `samples/README.md`; no test frameworks allowed in
  `samples/` (CI greps for `xunit|NUnit|MSTest|FluentAssertions`). The PRD text is
  `netcrypto-prd.md` FR-17 (line ~264) — direct template for dataproofs FR-20/FR-21 and the
  `tasks/samples-coverage/` tooling (dataproofs plans it under `tasks/`, NetCrypto keeps it under
  `tools/`; the program itself ports with only the anchor type changed).

## 11. Misc surface dataproofs may touch

- `public static class Secp256k1Recoverable` (`src/NetCrypto/Secp256k1Recoverable.cs`):
  `static (byte[] Signature64, int RecoveryId) Sign(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> digest32)`
  and
  `static byte[] RecoverPublicKey(ReadOnlySpan<byte> digest32, ReadOnlySpan<byte> signature64, int recoveryId, bool compressed = false)`.
  Caller supplies the 32-byte digest (Keccak for EVM); raw recovery id 0–3 (no `v` encoding).
  Not needed for dataproofs v1 but in the surface.
- `KeyType` ↔ algorithm mapping dataproofs FR-13 needs: `EdDSA`→`Ed25519`, `ES256K`→`Secp256k1`
  (already 64-byte R‖S), `ES256`→`P256`, `ES384`→`P384` (both need P1363 — see §2 risk),
  `ES512`→`P521` (out of v1 scope).
- Exceptions summary: invalid arguments → `ArgumentException`/`ArgumentOutOfRangeException`;
  crypto failures (tag mismatch, unwrap integrity, ECDH failure, native BBS errors) →
  `CryptographicException`; BBS-absent → `BbsUnavailableException` (subclass of
  `CryptographicException`); verification of merely-invalid signatures → `false`, never a throw.
- `tasks/lessons.md` exists in crypto-dotnet; the repo follows the same agent workflow as
  dataproofs.

## 12. Risk register (PRD-assumption impacts)

1. **No P1363 via `ISigner`/`IKeyStore`** (§2): FR-2's "key-store signer sufficient for every
   suite" + FR-5/FR-11/FR-13's P1363 requirement cannot both be met for P-256/P-384 without
   either a local DER→P1363 transcoder in dataproofs or a NetCrypto API addition.
2. **No public randomness API** (§9): dataproofs NFR-5's "NetCrypto's randomness" does not exist;
   needs a NetCrypto work item or an allowlist amendment for `RandomNumberGenerator`.
3. **`Hkdf` signature leaks `System.Security.Cryptography.HashAlgorithmName`** into callers (§6):
   the AC-6 "no `System.Security.Cryptography` in src/" gate needs `HashAlgorithmName` (and
   `CryptographicException`/`BbsUnavailableException` catch sites) on its allowlist alongside
   `CryptographicOperations.FixedTimeEquals`.
4. **AEAD/key-wrap coverage is 256-bit-only** (§7): JWE algorithms beyond
   `A256GCM`/`A256CBC-HS512`/`XC20P`/`A256KW` (e.g. `A128KW`, `A128CBC-HS256` used by some
   interop fixtures) are absent — scope dataproofs v1 accordingly or file NetCrypto work items.
5. **No SHA-3/HMAC statics** (§6): fine for the v1 suites (all SHA-2), but any SD-JWT `_sd_alg`
   beyond sha-256/384/512 has no backing primitive.
6. **BBS is draft-10-pinned, single ciphersuite, G2 96-byte keys, native-binary dependent** (§8):
   `bbs-2023` work must degrade gracefully (`IsAvailable`) and CI needs a BBS-absent leg.
7. **Version is `1.0.0-preview.1`**: the API is analyzer-locked but pre-1.0; coordinate any
   NetCrypto additions (P1363 signer, randomness) before dataproofs pins a release version.
