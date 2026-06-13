# AC-5 Parity Suite — didcomm-dotnet JWS/JWE behavior-parity port

- **Source repository:** `didcomm-dotnet` (local clone `/Users/moises/Projects/didcomm-dotnet`)
- **Source commit SHA:** `e98570cd2901ec9704a68c7587b063e597aa683e` (HEAD at port time, working tree clean; matches `tasks/research/didcomm-jose.md`)
- **Port date:** 2026-06-12
- **Contract (PRD AC-5):** test files copied with only namespace/using changes, type and member
  renames required by the new public API, and test-framework attribute namespaces.
  **Assertion content (expected values, asserted properties, fixture bytes) is unchanged.**
  The `tasks/parity-diff` tool (Phase F) normalizes identifiers per the rename table below and
  fails on any difference in literals or asserted structure.

## File map (ported file → source path at `e98570cd…`)

| Ported file (`tests/DataProofsDotnet.Jose.Tests/Parity/`) | Source path (`tests/DidComm.Core.Tests/`) |
|---|---|
| `JwsRoundTripTests.cs` | `Envelopes/Signing/JwsRoundTripTests.cs` |
| `AnoncryptRoundTripTests.cs` | `Envelopes/Encryption/AnoncryptRoundTripTests.cs` |
| `AuthcryptRoundTripTests.cs` | `Envelopes/Encryption/AuthcryptRoundTripTests.cs` |
| `ApuComputerTests.cs` | `Envelopes/Encryption/ApuComputerTests.cs` |
| `ApvComputerTests.cs` | `Envelopes/Encryption/ApvComputerTests.cs` |
| `EphemeralKeyPairTests.cs` | `Envelopes/Encryption/EphemeralKeyPairTests.cs` |
| `JwkConversionTests.cs` | `Envelopes/Encryption/JwkConversionTests.cs` |
| `Ecdh1PuKdfTests.cs` | `Crypto/Kdf/Ecdh1PuKdfTests.cs` |
| `EcdhEsKdfTests.cs` | `Crypto/Kdf/EcdhEsKdfTests.cs` |
| `AesCbcHmacSha512Tests.cs` | `Crypto/Aead/AesCbcHmacSha512Tests.cs` |
| `AesGcmAeadTests.cs` | `Crypto/Aead/AesGcmAeadTests.cs` |
| `XChaCha20Poly1305AeadTests.cs` | `Crypto/Aead/XChaCha20Poly1305AeadTests.cs` |
| `AesKeyWrapTests.cs` | `Crypto/KeyWrap/AesKeyWrapTests.cs` |
| `KeyTypeMapperTests.cs` | `Crypto/KeyAgreement/KeyTypeMapperTests.cs` |
| `TestKeyMaterial.cs` (support) | `Envelopes/TestKeyMaterial.cs` |
| `Hex.cs` (support) | `Hex.cs` |
| `AeadShims.cs` (support, new) | — (rename seam; see "Support-file adaptations") |
| `../GlobalUsings.cs` (support) | `GlobalUsings.cs` |

## Rename table (machine-readable, for `tasks/parity-diff`)

```parity-rename-map
# old-identifier -> new-identifier   (applies to both code and assertion text normalization)
DidComm.Tests -> DataProofsDotnet.Jose.Tests
DidComm.Jose -> DataProofsDotnet.Jose
DidComm.Jose.Signing -> DataProofsDotnet.Jose.Signing
DidComm.Jose.Encryption -> DataProofsDotnet.Jose.Encryption
DidComm.Crypto -> DataProofsDotnet.Jose
DidComm.Crypto.Kdf -> DataProofsDotnet.Jose.Encryption
DidComm.Crypto.KeyAgreement -> DataProofsDotnet.Jose
DidComm.Crypto.Aead -> DataProofsDotnet.Jose.Tests.Crypto.Aead
DidComm.Crypto.KeyWrap -> NetCrypto
DidComm.Exceptions.MalformedMessageException -> DataProofsDotnet.Jose.MalformedJoseException
DidComm.Exceptions.CryptoException -> DataProofsDotnet.Jose.JoseCryptoException
MalformedMessageException -> MalformedJoseException
CryptoException -> JoseCryptoException
DidComm.Crypto.DefaultCryptoProvider -> DataProofsDotnet.Jose.JoseCryptoProvider
DidCommDefaultCryptoProvider -> JoseDefaultCryptoProvider
NetDid.Core.Crypto.KeyType -> NetCrypto.KeyType
NetDid.Core.Crypto.DefaultKeyGenerator -> NetCrypto.DefaultKeyGenerator
NetDid.Core.Crypto.DefaultCryptoProvider -> NetCrypto.DefaultCryptoProvider
NetDid.Core.ICryptoProvider -> NetCrypto.ICryptoProvider
NetDid.Core.Crypto.Kdf.ConcatKdf -> NetCrypto.ConcatKdf
NetDidConcatKdf -> NetCryptoConcatKdf
NetDidCryptoProvider -> NetCryptoProvider
_netDid -> _netCrypto
JweBuilder.PackAnoncrypt -> JweBuilder.BuildEcdhEsA256Kw
JweBuilder.PackAuthcrypt -> JweBuilder.BuildEcdh1PuA256Kw
JwsBuilder.Build -> JwsBuilder.BuildJsonAsync
JwsParser.Parse -> JwsParser.Parse
JwkConversion.ToNetDidJwk -> JwkConversion.ToJsonWebKey
IInternalSecretsLookup -> IJweRecipientKeyResolver
IInternalSenderKeyLookup -> IJweSenderKeyResolver
secretsLookup -> recipientKeys
senderLookup -> senderKeys
cryptoProvider.NetDidProvider -> cryptoProvider.UnderlyingProvider
_crypto.NetDidProvider -> _crypto.UnderlyingProvider
AesCbcHmacSha512 -> AesCbcHmacSha512   # test-local shim over NetCrypto.AesCbcHmacCipher
AesGcmAead -> AesGcmAead               # test-local shim over NetCrypto.AesGcmCipher
XChaCha20Poly1305Aead -> XChaCha20Poly1305Aead  # test-local shim over NetCrypto.XChaCha20Poly1305Cipher
AesKeyWrap -> NetCrypto.AesKeyWrap     # local RFC 3394 impl deleted (AC-6); same static names/arg order
signer.PrivateJwk (as JwsBuilder argument) -> signer.Signer  # JwsBuilder signs via NetCrypto ISigner (AC-8)
result.Message.Id -> JsonDocument payload property "id"      # Message-payload adaptation, see below
result.Message.From -> JsonDocument payload property "from"  # Message-payload adaptation, see below
```

## Sanctioned adaptations (per AC-5 "allowed modifications" + research note §7/§9)

1. **Async signing call shape.** The dataproofs `JwsBuilder` signs through NetCrypto
   `ISigner` (NFR-3/AC-8), so `JwsBuilder.Build(...)` became `await JwsBuilder.BuildJsonAsync(...)`
   and the affected test methods became `async Task`. Assertion content unchanged.
2. **Message-payload adaptation.** The porting source signed a DIDComm `Message` built with
   `MessageBuilder`; dataproofs signs arbitrary bytes (FR-13). The same logical content travels
   as a JSON payload (`{"id":"m1","type":…,"from":…,"to":[…]}`), and the
   `result.Message.Id`/`result.Message.From` assertions read the identical values from the
   parsed payload JSON. Expected values unchanged.
3. **Argument-name renames** required by the new API surface (`senderLookup:` → `senderKeys:`)
   — call-site arrangement only.

## Support-file adaptations

- `TestKeyMaterial.cs` — rewired from net-did's `DefaultKeyGenerator`/`JwkConverter` to
  NetCrypto's; gains a `Signer` property (`JwsSigner` over `KeyPairSigner`) because dataproofs'
  builder never consumes a private JWK's `d` (AC-8). `DictionarySecretsLookup` /
  `DictionarySenderKeyLookup` now implement the renamed resolver interfaces.
- `AeadShims.cs` — **new support file.** The porting source's `IAead` instance classes
  (`AesCbcHmacSha512`, `AesGcmAead`, `XChaCha20Poly1305Aead`) were deleted from production code
  per AC-6 (every AEAD must be a NetCrypto cipher static). The shims reproduce the deleted
  classes' instance surface in the test project only, delegating every operation to
  `NetCrypto.AesCbcHmacCipher` / `AesGcmCipher` / `XChaCha20Poly1305Cipher`, so the ported AEAD
  tests keep their call shape and assertion content (including the
  `*tag verification failed*` message globs, which NetCrypto's exception text satisfies).
- `Hex.cs`, `GlobalUsings.cs` — copied as-is (namespace only).

## Intentionally omitted source tests (with justification)

| Source file / test | Reason |
|---|---|
| `JwsRoundTripTests.Sign_then_encrypt_inner_to_required_throws_when_missing` and `…_passes_when_present` | Assert DIDComm FR-SIG-06 (`requireInnerToHeader` anti-surreptitious-forwarding rule on the DIDComm `to` header) — DIDComm protocol semantics, not JOSE; the parameter does not exist in the generic FR-13 builder. |
| `JwsRoundTripTests.Consistency_check_blocks_mismatched_signer_kid` | Asserts DIDComm FR-CONSIST-03 (signer kid ↔ plaintext `from` agreement), a DIDComm addressing rule executed by `AddressingConsistency` — not part of generic JOSE; the seam was deliberately not ported (research note §2e). |
| `Envelopes/Encryption/EnvelopeDetectorTests.cs` (whole file) | Exercises `EnvelopeDetector`/`EnvelopeKind`, DIDComm's envelope-classification facade. dataproofs ships no detector (DIDComm-profile feature); its JOSE-relevant parsing coverage is duplicated by the JWS/JWE parser tests. |
| `Envelopes/Composition/EnvelopeReaderTests.cs` (Tier 3, whole file) | Exercises `DidComm.Composition.EnvelopeWriter`/`EnvelopeReader` — the DIDComm facade above the JOSE layer (plaintext/signed/encrypted classification, FR-CONSIST-01/02, recursive unwrap). Heavily DIDComm-semantic; its JOSE-relevant coverage is duplicated by Tier 1 (research note §7 recommendation). |

## Behavioral deltas sanctioned by the PRD (visible to parity tests only as extensions)

- `JweProtectedHeader.Apv` is optional in dataproofs (generic JOSE); the didcomm
  recipient-list commitment check still runs whenever `apv` is present, so every ported
  assertion (including the apv-tamper negative) behaves identically — envelopes built by the
  ported builders always carry `apv`.
- The dataproofs parser additionally accepts `alg="A256KW"` and compact serializations; the
  ported tests never produce those, so no assertion is affected.
