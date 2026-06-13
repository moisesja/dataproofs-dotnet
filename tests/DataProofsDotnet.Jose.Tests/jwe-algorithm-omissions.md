# JWE algorithm omissions (AC-3 step 4 — FR-14 ↔ NetCrypto equivalence checkpoint)

This file is machine-read by `Conformance/NetCryptoEquivalenceTests.cs`. Every standard JOSE
JWE algorithm that **could** be composed from NetCrypto v1's published primitive surface but is
**not** registered by `DataProofsDotnet.Jose` must appear in exactly one table below with a
reason. The checkpoint fails on any NetCrypto-backable algorithm that is neither registered nor
listed here, and on any listed algorithm that is in fact registered.

Format contract: the tool consumes the first backtick-quoted token of each table row.

## Omitted key-management (`alg`) algorithms

| Algorithm | Reason |
|---|---|
| `dir` | Direct use of a shared symmetric CEK needs no primitive at all (trivially "backable"), but v1 has no consumer: the didcomm porting source never uses it, and the stack's key-distribution story is key agreement (ECDH-ES/1PU) or A256KW. Deliberately out of v1 scope (PRD FR-14 lists the composed set exhaustively). |
| `ECDH-ES` | Direct key agreement (no key wrap) is backable via `DeriveSharedSecret` + `ConcatKdf`, and the KDF itself ships and is vector-tested (RFC 7518 Appendix C, AC-3). The envelope-level mode is omitted in v1: no stack consumer uses it (didcomm pins +A256KW), and multi-recipient JWEs — the FR-14 headline feature — are impossible with direct agreement (one CEK per recipient). |
| `ECDH-1PU` | Same as `ECDH-ES`: direct-mode 1PU (draft-madden-04 Appendix A) is KDF-backable and the KDF path is vector-tested, but the envelope mode is single-recipient-only and unused by the didcomm adoption, which mandates the +A256KW key-wrap mode. |

## Omitted content-encryption (`enc`) algorithms

*(none — every NetCrypto AEAD (`AesGcmCipher`, `AesCbcHmacCipher`, `XChaCha20Poly1305Cipher`)
is registered as its JOSE algorithm: `A256GCM`, `A256CBC-HS512`, `XC20P`.)*

## Not backable by NetCrypto v1 (listed for completeness; NOT omissions)

These standard JWE algorithms have **no** NetCrypto v1 primitive, so the checkpoint derives no
expectation for them (the gap is a NetCrypto work item per concept §6, not a Jose omission):
`A128KW`/`A192KW` (AesKeyWrap is 32-byte-KEK only), `A128GCM`/`A192GCM`,
`A128CBC-HS256`/`A192CBC-HS384`, `A128GCMKW`/`A192GCMKW`/`A256GCMKW` (no AES-GCM key-wrap
primitive), `PBES2-*` (no PBKDF2), `RSA1_5`/`RSA-OAEP*` (no RSA, PRD §11), and the
`ECDH-ES+A128KW`/`+A192KW` / `ECDH-1PU+A128KW`/`+A192KW` variants (blocked on the missing
128/192-bit AES-KW).
