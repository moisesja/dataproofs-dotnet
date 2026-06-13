namespace DataProofsDotnet.Jose;

/// <summary>
/// JOSE-shaped cryptographic surface used by the JWS/JWE builders and parsers. Methods dispatch
/// by JOSE algorithm identifier strings (<c>"EdDSA"</c>, <c>"ES256"</c>, <c>"A256GCM"</c>, etc.)
/// rather than enum types, matching the way JWE/JWS protected headers carry the values.
/// </summary>
/// <remarks>
/// Ported from didcomm-dotnet <c>DidComm.Crypto.ICryptoProvider</c> (PRD §1.4 item 2). The
/// default implementation <see cref="JoseCryptoProvider"/> delegates every primitive to
/// NetCrypto (PRD §2.2: no local crypto). Unlike the porting source this surface carries
/// <b>no signing member</b> — signing flows exclusively through
/// <see cref="Signing.JwsSigner"/> over a NetCrypto <c>ISigner</c>/<c>IKeyStore</c>, so no
/// public signing entry point ever takes raw private-key bytes (PRD AC-8). Verification and
/// the symmetric operations are synchronous (no I/O occurs; NFR-3).
/// </remarks>
public interface IJoseCryptoProvider
{
    /// <summary>Verify a JWS signature in JOSE wire format (Ed25519 raw 64-byte; ECDSA fixed-width R‖S per RFC 7515 §3.4).</summary>
    /// <param name="joseAlg">JOSE signing algorithm identifier.</param>
    /// <param name="publicKey">Raw public key bytes (OKP raw 32; EC compressed or uncompressed SEC1).</param>
    /// <param name="data">The signed data (JWS signing input).</param>
    /// <param name="signature">JOSE wire-format signature bytes.</param>
    bool Verify(string joseAlg, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    /// <summary>
    /// Compute the raw ECDH shared secret <c>Z</c> on the curve named by <paramref name="crv"/>.
    /// Returns the unprocessed shared secret (no KDF applied) — callers feed it (or
    /// <c>Ze ‖ Zs</c> for ECDH-1PU) into the Concat KDF (RFC 7518 §4.6).
    /// </summary>
    /// <param name="crv">JWK <c>crv</c> value — one of <c>"X25519"</c>, <c>"P-256"</c>, <c>"P-384"</c>, <c>"P-521"</c>.</param>
    /// <param name="privateKey">Raw private key bytes for the local party.</param>
    /// <param name="publicKey">Raw or SEC1-encoded public key bytes for the remote party.</param>
    byte[] DeriveSharedSecret(string crv, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey);

    /// <summary>Authenticated encryption with associated data.</summary>
    /// <param name="enc">JWE <c>enc</c> value — one of <c>"A256CBC-HS512"</c>, <c>"A256GCM"</c>, <c>"XC20P"</c>.</param>
    /// <param name="cek">Content-encryption key matching the algorithm's expected length.</param>
    /// <param name="iv">Initialization vector / nonce matching the algorithm's expected length.</param>
    /// <param name="aad">Associated data covered by the authentication tag but not encrypted.</param>
    /// <param name="plaintext">Data to encrypt.</param>
    (byte[] Ciphertext, byte[] Tag) AeadEncrypt(
        string enc,
        ReadOnlySpan<byte> cek,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> plaintext);

    /// <summary>Authenticated decryption.</summary>
    /// <param name="enc">JWE <c>enc</c> value used to produce <paramref name="ciphertext"/>.</param>
    /// <param name="cek">Content-encryption key.</param>
    /// <param name="iv">IV / nonce the ciphertext was produced with.</param>
    /// <param name="aad">Associated data the tag was computed over.</param>
    /// <param name="ciphertext">Ciphertext bytes.</param>
    /// <param name="tag">Authentication tag produced at encryption time.</param>
    byte[] AeadDecrypt(
        string enc,
        ReadOnlySpan<byte> cek,
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag);

    /// <summary>Wrap <paramref name="cek"/> under <paramref name="kek"/>.</summary>
    /// <param name="alg">Key-wrap algorithm — <c>"A256KW"</c> (RFC 3394) is the only supported value.</param>
    /// <param name="kek">Key-encryption key (32 bytes).</param>
    /// <param name="cek">Content-encryption key to wrap.</param>
    byte[] KeyWrap(string alg, ReadOnlySpan<byte> kek, ReadOnlySpan<byte> cek);

    /// <summary>Unwrap a CEK previously wrapped by <see cref="KeyWrap"/>.</summary>
    /// <param name="alg">Key-wrap algorithm used to produce <paramref name="wrapped"/>.</param>
    /// <param name="kek">Key-encryption key (32 bytes).</param>
    /// <param name="wrapped">Wrapped CEK as returned by <see cref="KeyWrap"/>.</param>
    byte[] KeyUnwrap(string alg, ReadOnlySpan<byte> kek, ReadOnlySpan<byte> wrapped);

    /// <summary>Cryptographically secure RNG suitable for CEKs and IVs (NFR-5).</summary>
    /// <param name="destination">Buffer to fill with random bytes.</param>
    void Fill(Span<byte> destination);
}
