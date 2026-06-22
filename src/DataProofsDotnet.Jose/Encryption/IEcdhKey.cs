namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// An ECDH key-agreement handle the JWE builder/parser can call without ever seeing the private
/// scalar. It performs the raw ECDH against a peer public key and returns the unhashed shared
/// secret <c>Z</c>; everything after <c>Z</c> (Concat KDF, key-wrap, AEAD) stays in this package and
/// uses only public/derived data. This is the seam that lets an <b>opaque</b> private key — held in
/// an HSM, cloud KMS, OS keychain, or <c>NetCrypto.IKeyStore</c> — participate in JWE
/// <c>ECDH-ES</c>/<c>ECDH-1PU</c> decryption and authcrypt sending.
/// </summary>
/// <remarks>
/// <para>
/// The handle is deliberately minimal and <b>DID-agnostic</b>: it carries only a self-describing
/// curve and a derive callback — no <c>kid</c>, DID, or keystore concept leaks into
/// <c>DataProofsDotnet.Jose</c>. The raw-bytes implementation that ships here is
/// <see cref="RawEcdhKey"/>; an opaque (keystore-backed) implementation lives in the consuming layer
/// and typically wraps <c>NetCrypto.IKeyStore.DeriveSharedSecretAsync</c>.
/// </para>
/// <para>
/// <see cref="DeriveAsync"/> may be invoked more than once for a single decrypt — ECDH-1PU derives
/// two secrets (<c>Ze</c> against the ephemeral public key, then <c>Zs</c> against the sender's
/// static public key) — so implementations must support repeated invocation. ECDH key agreement is
/// naturally idempotent, so this is a non-constraint for HSM/keystore backings.
/// </para>
/// </remarks>
public interface IEcdhKey
{
    /// <summary>The JWK <c>crv</c> this key agrees on (<c>X25519</c>, <c>P-256</c>, <c>P-384</c>, or <c>P-521</c>).</summary>
    string Crv { get; }

    /// <summary>
    /// Compute the raw ECDH shared secret <c>Z</c> between this private key and
    /// <paramref name="peerPublicKey"/>. <b>No KDF, truncation, or normalization</b> is applied —
    /// byte-identical to <see cref="IJoseCryptoProvider.DeriveSharedSecret"/>.
    /// </summary>
    /// <param name="peerPublicKey">The peer's public key in this curve's canonical encoding: raw
    /// 32 bytes for X25519; SEC1 (compressed <c>0x02</c>/<c>0x03 || X</c> or uncompressed
    /// <c>0x04 || X || Y</c>) for the NIST curves. The caller assembles it from the JWE
    /// <c>epk</c>/sender public key.</param>
    /// <param name="ct">A token to cancel the (possibly I/O-bound) derivation.</param>
    /// <returns>The raw shared secret <c>Z</c>.</returns>
    ValueTask<byte[]> DeriveAsync(ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct = default);
}
