using System.Buffers.Binary;
using System.Security.Cryptography;
using NetCrypto;

namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// ECDH-ES key derivation for JOSE (RFC 7518 §4.6). Performs a single raw ECDH
/// (ephemeral × recipient) and feeds the result into NetCrypto's Concat KDF with a
/// tag-free <c>SuppPubInfo = BE32(keyDataLen * 8)</c>.
/// </summary>
/// <remarks>
/// <para>
/// Ported from didcomm-dotnet <c>DidComm.Crypto.Kdf.EcdhEsKdf</c> (PRD §1.4 item 2), rerouted
/// to NetCrypto's <c>DeriveSharedSecret</c> (raw Z) + <c>ConcatKdf</c> (NIST SP 800-56A —
/// <b>not</b> HKDF, per RFC 7518 §4.6). NetCrypto's <c>ConcatKdf</c> length-prefixes
/// <c>algorithmId</c>/<c>partyUInfo</c>/<c>partyVInfo</c> internally and passes
/// <c>suppPubInfo</c> through verbatim, so callers supply raw values.
/// </para>
/// <list type="bullet">
///   <item>ECDH-ES → <c>EcdhEsKdf.DeriveKey</c> (Ze only, no tag).</item>
///   <item>ECDH-1PU → <see cref="Ecdh1PuKdf.DeriveKey"/> (Ze ‖ Zs, tag in SuppPubInfo).</item>
/// </list>
/// </remarks>
internal static class EcdhEsKdf
{
    /// <summary>Derive the wrapping key for ECDH-ES+A256KW.</summary>
    /// <param name="cryptoProvider">The NetCrypto provider supplying raw ECDH.</param>
    /// <param name="curve">Curve for the ECDH (must match ephemeral, recipient).</param>
    /// <param name="ephemeralPrivateKey">Per-message ephemeral private key (matches <c>epk</c>).</param>
    /// <param name="recipientPublicKey">Recipient's public key.</param>
    /// <param name="algorithmId">UTF-8 of the JOSE <c>alg</c> (<c>"ECDH-ES+A256KW"</c>).</param>
    /// <param name="apv">PartyVInfo (recipient info).</param>
    /// <param name="keyDataLen">Wrapping-key length in bytes (32 for A256KW).</param>
    /// <returns><paramref name="keyDataLen"/> bytes of derived keying material.</returns>
    public static byte[] DeriveKey(
        NetCrypto.ICryptoProvider cryptoProvider,
        KeyType curve,
        ReadOnlySpan<byte> ephemeralPrivateKey,
        ReadOnlySpan<byte> recipientPublicKey,
        ReadOnlySpan<byte> algorithmId,
        ReadOnlySpan<byte> apv,
        int keyDataLen)
        => DeriveKeyCore(cryptoProvider, curve, ephemeralPrivateKey, recipientPublicKey, algorithmId, ReadOnlySpan<byte>.Empty, apv, keyDataLen);

    /// <summary>
    /// Derive the key with an explicit <c>apu</c> (PartyUInfo). Generic JOSE ECDH-ES allows the
    /// producer to set both <c>apu</c> and <c>apv</c> (RFC 7518 §4.6.1); the apu-less overload
    /// above preserves the didcomm porting source's anoncrypt profile (empty PartyUInfo).
    /// </summary>
    /// <param name="cryptoProvider">The NetCrypto provider supplying raw ECDH.</param>
    /// <param name="curve">Curve for the ECDH.</param>
    /// <param name="ephemeralPrivateKey">Per-message ephemeral private key (matches <c>epk</c>).</param>
    /// <param name="recipientPublicKey">Recipient's public key.</param>
    /// <param name="algorithmId">UTF-8 of the JOSE <c>alg</c> (key-wrap modes) or <c>enc</c> (direct mode).</param>
    /// <param name="apu">PartyUInfo (producer info).</param>
    /// <param name="apv">PartyVInfo (recipient info).</param>
    /// <param name="keyDataLen">Derived-key length in bytes.</param>
    public static byte[] DeriveKey(
        NetCrypto.ICryptoProvider cryptoProvider,
        KeyType curve,
        ReadOnlySpan<byte> ephemeralPrivateKey,
        ReadOnlySpan<byte> recipientPublicKey,
        ReadOnlySpan<byte> algorithmId,
        ReadOnlySpan<byte> apu,
        ReadOnlySpan<byte> apv,
        int keyDataLen)
        => DeriveKeyCore(cryptoProvider, curve, ephemeralPrivateKey, recipientPublicKey, algorithmId, apu, apv, keyDataLen);

    /// <summary>
    /// Receive-side variant. By DH commutativity the recipient computes the same KEK using
    /// <c>ECDH(recipient_priv, ephemeral_pub)</c> instead of <c>ECDH(ephemeral_priv, recipient_pub)</c>.
    /// </summary>
    /// <param name="cryptoProvider">The NetCrypto provider supplying raw ECDH.</param>
    /// <param name="curve">Curve for the ECDH.</param>
    /// <param name="recipientPrivateKey">Recipient's own private key.</param>
    /// <param name="ephemeralPublicKey">Ephemeral public key from the JWE protected header <c>epk</c>.</param>
    /// <param name="algorithmId">UTF-8 of the JOSE <c>alg</c> (<c>"ECDH-ES+A256KW"</c>).</param>
    /// <param name="apv">PartyVInfo.</param>
    /// <param name="keyDataLen">Wrapping-key length in bytes (32 for A256KW).</param>
    public static byte[] DeriveKeyForReceiver(
        NetCrypto.ICryptoProvider cryptoProvider,
        KeyType curve,
        ReadOnlySpan<byte> recipientPrivateKey,
        ReadOnlySpan<byte> ephemeralPublicKey,
        ReadOnlySpan<byte> algorithmId,
        ReadOnlySpan<byte> apv,
        int keyDataLen)
        => DeriveKeyCore(cryptoProvider, curve, recipientPrivateKey, ephemeralPublicKey, algorithmId, ReadOnlySpan<byte>.Empty, apv, keyDataLen);

    /// <summary>Receive-side variant with an explicit <c>apu</c> (PartyUInfo).</summary>
    /// <param name="cryptoProvider">The NetCrypto provider supplying raw ECDH.</param>
    /// <param name="curve">Curve for the ECDH.</param>
    /// <param name="recipientPrivateKey">Recipient's own private key.</param>
    /// <param name="ephemeralPublicKey">Ephemeral public key from the JWE protected header <c>epk</c>.</param>
    /// <param name="algorithmId">UTF-8 of the JOSE <c>alg</c> or <c>enc</c>.</param>
    /// <param name="apu">PartyUInfo (producer info, decoded from the header's <c>apu</c>).</param>
    /// <param name="apv">PartyVInfo.</param>
    /// <param name="keyDataLen">Derived-key length in bytes.</param>
    public static byte[] DeriveKeyForReceiver(
        NetCrypto.ICryptoProvider cryptoProvider,
        KeyType curve,
        ReadOnlySpan<byte> recipientPrivateKey,
        ReadOnlySpan<byte> ephemeralPublicKey,
        ReadOnlySpan<byte> algorithmId,
        ReadOnlySpan<byte> apu,
        ReadOnlySpan<byte> apv,
        int keyDataLen)
        => DeriveKeyCore(cryptoProvider, curve, recipientPrivateKey, ephemeralPublicKey, algorithmId, apu, apv, keyDataLen);

    /// <summary>
    /// Receive-side variant for an <b>opaque</b> recipient key (issue #13). The ECDH runs inside the
    /// <see cref="IEcdhKey"/> (which may be HSM/keystore-backed and never exposes its scalar); the
    /// derived secret is fed through the same Concat KDF as the sync path, so the wrapping key is
    /// byte-identical.
    /// </summary>
    /// <param name="recipientKey">The recipient's opaque ECDH key.</param>
    /// <param name="ephemeralPublicKey">Ephemeral public key from the JWE protected header <c>epk</c>.</param>
    /// <param name="algorithmId">UTF-8 of the JOSE <c>alg</c>.</param>
    /// <param name="apu">PartyUInfo.</param>
    /// <param name="apv">PartyVInfo.</param>
    /// <param name="keyDataLen">Wrapping-key length in bytes (32 for A256KW).</param>
    /// <param name="ct">Cancellation token for the (possibly I/O-bound) derivation.</param>
    public static async ValueTask<byte[]> DeriveKeyForReceiverAsync(
        IEcdhKey recipientKey,
        ReadOnlyMemory<byte> ephemeralPublicKey,
        ReadOnlyMemory<byte> algorithmId,
        ReadOnlyMemory<byte> apu,
        ReadOnlyMemory<byte> apv,
        int keyDataLen,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(recipientKey);
        var z = await recipientKey.DeriveAsync(ephemeralPublicKey, ct).ConfigureAwait(false);
        return FinishConcatKdf(z, algorithmId.Span, apu.Span, apv.Span, keyDataLen);
    }

    private static byte[] DeriveKeyCore(
        NetCrypto.ICryptoProvider cryptoProvider,
        KeyType curve,
        ReadOnlySpan<byte> ownPrivateKey,
        ReadOnlySpan<byte> peerPublicKey,
        ReadOnlySpan<byte> algorithmId,
        ReadOnlySpan<byte> apu,
        ReadOnlySpan<byte> apv,
        int keyDataLen)
    {
        ArgumentNullException.ThrowIfNull(cryptoProvider);
        var z = cryptoProvider.DeriveSharedSecret(curve, ownPrivateKey, peerPublicKey);
        return FinishConcatKdf(z, algorithmId, apu, apv, keyDataLen);
    }

    /// <summary>
    /// The shared post-ECDH assembly: tag-free <c>SuppPubInfo = BE32(keyDataLen * 8)</c> then the
    /// Concat KDF. Both the sync and opaque-async cores funnel through here so the derived key is
    /// identical regardless of how <paramref name="z"/> was obtained. Zeroizes <paramref name="z"/>.
    /// </summary>
    private static byte[] FinishConcatKdf(
        byte[] z,
        ReadOnlySpan<byte> algorithmId,
        ReadOnlySpan<byte> apu,
        ReadOnlySpan<byte> apv,
        int keyDataLen)
    {
        var suppPubInfo = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(suppPubInfo, checked((uint)keyDataLen * 8U));

        try
        {
            return ConcatKdf.DeriveKey(
                sharedSecret: z,
                algorithmId: algorithmId,
                partyUInfo: apu,
                partyVInfo: apv,
                suppPubInfo: suppPubInfo,
                suppPrivInfo: ReadOnlySpan<byte>.Empty,
                keyDataLen: keyDataLen);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(z);
        }
    }
}
