using System.Buffers.Binary;
using System.Security.Cryptography;
using NetCrypto;

namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// ECDH-1PU key derivation for JOSE authenticated encryption
/// (<c>draft-madden-jose-ecdh-1pu-04 §2</c>, the pin required by the future didcomm adoption —
/// PRD FR-14). Composes <c>Z = Ze ‖ Zs</c> from two raw ECDH computations (ephemeral ×
/// recipient, then sender-static × recipient), then runs NetCrypto's Concat KDF with the AEAD
/// authentication tag bound into <c>SuppPubInfo</c>.
/// </summary>
/// <remarks>
/// <para>
/// Ported from didcomm-dotnet <c>DidComm.Crypto.Kdf.Ecdh1PuKdf</c> (PRD §1.4 item 2). The
/// underlying primitives — raw ECDH and the Concat KDF itself — live in NetCrypto; this class
/// only owns the 1PU-specific orchestration.
/// </para>
/// <para>
/// <c>SuppPubInfo</c> layout per draft-madden §2.3:
/// </para>
/// <code>
/// SuppPubInfo = BE32(keyDataLen * 8) ‖ BE32(tag.Length) ‖ AEAD_tag   (tag block omitted when empty)
/// </code>
/// <para>
/// The 4-byte tag-length prefix is load-bearing: omitting it round-trips locally but breaks
/// interop with every external 1PU implementation (askar/SICPA).
/// </para>
/// </remarks>
internal static class Ecdh1PuKdf
{
    /// <summary>Derive the wrapping key for ECDH-1PU+A256KW (send side).</summary>
    /// <param name="cryptoProvider">The NetCrypto provider supplying raw ECDH.</param>
    /// <param name="curve">Curve for both ECDH operations (must match for sender, ephemeral, recipient).</param>
    /// <param name="senderPrivateKey">The sender's static private key (matches <c>skid</c>).</param>
    /// <param name="ephemeralPrivateKey">The per-message ephemeral private key (matches <c>epk</c>).</param>
    /// <param name="recipientPublicKey">The recipient's public key.</param>
    /// <param name="algorithmId">UTF-8 of the JOSE <c>alg</c> for which the wrapping key is derived
    ///   (e.g. <c>"ECDH-1PU+A256KW"</c>). Length-prefixed inside the Concat KDF.</param>
    /// <param name="apu">PartyUInfo (sender info). Length-prefixed inside the Concat KDF.</param>
    /// <param name="apv">PartyVInfo (recipient info). Length-prefixed inside the Concat KDF.</param>
    /// <param name="aeadTag">The AEAD authentication tag from the just-completed content encryption.
    ///   Pass <see cref="ReadOnlySpan{T}.Empty"/> for the direct-mode derivation that does not
    ///   bind a tag.</param>
    /// <param name="keyDataLen">Wrapping-key length in bytes (32 for A256KW).</param>
    /// <returns><paramref name="keyDataLen"/> bytes of derived keying material.</returns>
    public static byte[] DeriveKey(
        NetCrypto.ICryptoProvider cryptoProvider,
        KeyType curve,
        ReadOnlySpan<byte> senderPrivateKey,
        ReadOnlySpan<byte> ephemeralPrivateKey,
        ReadOnlySpan<byte> recipientPublicKey,
        ReadOnlySpan<byte> algorithmId,
        ReadOnlySpan<byte> apu,
        ReadOnlySpan<byte> apv,
        ReadOnlySpan<byte> aeadTag,
        int keyDataLen)
        => DeriveKeyCore(
            cryptoProvider, curve,
            firstZPriv: ephemeralPrivateKey, firstZPub: recipientPublicKey,
            secondZPriv: senderPrivateKey, secondZPub: recipientPublicKey,
            algorithmId, apu, apv, aeadTag, keyDataLen);

    /// <summary>
    /// Receive-side variant. DH commutativity gives the recipient the same KEK using their own
    /// private key against the ephemeral and sender public keys:
    /// <c>Ze = ECDH(recipient_priv, ephemeral_pub)</c>, <c>Zs = ECDH(recipient_priv, sender_pub)</c>.
    /// </summary>
    /// <param name="cryptoProvider">The NetCrypto provider supplying raw ECDH.</param>
    /// <param name="curve">Curve for both ECDH operations.</param>
    /// <param name="recipientPrivateKey">Recipient's own private key.</param>
    /// <param name="ephemeralPublicKey">Ephemeral public key from the JWE protected header <c>epk</c>.</param>
    /// <param name="senderPublicKey">Sender static public key resolved via <c>skid</c>/<c>apu</c>.</param>
    /// <param name="algorithmId">UTF-8 of the JOSE <c>alg</c> (<c>"ECDH-1PU+A256KW"</c>).</param>
    /// <param name="apu">PartyUInfo (sender info).</param>
    /// <param name="apv">PartyVInfo (recipient info).</param>
    /// <param name="aeadTag">AEAD authentication tag from the received envelope.</param>
    /// <param name="keyDataLen">Wrapping-key length in bytes (32 for A256KW).</param>
    public static byte[] DeriveKeyForReceiver(
        NetCrypto.ICryptoProvider cryptoProvider,
        KeyType curve,
        ReadOnlySpan<byte> recipientPrivateKey,
        ReadOnlySpan<byte> ephemeralPublicKey,
        ReadOnlySpan<byte> senderPublicKey,
        ReadOnlySpan<byte> algorithmId,
        ReadOnlySpan<byte> apu,
        ReadOnlySpan<byte> apv,
        ReadOnlySpan<byte> aeadTag,
        int keyDataLen)
        => DeriveKeyCore(
            cryptoProvider, curve,
            firstZPriv: recipientPrivateKey, firstZPub: ephemeralPublicKey,
            secondZPriv: recipientPrivateKey, secondZPub: senderPublicKey,
            algorithmId, apu, apv, aeadTag, keyDataLen);

    private static byte[] DeriveKeyCore(
        NetCrypto.ICryptoProvider cryptoProvider,
        KeyType curve,
        ReadOnlySpan<byte> firstZPriv, ReadOnlySpan<byte> firstZPub,
        ReadOnlySpan<byte> secondZPriv, ReadOnlySpan<byte> secondZPub,
        ReadOnlySpan<byte> algorithmId,
        ReadOnlySpan<byte> apu,
        ReadOnlySpan<byte> apv,
        ReadOnlySpan<byte> aeadTag,
        int keyDataLen)
    {
        ArgumentNullException.ThrowIfNull(cryptoProvider);

        var ze = cryptoProvider.DeriveSharedSecret(curve, firstZPriv, firstZPub);
        var zs = cryptoProvider.DeriveSharedSecret(curve, secondZPriv, secondZPub);

        var z = new byte[ze.Length + zs.Length];
        ze.AsSpan().CopyTo(z);
        zs.AsSpan().CopyTo(z.AsSpan(ze.Length));
        CryptographicOperations.ZeroMemory(ze);
        CryptographicOperations.ZeroMemory(zs);

        // SuppPubInfo layout per draft-madden-jose-ecdh-1pu-04 §2.3 (and the askar reference
        // impl that produced the SICPA spec vectors):
        //   BE32(keyDataLen * 8) || [ BE32(cctag.length) || cctag ]   (cctag-block omitted when empty)
        // The didcomm porting source records that omitting the tag-length prefix round-trips
        // locally but is incompatible with every external 1PU implementation.
        var suppPubInfo = aeadTag.Length == 0
            ? new byte[4]
            : new byte[4 + 4 + aeadTag.Length];
        BinaryPrimitives.WriteUInt32BigEndian(suppPubInfo, checked((uint)keyDataLen * 8U));
        if (aeadTag.Length > 0)
        {
            BinaryPrimitives.WriteUInt32BigEndian(suppPubInfo.AsSpan(4, 4), (uint)aeadTag.Length);
            aeadTag.CopyTo(suppPubInfo.AsSpan(8));
        }

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
