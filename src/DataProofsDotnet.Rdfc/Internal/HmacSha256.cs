using NetCrypto;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>
/// HMAC-SHA-256 (RFC 2104) composed over NetCrypto's <see cref="Hash.Sha256"/> primitive.
/// </summary>
/// <remarks>
/// <para>
/// <c>bbs-2023</c> relabels canonical blank-node identifiers with an HMAC keyed by a
/// per-credential secret (FR-12). NetCrypto exposes the SHA-256 primitive but no standalone
/// HMAC, and the §2.2 / AC-6 ban forbids <c>System.Security.Cryptography.HMACSHA256</c>; so
/// HMAC is constructed here from the allowed NetCrypto hash — a compositional use of the
/// substrate, not a separate crypto backend. No keyed BCL primitive is referenced.
/// </para>
/// <para>Stateless and thread-safe.</para>
/// </remarks>
internal static class HmacSha256
{
    private const int BlockSize = 64; // SHA-256 input block size in bytes.
    private const byte IPad = 0x36;
    private const byte OPad = 0x5c;

    public static byte[] Compute(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        // Normalize the key to one block: keys longer than the block are hashed first,
        // shorter keys are zero-padded (RFC 2104).
        Span<byte> block = stackalloc byte[BlockSize];
        if (key.Length > BlockSize)
        {
            Hash.Sha256(key).CopyTo(block);
        }
        else
        {
            key.CopyTo(block);
        }

        Span<byte> innerKey = stackalloc byte[BlockSize];
        Span<byte> outerKey = stackalloc byte[BlockSize];
        for (var i = 0; i < BlockSize; i++)
        {
            innerKey[i] = (byte)(block[i] ^ IPad);
            outerKey[i] = (byte)(block[i] ^ OPad);
        }

        // inner = SHA-256(innerKey ‖ message)
        var innerInput = new byte[BlockSize + message.Length];
        innerKey.CopyTo(innerInput);
        message.CopyTo(innerInput.AsSpan(BlockSize));
        var inner = Hash.Sha256(innerInput);

        // outer = SHA-256(outerKey ‖ inner)
        var outerInput = new byte[BlockSize + inner.Length];
        outerKey.CopyTo(outerInput);
        inner.CopyTo(outerInput.AsSpan(BlockSize));
        return Hash.Sha256(outerInput);
    }
}
