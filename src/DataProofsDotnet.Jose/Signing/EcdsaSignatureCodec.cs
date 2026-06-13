namespace DataProofsDotnet.Jose.Signing;

/// <summary>
/// Transcodes ECDSA signatures between ASN.1 DER (<c>SEQUENCE { INTEGER r, INTEGER s }</c>) and
/// the fixed-width IEEE P1363 <c>R ‖ S</c> form JOSE requires (RFC 7515 §3.4).
/// </summary>
/// <remarks>
/// <para>
/// NetCrypto's <c>ISigner.SignAsync</c> has no signature-format parameter and the shipped
/// signers return NIST-curve ECDSA in DER (the PRD FR-13 signature-format gotcha;
/// tasks/research/netcrypto-api.md §2). This codec is pure byte parsing — no cryptographic
/// primitive is involved, so it is AC-6-clean — and lets <see cref="JwsSigner"/> normalize
/// whatever a NetCrypto signer returns into the JOSE wire form.
/// </para>
/// <para>
/// Ed25519 (raw 64 bytes) and secp256k1 (NetCrypto already returns compact 64-byte R‖S) never
/// pass through here.
/// </para>
/// </remarks>
internal static class EcdsaSignatureCodec
{
    /// <summary>
    /// Return <paramref name="signature"/> as fixed-width IEEE P1363 <c>R ‖ S</c> with each
    /// coordinate left-padded to <paramref name="coordinateLength"/> bytes. DER input is
    /// transcoded; input that is already exactly <c>2 × coordinateLength</c> bytes and not a
    /// parseable DER sequence is passed through unchanged (a P1363-native signer).
    /// </summary>
    /// <param name="signature">DER or P1363 signature bytes from a NetCrypto signer.</param>
    /// <param name="coordinateLength">The curve field width in bytes (32 for P-256, 48 for P-384).</param>
    /// <exception cref="JoseCryptoException">When the bytes are neither valid DER nor plausibly P1363.</exception>
    public static byte[] EnsureIeeeP1363(byte[] signature, int coordinateLength)
    {
        ArgumentNullException.ThrowIfNull(signature);

        if (TryParseDer(signature, coordinateLength, out var p1363))
            return p1363;

        if (signature.Length == checked(2 * coordinateLength))
            return signature;

        throw new JoseCryptoException(
            $"ECDSA signature is neither valid DER nor fixed-width P1363 for a {coordinateLength * 8}-bit curve (length {signature.Length}).");
    }

    private static bool TryParseDer(ReadOnlySpan<byte> der, int coordinateLength, out byte[] p1363)
    {
        p1363 = [];
        var offset = 0;

        if (!TryReadTagLength(der, ref offset, expectedTag: 0x30, out var seqLength))
            return false;
        if (offset + seqLength != der.Length)
            return false;

        if (!TryReadInteger(der, ref offset, coordinateLength, out var r))
            return false;
        if (!TryReadInteger(der, ref offset, coordinateLength, out var s))
            return false;
        if (offset != der.Length)
            return false;

        var result = new byte[2 * coordinateLength];
        r.CopyTo(result.AsSpan(coordinateLength - r.Length));
        s.CopyTo(result.AsSpan(coordinateLength + (coordinateLength - s.Length)));
        p1363 = result;
        return true;
    }

    private static bool TryReadTagLength(ReadOnlySpan<byte> data, ref int offset, byte expectedTag, out int length)
    {
        length = 0;
        if (offset >= data.Length || data[offset] != expectedTag)
            return false;
        offset++;

        if (offset >= data.Length)
            return false;

        var first = data[offset++];
        if (first < 0x80)
        {
            length = first;
            return true;
        }

        // Long form: only 0x81 (one length byte) ever occurs for ECDSA P-256/P-384 sizes.
        if (first != 0x81 || offset >= data.Length)
            return false;
        length = data[offset++];
        return length >= 0x80; // DER requires minimal-length encoding.
    }

    private static bool TryReadInteger(ReadOnlySpan<byte> data, ref int offset, int coordinateLength, out ReadOnlySpan<byte> magnitude)
    {
        magnitude = default;
        if (!TryReadTagLength(data, ref offset, expectedTag: 0x02, out var length))
            return false;
        if (length == 0 || offset + length > data.Length)
            return false;

        var value = data.Slice(offset, length);
        offset += length;

        // Negative INTEGERs never appear in ECDSA (r, s > 0).
        if ((value[0] & 0x80) != 0)
            return false;

        // Strip the single permissible leading zero (sign byte for a high MSB).
        if (value[0] == 0x00 && value.Length > 1)
        {
            // DER minimality: a 0x00 prefix is only valid when the next byte has its MSB set.
            if ((value[1] & 0x80) == 0)
                return false;
            value = value[1..];
        }

        if (value.Length > coordinateLength)
            return false;

        magnitude = value;
        return true;
    }
}
