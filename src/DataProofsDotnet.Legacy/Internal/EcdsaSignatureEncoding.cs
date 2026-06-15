namespace DataProofsDotnet.Legacy.Internal;

/// <summary>
/// Pure byte-level transcoding between ASN.1 DER ECDSA signatures and IEEE P1363
/// fixed-width <c>r ‖ s</c> form. The legacy <c>EcdsaSecp256r1Signature2019</c> suite puts
/// P1363 on the wire (zcap-dotnet signs with <c>EcdsaSignatureFormat.IeeeP1363</c>), while
/// NetCrypto's <c>ISigner</c> surface returns DER for NIST curves; this transcoder bridges
/// the two without touching any cryptographic primitive.
/// </summary>
/// <remarks>
/// Vendored verbatim from <c>DataProofsDotnet.Core/Internal/EcdsaSignatureEncoding.cs</c>
/// (the Rdfc package follows the same precedent), so this new assembly stays self-contained
/// and does not widen Core's <c>InternalsVisibleTo</c>.
/// </remarks>
internal static class EcdsaSignatureEncoding
{
    /// <summary>
    /// Normalizes an ECDSA signature to IEEE P1363 fixed-width form. Strict DER parsing
    /// is attempted first (the NetCrypto signer contract); a signature whose length is
    /// already exactly <c>2 * fieldWidth</c> is passed through unchanged when DER parsing
    /// fails (custom signers that emit P1363 natively).
    /// </summary>
    /// <param name="signature">The signature bytes as returned by the signer.</param>
    /// <param name="fieldWidth">The curve field width in bytes (32 for P-256).</param>
    /// <param name="p1363">The fixed-width signature on success.</param>
    public static bool TryNormalizeToP1363(ReadOnlySpan<byte> signature, int fieldWidth, out byte[] p1363)
    {
        if (TryParseDer(signature, fieldWidth, out p1363))
        {
            return true;
        }

        if (signature.Length == 2 * fieldWidth)
        {
            p1363 = signature.ToArray();
            return true;
        }

        p1363 = [];
        return false;
    }

    private static bool TryParseDer(ReadOnlySpan<byte> der, int fieldWidth, out byte[] p1363)
    {
        p1363 = [];

        // SEQUENCE
        if (der.Length < 8 || der[0] != 0x30)
        {
            return false;
        }

        if (!TryReadLength(der, 1, out var seqLength, out var offset))
        {
            return false;
        }

        if (offset + seqLength != der.Length)
        {
            return false;
        }

        if (!TryReadInteger(der, ref offset, fieldWidth, out var r) ||
            !TryReadInteger(der, ref offset, fieldWidth, out var s) ||
            offset != der.Length)
        {
            return false;
        }

        p1363 = new byte[2 * fieldWidth];
        r.CopyTo(p1363.AsSpan(fieldWidth - r.Length));
        s.CopyTo(p1363.AsSpan(2 * fieldWidth - s.Length));
        return true;
    }

    private static bool TryReadLength(ReadOnlySpan<byte> data, int offset, out int length, out int next)
    {
        length = 0;
        next = offset;
        if (offset >= data.Length)
        {
            return false;
        }

        var first = data[offset];
        if (first < 0x80)
        {
            length = first;
            next = offset + 1;
            return true;
        }

        // Only one length byte is ever needed for ECDSA signatures (max ~140 bytes).
        if (first != 0x81 || offset + 1 >= data.Length)
        {
            return false;
        }

        length = data[offset + 1];
        next = offset + 2;
        // DER requires minimal length encoding.
        return length >= 0x80;
    }

    private static bool TryReadInteger(ReadOnlySpan<byte> data, ref int offset, int fieldWidth, out ReadOnlySpan<byte> value)
    {
        value = default;
        if (offset + 2 > data.Length || data[offset] != 0x02)
        {
            return false;
        }

        if (!TryReadLength(data, offset + 1, out var length, out var contentStart))
        {
            return false;
        }

        if (length == 0 || contentStart + length > data.Length)
        {
            return false;
        }

        var content = data.Slice(contentStart, length);

        // DER: no superfluous leading zero (a zero byte is only valid to clear the sign bit).
        if (content.Length > 1 && content[0] == 0x00 && (content[1] & 0x80) == 0)
        {
            return false;
        }

        // Negative integers are invalid for r/s.
        if ((content[0] & 0x80) != 0)
        {
            return false;
        }

        // Strip the sign-clearing zero byte.
        if (content[0] == 0x00)
        {
            content = content[1..];
        }

        if (content.Length > fieldWidth)
        {
            return false;
        }

        value = content;
        offset = contentStart + length;
        return true;
    }
}
