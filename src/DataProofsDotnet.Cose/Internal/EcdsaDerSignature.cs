namespace DataProofsDotnet.Cose.Internal;

/// <summary>
/// DER → IEEE P1363 ECDSA signature transcoding.
/// </summary>
/// <remarks>
/// NetCrypto's <c>ISigner.SignAsync</c> (and <c>IKeyStore.SignAsync</c>) route to the default
/// <c>ICryptoProvider.Sign</c> overload, which returns NIST-curve ECDSA signatures in DER —
/// there is no format-aware <c>ISigner</c> member (netcrypto-api.md §2). COSE requires
/// fixed-width R‖S (IEEE P1363), so the DER bytes are transcoded here. This is pure ASN.1
/// byte parsing — no cryptographic primitive is involved (AC-6 clean).
/// </remarks>
internal static class EcdsaDerSignature
{
    /// <summary>
    /// Normalizes an ECDSA signature returned by an <c>ISigner</c> to fixed-width IEEE P1363 R‖S.
    /// Strict-DER input is transcoded; input that is already exactly <c>2 × fieldWidth</c> bytes
    /// and not valid DER is passed through unchanged (a format-aware custom signer).
    /// </summary>
    /// <exception cref="CoseException">The signature is neither strict DER nor P1363-width.</exception>
    internal static byte[] NormalizeToIeeeP1363(byte[] signature, int fieldWidth)
    {
        if (TryParseDer(signature, out Range r, out Range s))
        {
            ReadOnlySpan<byte> rBytes = TrimLeadingZero(signature.AsSpan(r));
            ReadOnlySpan<byte> sBytes = TrimLeadingZero(signature.AsSpan(s));
            if (rBytes.Length > fieldWidth || sBytes.Length > fieldWidth)
            {
                throw new CoseException(
                    $"The signer returned a DER ECDSA signature whose integers exceed the curve field width ({fieldWidth} bytes).");
            }

            byte[] p1363 = new byte[2 * fieldWidth];
            rBytes.CopyTo(p1363.AsSpan(fieldWidth - rBytes.Length));
            sBytes.CopyTo(p1363.AsSpan(2 * fieldWidth - sBytes.Length));
            return p1363;
        }

        if (signature.Length == 2 * fieldWidth)
        {
            // Not parseable as strict DER but exactly P1363-shaped: a custom ISigner that already
            // emits fixed-width R‖S. Accept verbatim.
            return signature;
        }

        throw new CoseException(
            $"The signer returned an ECDSA signature that is neither DER nor IEEE P1363 ({signature.Length} bytes; expected DER or {2 * fieldWidth} bytes).");
    }

    private static ReadOnlySpan<byte> TrimLeadingZero(ReadOnlySpan<byte> value) =>
        value.Length > 1 && value[0] == 0x00 ? value[1..] : value;

    /// <summary>
    /// Strict parse of SEQUENCE { INTEGER r, INTEGER s }: definite lengths, minimal integer
    /// encodings, positive values, full input consumption. Random P1363 bytes cannot satisfy
    /// this accidentally with realistic probability.
    /// </summary>
    private static bool TryParseDer(ReadOnlySpan<byte> der, out Range r, out Range s)
    {
        r = default;
        s = default;
        if (der.Length < 8 || der[0] != 0x30)
        {
            return false;
        }

        int pos = 1;
        if (!TryReadLength(der, ref pos, out int seqLength) || pos + seqLength != der.Length)
        {
            return false;
        }

        if (!TryReadInteger(der, ref pos, out r) || !TryReadInteger(der, ref pos, out s))
        {
            return false;
        }

        return pos == der.Length;
    }

    private static bool TryReadLength(ReadOnlySpan<byte> der, ref int pos, out int length)
    {
        length = 0;
        if (pos >= der.Length)
        {
            return false;
        }

        byte first = der[pos++];
        if (first < 0x80)
        {
            length = first;
            return true;
        }

        // ECDSA signatures for P-256/P-384 fit in a single-byte long form (0x81). Anything
        // longer is not a plausible signature; reject multi-byte length forms.
        if (first != 0x81 || pos >= der.Length)
        {
            return false;
        }

        length = der[pos++];
        return length >= 0x80; // DER: long form must not encode a short-form-expressible length
    }

    private static bool TryReadInteger(ReadOnlySpan<byte> der, ref int pos, out Range value)
    {
        value = default;
        if (pos + 2 > der.Length || der[pos] != 0x02)
        {
            return false;
        }

        pos++;
        if (!TryReadLength(der, ref pos, out int length) || length == 0 || pos + length > der.Length)
        {
            return false;
        }

        ReadOnlySpan<byte> bytes = der.Slice(pos, length);
        if ((bytes[0] & 0x80) != 0)
        {
            return false; // negative integer — not a valid ECDSA signature component
        }

        if (length > 1 && bytes[0] == 0x00 && (bytes[1] & 0x80) == 0)
        {
            return false; // non-minimal encoding
        }

        value = new Range(pos, pos + length);
        pos += length;
        return true;
    }
}
