using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Globalization;

namespace DataProofsDotnet.Cose.Internal;

/// <summary>Which leading CBOR tags a decode accepts.</summary>
internal enum CoseTagAcceptance
{
    /// <summary>COSE_Sign1 (tag 18) or untagged.</summary>
    Sign1,

    /// <summary>CWT entry point: 61(18(…)), 18(…), or untagged (RFC 8392 §6).</summary>
    Cwt,
}

/// <summary>
/// All COSE_Sign1 CBOR encoding/decoding (RFC 9052 §4.2/§4.4). CBOR stays strictly internal:
/// no <c>System.Formats.Cbor</c> type appears in any public signature (AC-7). Emission uses
/// canonical CBOR (deterministic encoding, NFR-5); decoding is lax to accept messages from
/// other conformant implementations.
/// </summary>
internal static class CoseSign1Codec
{
    private const ulong Sign1Tag = 18;
    private const ulong CwtTag = 61;

    /// <summary>Protected/unprotected header labels this implementation understands (for crit checking).</summary>
    private static readonly long[] UnderstoodLabels = [1, 3, 4, 16];

    private const long AlgLabel = 1;
    private const long CritLabel = 2;
    private const long ContentTypeLabel = 3;
    private const long KidLabel = 4;
    private const long TypLabel = 16; // RFC 9596

    // ----- decoding -----

    internal static bool TryDecode(
        ReadOnlyMemory<byte> data,
        CoseTagAcceptance acceptance,
        [NotNullWhen(true)] out CoseSign1Message? message,
        [NotNullWhen(false)] out CoseVerificationFailure? failure)
    {
        message = null;
        failure = null;
        try
        {
            var reader = new CborReader(data, CborConformanceMode.Lax);
            var tags = new List<ulong>();
            while (reader.PeekState() == CborReaderState.Tag)
            {
                tags.Add((ulong)reader.ReadTag());
                if (tags.Count > 2)
                {
                    failure = Fail(CoseVerificationErrorCode.UnexpectedCborTag, "More than two nested CBOR tags precede the COSE structure.");
                    return false;
                }
            }

            if (!ValidateTags(tags, acceptance, out failure))
            {
                return false;
            }

            message = ReadStructure(reader, hasSign1Tag: tags.Contains(Sign1Tag));
            if (reader.BytesRemaining > 0)
            {
                message = null;
                failure = Fail(CoseVerificationErrorCode.MalformedMessage, "Trailing bytes follow the COSE_Sign1 structure.");
                return false;
            }

            return true;
        }
        catch (CborContentException ex)
        {
            failure = Fail(CoseVerificationErrorCode.MalformedMessage, $"Malformed CBOR/COSE input: {ex.Message}");
            return false;
        }
        catch (InvalidOperationException ex)
        {
            // CborReader throws InvalidOperationException when the next data item has an
            // unexpected major type (e.g. a text string where a byte string is required).
            failure = Fail(CoseVerificationErrorCode.MalformedMessage, $"Malformed COSE_Sign1 structure: {ex.Message}");
            return false;
        }
        catch (OverflowException)
        {
            failure = Fail(CoseVerificationErrorCode.MalformedMessage, "A CBOR integer in the message is outside the supported range.");
            return false;
        }
    }

    private static bool ValidateTags(List<ulong> tags, CoseTagAcceptance acceptance, [NotNullWhen(false)] out CoseVerificationFailure? failure)
    {
        failure = null;
        switch (acceptance)
        {
            case CoseTagAcceptance.Sign1:
                if (tags.Count == 0 || (tags.Count == 1 && tags[0] == Sign1Tag))
                {
                    return true;
                }

                if (tags[0] == CwtTag)
                {
                    failure = Fail(CoseVerificationErrorCode.UnexpectedCborTag, "The input carries the CWT tag (61); use the Cwt API to process CBOR Web Tokens.");
                    return false;
                }

                failure = DescribeUnexpectedTag(tags[0] == Sign1Tag ? tags[1] : tags[0]);
                return false;

            case CoseTagAcceptance.Cwt:
                if (tags.Count == 0 || (tags.Count == 1 && tags[0] == Sign1Tag))
                {
                    return true;
                }

                if (tags[0] == CwtTag)
                {
                    if (tags.Count == 1)
                    {
                        // RFC 8392 §6: when the CWT tag is present, it MUST prefix a tagged COSE message.
                        failure = Fail(CoseVerificationErrorCode.UnexpectedCborTag, "The CWT tag (61) must be followed by a tagged COSE message (RFC 8392 §6).");
                        return false;
                    }

                    if (tags[1] == Sign1Tag)
                    {
                        return true;
                    }

                    failure = DescribeUnexpectedTag(tags[1]);
                    return false;
                }

                failure = DescribeUnexpectedTag(tags[0]);
                return false;

            default:
                failure = Fail(CoseVerificationErrorCode.MalformedMessage, "Unknown tag acceptance mode.");
                return false;
        }
    }

    private static CoseVerificationFailure DescribeUnexpectedTag(ulong tag) => tag switch
    {
        16 => Fail(CoseVerificationErrorCode.UnsupportedCoseStructure, "The input is a COSE_Encrypt0 (tag 16); only COSE_Sign1 (tag 18) is supported."),
        17 => Fail(CoseVerificationErrorCode.UnsupportedCoseStructure, "The input is a COSE_Mac0 (tag 17); only COSE_Sign1 (tag 18) is supported."),
        96 => Fail(CoseVerificationErrorCode.UnsupportedCoseStructure, "The input is a COSE_Encrypt (tag 96); only COSE_Sign1 (tag 18) is supported."),
        97 => Fail(CoseVerificationErrorCode.UnsupportedCoseStructure, "The input is a COSE_Mac (tag 97); only COSE_Sign1 (tag 18) is supported."),
        98 => Fail(CoseVerificationErrorCode.UnsupportedCoseStructure, "The input is a COSE_Sign (tag 98, multi-signer); only COSE_Sign1 (tag 18) is supported."),
        _ => Fail(CoseVerificationErrorCode.UnexpectedCborTag, $"Unexpected CBOR tag {tag}; expected COSE_Sign1 (tag 18) or an untagged message."),
    };

    private static CoseSign1Message ReadStructure(CborReader reader, bool hasSign1Tag)
    {
        int? length = reader.ReadStartArray();
        if (length is not null && length != 4)
        {
            throw new CborContentException($"COSE_Sign1 must be an array of 4 elements; found {length}.");
        }

        byte[] protectedBytes = reader.ReadByteString();
        var bag = new HeaderBag();
        ParseProtectedHeaders(protectedBytes, bag);
        ParseHeaderMap(reader, bag, isProtected: false);

        byte[]? payload;
        if (reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
            payload = null;
        }
        else
        {
            payload = reader.ReadByteString();
        }

        byte[] signature = reader.ReadByteString();
        reader.ReadEndArray();

        return new CoseSign1Message(bag, hasSign1Tag, protectedBytes, payload, signature);
    }

    private static void ParseProtectedHeaders(byte[] protectedBytes, HeaderBag bag)
    {
        if (protectedBytes.Length == 0)
        {
            return; // zero-length byte string ⇒ no protected headers (RFC 9052 §3)
        }

        var reader = new CborReader(protectedBytes, CborConformanceMode.Lax);
        ParseHeaderMap(reader, bag, isProtected: true);
        if (reader.BytesRemaining > 0)
        {
            throw new CborContentException("The protected header byte string contains trailing data after the header map.");
        }
    }

    private static void ParseHeaderMap(CborReader reader, HeaderBag bag, bool isProtected)
    {
        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            switch (reader.PeekState())
            {
                case CborReaderState.UnsignedInteger:
                case CborReaderState.NegativeInteger:
                    long label = reader.ReadInt64();
                    if (!bag.TryClaimLabel(label))
                    {
                        throw new CborContentException($"Duplicate COSE header label {label} (labels must be unique across the protected and unprotected buckets, RFC 9052 §3).");
                    }

                    if (isProtected)
                    {
                        bag.NoteProtectedLabel(label);
                    }

                    ReadHeaderValue(reader, bag, label, isProtected);
                    break;

                case CborReaderState.TextString:
                    string textLabel = reader.ReadTextString();
                    if (!bag.TryClaimLabel(textLabel))
                    {
                        throw new CborContentException($"Duplicate COSE header label \"{textLabel}\".");
                    }

                    if (isProtected)
                    {
                        bag.NoteProtectedLabel(textLabel);
                    }

                    reader.SkipValue(); // unknown application-defined text label: ignored unless listed in crit
                    break;

                default:
                    throw new CborContentException("COSE header labels must be integers or text strings (RFC 9052 §3).");
            }
        }

        reader.ReadEndMap();
    }

    private static void ReadHeaderValue(CborReader reader, HeaderBag bag, long label, bool isProtected)
    {
        switch (label)
        {
            case AlgLabel:
                switch (reader.PeekState())
                {
                    case CborReaderState.UnsignedInteger:
                    case CborReaderState.NegativeInteger:
                        bag.AlgorithmId = reader.ReadInt64();
                        break;
                    case CborReaderState.TextString:
                        bag.AlgorithmText = reader.ReadTextString();
                        break;
                    default:
                        bag.AlgorithmValueInvalid = true;
                        reader.SkipValue();
                        break;
                }

                break;

            case CritLabel:
                if (!isProtected)
                {
                    throw new CborContentException("The crit (2) header parameter must be in the protected bucket (RFC 9052 §3.1).");
                }

                ReadCriticalHeaders(reader, bag);
                break;

            case ContentTypeLabel:
                switch (reader.PeekState())
                {
                    case CborReaderState.TextString:
                        bag.ContentType = reader.ReadTextString();
                        bag.ContentTypeIsProtected = isProtected;
                        break;
                    case CborReaderState.UnsignedInteger:
                        bag.ContentFormat = reader.ReadInt64();
                        bag.ContentTypeIsProtected = isProtected;
                        break;
                    default:
                        reader.SkipValue(); // invalid content-type value shape: leave unmodeled
                        break;
                }

                break;

            case KidLabel:
                if (reader.PeekState() == CborReaderState.ByteString)
                {
                    bag.KeyId = reader.ReadByteString();
                }
                else
                {
                    reader.SkipValue();
                }

                break;

            case TypLabel:
                if (reader.PeekState() == CborReaderState.TextString)
                {
                    bag.Type = reader.ReadTextString();
                    bag.TypeIsProtected = isProtected;
                }
                else
                {
                    reader.SkipValue(); // RFC 9596 also allows uint typ values; not modeled in v1
                }

                break;

            default:
                reader.SkipValue(); // unknown non-critical header: ignored
                break;
        }
    }

    private static void ReadCriticalHeaders(CborReader reader, HeaderBag bag)
    {
        reader.ReadStartArray();
        int entries = 0;
        while (reader.PeekState() != CborReaderState.EndArray)
        {
            switch (reader.PeekState())
            {
                case CborReaderState.UnsignedInteger:
                case CborReaderState.NegativeInteger:
                    long label = reader.ReadInt64();
                    entries++;
                    bag.CriticalIntLabels.Add(label);
                    if (Array.IndexOf(UnderstoodLabels, label) < 0)
                    {
                        bag.UnknownCriticalLabels.Add(label.ToString(CultureInfo.InvariantCulture));
                    }

                    break;

                case CborReaderState.TextString:
                    // This implementation understands no application-defined text labels.
                    string critTextLabel = reader.ReadTextString();
                    bag.CriticalTextLabels.Add(critTextLabel);
                    bag.UnknownCriticalLabels.Add($"\"{critTextLabel}\"");
                    entries++;
                    break;

                default:
                    throw new CborContentException("crit (2) entries must be integer or text-string labels (RFC 9052 §3.1).");
            }
        }

        reader.ReadEndArray();
        if (entries == 0)
        {
            throw new CborContentException("The crit (2) header parameter must contain at least one label (RFC 9052 §3.1).");
        }
    }

    // ----- encoding -----

    internal static byte[] EncodeProtectedHeaders(CoseAlgorithm algorithm, string? contentType, int? contentFormat, string? type)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        int count = 1 + (contentType is not null || contentFormat is not null ? 1 : 0) + (type is not null ? 1 : 0);
        writer.WriteStartMap(count);
        writer.WriteInt64(AlgLabel);
        writer.WriteInt64((long)algorithm);
        if (contentType is not null)
        {
            writer.WriteInt64(ContentTypeLabel);
            writer.WriteTextString(contentType);
        }
        else if (contentFormat is not null)
        {
            writer.WriteInt64(ContentTypeLabel);
            writer.WriteInt64(contentFormat.Value);
        }

        if (type is not null)
        {
            writer.WriteInt64(TypLabel);
            writer.WriteTextString(type);
        }

        writer.WriteEndMap();
        return writer.Encode();
    }

    internal static byte[] EncodeMessage(byte[] protectedBytes, ReadOnlyMemory<byte>? keyId, byte[]? payload, byte[] signature, bool includeSign1Tag)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        if (includeSign1Tag)
        {
            writer.WriteTag((CborTag)Sign1Tag);
        }

        writer.WriteStartArray(4);
        writer.WriteByteString(protectedBytes);
        if (keyId is { } kid)
        {
            writer.WriteStartMap(1);
            writer.WriteInt64(KidLabel);
            writer.WriteByteString(kid.Span);
            writer.WriteEndMap();
        }
        else
        {
            writer.WriteStartMap(0);
            writer.WriteEndMap();
        }

        if (payload is null)
        {
            writer.WriteNull();
        }
        else
        {
            writer.WriteByteString(payload);
        }

        writer.WriteByteString(signature);
        writer.WriteEndArray();
        return writer.Encode();
    }

    internal static byte[] WrapInCwtTag(byte[] encodedCoseSign1)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)CwtTag);
        writer.WriteEncodedValue(encodedCoseSign1);
        return writer.Encode();
    }

    /// <summary>
    /// Builds the Sig_structure ("Signature1") signing input of RFC 9052 §4.4:
    /// <c>["Signature1", body_protected, external_aad, payload]</c>.
    /// </summary>
    internal static byte[] BuildSignatureInput(ReadOnlySpan<byte> bodyProtected, ReadOnlySpan<byte> externalData, ReadOnlySpan<byte> payload)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(4);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(bodyProtected);
        writer.WriteByteString(externalData);
        writer.WriteByteString(payload);
        writer.WriteEndArray();
        return writer.Encode();
    }

    /// <summary>
    /// RFC 9052 §3 permits encoding an empty protected bucket as either a zero-length byte
    /// string or an encoded empty map (h'A0'); the Sig_structure must use the zero-length form
    /// for both (the cose-wg "redo protected" rule).
    /// </summary>
    internal static ReadOnlySpan<byte> NormalizeProtectedForSignatureInput(byte[] protectedBytes) =>
        protectedBytes.Length == 1 && protectedBytes[0] == 0xA0 ? default : protectedBytes;

    private static CoseVerificationFailure Fail(CoseVerificationErrorCode code, string message) => new(code, message);
}

/// <summary>Mutable parse-time header accumulator; never escapes the codec/message internals.</summary>
internal sealed class HeaderBag
{
    private readonly HashSet<long> _intLabels = [];
    private readonly HashSet<string> _textLabels = [];
    private readonly HashSet<long> _protectedIntLabels = [];
    private readonly HashSet<string> _protectedTextLabels = [];

    internal long? AlgorithmId { get; set; }

    internal string? AlgorithmText { get; set; }

    internal bool AlgorithmValueInvalid { get; set; }

    internal byte[]? KeyId { get; set; }

    internal string? ContentType { get; set; }

    internal long? ContentFormat { get; set; }

    internal bool ContentTypeIsProtected { get; set; }

    internal string? Type { get; set; }

    internal bool TypeIsProtected { get; set; }

    internal List<string> UnknownCriticalLabels { get; } = [];

    /// <summary>Integer labels named in the crit (2) array (RFC 9052 §3.1), in declaration order.</summary>
    internal List<long> CriticalIntLabels { get; } = [];

    /// <summary>Text labels named in the crit (2) array (RFC 9052 §3.1), in declaration order.</summary>
    internal List<string> CriticalTextLabels { get; } = [];

    internal bool TryClaimLabel(long label) => _intLabels.Add(label);

    internal bool TryClaimLabel(string label) => _textLabels.Add(label);

    /// <summary>Records that <paramref name="label"/> appeared as a key in the protected header map.</summary>
    internal void NoteProtectedLabel(long label) => _protectedIntLabels.Add(label);

    /// <summary>Records that <paramref name="label"/> appeared as a key in the protected header map.</summary>
    internal void NoteProtectedLabel(string label) => _protectedTextLabels.Add(label);

    internal bool IsProtectedLabelPresent(long label) => _protectedIntLabels.Contains(label);

    internal bool IsProtectedLabelPresent(string label) => _protectedTextLabels.Contains(label);
}
