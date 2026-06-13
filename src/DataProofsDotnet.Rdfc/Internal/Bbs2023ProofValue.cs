using System.Formats.Cbor;
using System.Globalization;
using NetCid;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>
/// CBOR serialization of the <c>bbs-2023</c> multi-component <c>proofValue</c> (FR-12,
/// spec §3.3.1–3.3.7). Internal only: no CBOR type appears in any public signature (AC-7).
/// </summary>
/// <remarks>
/// <para>
/// A <c>bbs-2023</c> base or derived proof packs several byte/array components into one
/// <c>proofValue</c>. The wire form is <c>"u"</c> (multibase base64url-no-pad) followed by a
/// three-byte header (<c>0xd9 0x5d 0x02</c> base / <c>0xd9 0x5d 0x03</c> derived) and a
/// definite-length CBOR array of the components, with no CBOR tags on the components
/// themselves (spec §3.3.1). The header is carried as raw bytes — it is not a CBOR tag —
/// so encoding writes only the array after the literal header bytes.
/// </para>
/// <para>Stateless; each call uses a fresh writer/reader.</para>
/// </remarks>
internal static class Bbs2023ProofValue
{
    // Three-byte proofValue headers (baseline feature). These are literal prefix bytes that
    // happen to read as a CBOR tag (0xd95d02 / 0xd95d03) but are written/parsed as raw bytes.
    private static readonly byte[] BaseHeader = [0xd9, 0x5d, 0x02];
    private static readonly byte[] DerivedHeader = [0xd9, 0x5d, 0x03];

    /// <summary>The decoded components of a <c>bbs-2023</c> base proof.</summary>
    internal readonly record struct BaseProofComponents(
        byte[] BbsSignature,
        byte[] BbsHeader,
        byte[] PublicKey,
        byte[] HmacKey,
        IReadOnlyList<string> MandatoryPointers);

    /// <summary>The decoded components of a <c>bbs-2023</c> derived proof.</summary>
    internal readonly record struct DerivedProofComponents(
        byte[] BbsProof,
        IReadOnlyDictionary<string, string> LabelMap,
        IReadOnlyList<int> MandatoryIndexes,
        IReadOnlyList<int> SelectiveIndexes,
        byte[] PresentationHeader);

    /// <summary>Serializes a base proof to its <c>u2V0C…</c> multibase <c>proofValue</c> (§3.3.1).</summary>
    public static string SerializeBaseProof(
        ReadOnlySpan<byte> bbsSignature,
        ReadOnlySpan<byte> bbsHeader,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> hmacKey,
        IReadOnlyList<string> mandatoryPointers)
    {
        ArgumentNullException.ThrowIfNull(mandatoryPointers);

        var writer = new CborWriter();
        writer.WriteStartArray(5);
        writer.WriteByteString(bbsSignature);
        writer.WriteByteString(bbsHeader);
        writer.WriteByteString(publicKey);
        writer.WriteByteString(hmacKey);
        writer.WriteStartArray(mandatoryPointers.Count);
        foreach (var pointer in mandatoryPointers)
        {
            writer.WriteTextString(pointer);
        }

        writer.WriteEndArray();
        writer.WriteEndArray();

        return Encode(BaseHeader, writer.Encode());
    }

    /// <summary>Parses a <c>u2V0C…</c> base proof <c>proofValue</c> (§3.3.2).</summary>
    public static BaseProofComponents ParseBaseProof(string proofValue)
    {
        var payload = DecodeHeadered(proofValue, BaseHeader, "base");
        var reader = new CborReader(payload);

        var count = reader.ReadStartArray();
        if (count != 5)
        {
            throw new FormatException("A bbs-2023 base proofValue must encode a five-element array.");
        }

        var bbsSignature = reader.ReadByteString();
        var bbsHeader = reader.ReadByteString();
        var publicKey = reader.ReadByteString();
        var hmacKey = reader.ReadByteString();
        var mandatoryPointers = ReadStringArray(reader);
        reader.ReadEndArray();

        return new BaseProofComponents(bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers);
    }

    /// <summary>Serializes a derived proof to its <c>u2V0D…</c> multibase <c>proofValue</c> (§3.3.6).</summary>
    public static string SerializeDerivedProof(
        ReadOnlySpan<byte> bbsProof,
        IReadOnlyDictionary<string, string> labelMap,
        IReadOnlyList<int> mandatoryIndexes,
        IReadOnlyList<int> selectiveIndexes,
        ReadOnlySpan<byte> presentationHeader)
    {
        ArgumentNullException.ThrowIfNull(labelMap);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);
        ArgumentNullException.ThrowIfNull(selectiveIndexes);

        var writer = new CborWriter();
        writer.WriteStartArray(5);
        writer.WriteByteString(bbsProof);
        WriteCompressedLabelMap(writer, labelMap);
        WriteIntArray(writer, mandatoryIndexes);
        WriteIntArray(writer, selectiveIndexes);
        writer.WriteByteString(presentationHeader);
        writer.WriteEndArray();

        return Encode(DerivedHeader, writer.Encode());
    }

    /// <summary>Parses a <c>u2V0D…</c> derived proof <c>proofValue</c> (§3.3.7).</summary>
    public static DerivedProofComponents ParseDerivedProof(string proofValue)
    {
        var payload = DecodeHeadered(proofValue, DerivedHeader, "derived");
        var reader = new CborReader(payload);

        var count = reader.ReadStartArray();
        if (count != 5)
        {
            throw new FormatException("A bbs-2023 derived proofValue must encode a five-element array.");
        }

        var bbsProof = reader.ReadByteString();
        var labelMap = ReadCompressedLabelMap(reader);
        var mandatoryIndexes = ReadIntArray(reader);
        var selectiveIndexes = ReadIntArray(reader);
        var presentationHeader = reader.ReadByteString();
        reader.ReadEndArray();

        return new DerivedProofComponents(bbsProof, labelMap, mandatoryIndexes, selectiveIndexes, presentationHeader);
    }

    // --- compression helpers (spec §3.3.4 / §3.3.5) ---

    // compressLabelMap: { "c14nN" -> "bM" } becomes a CBOR map { N(uint) -> M(uint) }.
    private static void WriteCompressedLabelMap(CborWriter writer, IReadOnlyDictionary<string, string> labelMap)
    {
        var compressed = new SortedDictionary<int, int>();
        foreach (var (key, value) in labelMap)
        {
            compressed[StripPrefix(key, "c14n")] = StripPrefix(value, "b");
        }

        writer.WriteStartMap(compressed.Count);
        foreach (var (key, value) in compressed)
        {
            writer.WriteUInt32((uint)key);
            writer.WriteUInt32((uint)value);
        }

        writer.WriteEndMap();
    }

    private static IReadOnlyDictionary<string, string> ReadCompressedLabelMap(CborReader reader)
    {
        var count = reader.ReadStartMap();
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < count; i++)
        {
            var key = reader.ReadUInt32();
            var value = reader.ReadUInt32();
            map["c14n" + key.ToString(CultureInfo.InvariantCulture)] = "b" + value.ToString(CultureInfo.InvariantCulture);
        }

        reader.ReadEndMap();
        return map;
    }

    private static void WriteIntArray(CborWriter writer, IReadOnlyList<int> values)
    {
        writer.WriteStartArray(values.Count);
        foreach (var value in values)
        {
            writer.WriteInt32(value);
        }

        writer.WriteEndArray();
    }

    private static IReadOnlyList<int> ReadIntArray(CborReader reader)
    {
        var count = reader.ReadStartArray();
        var values = new List<int>(count ?? 0);
        while (reader.PeekState() != CborReaderState.EndArray)
        {
            values.Add(reader.ReadInt32());
        }

        reader.ReadEndArray();
        return values;
    }

    private static IReadOnlyList<string> ReadStringArray(CborReader reader)
    {
        var count = reader.ReadStartArray();
        var values = new List<string>(count ?? 0);
        while (reader.PeekState() != CborReaderState.EndArray)
        {
            values.Add(reader.ReadTextString());
        }

        reader.ReadEndArray();
        return values;
    }

    private static int StripPrefix(string label, string prefix)
    {
        if (!label.StartsWith(prefix, StringComparison.Ordinal)
            || !int.TryParse(label.AsSpan(prefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out var value))
        {
            throw new FormatException($"Label '{label}' is not of the form '{prefix}<integer>'.");
        }

        return value;
    }

    private static string Encode(byte[] header, byte[] cbor)
    {
        var buffer = new byte[header.Length + cbor.Length];
        header.CopyTo(buffer, 0);
        cbor.CopyTo(buffer, header.Length);
        return Multibase.Encode(buffer, MultibaseEncoding.Base64Url);
    }

    private static byte[] DecodeHeadered(string proofValue, byte[] header, string kind)
    {
        ArgumentException.ThrowIfNullOrEmpty(proofValue);
        if (proofValue[0] != 'u')
        {
            throw new FormatException("A bbs-2023 proofValue must be multibase base64url-no-pad ('u' prefix).");
        }

        if (!Multibase.TryDecode(proofValue, out var bytes, out var encoding) || encoding != MultibaseEncoding.Base64Url)
        {
            throw new FormatException("The bbs-2023 proofValue is not valid multibase base64url-no-pad.");
        }

        if (bytes.Length < header.Length || !bytes.AsSpan(0, header.Length).SequenceEqual(header))
        {
            throw new FormatException($"The proofValue header does not match the bbs-2023 {kind} proof header.");
        }

        return bytes.AsSpan(header.Length).ToArray();
    }
}
