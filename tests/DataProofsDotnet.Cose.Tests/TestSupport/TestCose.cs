using System.Formats.Cbor;
using NetCrypto;

namespace DataProofsDotnet.Cose.Tests.TestSupport;

/// <summary>
/// Test-side helpers: NetCrypto signer construction from raw keys and adversarial COSE_Sign1
/// CBOR construction (System.Formats.Cbor is test tooling here; the AC-7 ban applies to the
/// public API of src/ packages).
/// </summary>
internal static class TestCose
{
    internal static readonly DefaultCryptoProvider Crypto = new();
    internal static readonly DefaultKeyGenerator KeyGenerator = new();

    internal static ISigner SignerFor(KeyType keyType, byte[] privateKey) =>
        new KeyPairSigner(KeyGenerator.FromPrivateKey(keyType, privateKey), Crypto);

    /// <summary>Builds a COSE_Sign1 message with full control over every field (Lax conformance).</summary>
    internal static byte[] BuildSign1(
        Action<CborWriter>? writeProtectedMap,
        Action<CborWriter>? writeUnprotectedMap,
        byte[]? payload,
        byte[] signature,
        ulong? tag = 18)
    {
        byte[] protectedBytes = [];
        if (writeProtectedMap is not null)
        {
            var protectedWriter = new CborWriter(CborConformanceMode.Lax);
            writeProtectedMap(protectedWriter);
            protectedBytes = protectedWriter.Encode();
        }

        var writer = new CborWriter(CborConformanceMode.Lax);
        if (tag is { } t)
        {
            writer.WriteTag((CborTag)t);
        }

        writer.WriteStartArray(4);
        writer.WriteByteString(protectedBytes);
        if (writeUnprotectedMap is not null)
        {
            writeUnprotectedMap(writer);
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

    /// <summary>Writes <c>{1: alg}</c> — the minimal protected header map.</summary>
    internal static Action<CborWriter> ProtectedAlg(long algorithmId) => writer =>
    {
        writer.WriteStartMap(1);
        writer.WriteInt64(1);
        writer.WriteInt64(algorithmId);
        writer.WriteEndMap();
    };

    /// <summary>Prefixes <paramref name="encoded"/> with an extra CBOR tag.</summary>
    internal static byte[] PrependTag(ulong tag, byte[] encoded)
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteTag((CborTag)tag);
        writer.WriteEncodedValue(encoded);
        return writer.Encode();
    }

    /// <summary>Removes the leading CBOR tag from <paramref name="encoded"/>.</summary>
    internal static byte[] StripLeadingTag(byte[] encoded)
    {
        var reader = new CborReader(encoded, CborConformanceMode.Lax);
        reader.ReadTag();
        return reader.ReadEncodedValue().ToArray();
    }

    /// <summary>Returns a copy of <paramref name="bytes"/> with the byte at <paramref name="index"/> XOR-flipped.</summary>
    internal static byte[] FlipByte(byte[] bytes, Index index)
    {
        byte[] copy = (byte[])bytes.Clone();
        copy[index] ^= 0x01;
        return copy;
    }
}
