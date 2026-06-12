using DataProofsDotnet.Cose.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Cose.Tests;

/// <summary>
/// AC-4 negative paths beyond the cose-wg corpus: malformed CBOR, adversarial header shapes,
/// algorithm confusion, unknown critical headers, and tag abuse. Every case through
/// <see cref="CoseSign1.Verify"/> must yield a structured failure — never an unhandled
/// exception; <see cref="CoseSign1.Decode"/> throws the documented <see cref="CoseException"/>.
/// </summary>
public sealed class CoseSign1NegativeTests
{
    private static readonly byte[] Payload = "payload"u8.ToArray();
    private static readonly byte[] GarbageSignature64 = new byte[64];
    private static readonly KeyPair P256Key = TestCose.KeyGenerator.Generate(KeyType.P256);

    // ----- malformed input -----

    public static TheoryData<string, byte[]> MalformedInputs => new()
    {
        { "empty input", [] },
        { "truncated CBOR", [0xD2, 0x84, 0x41] },
        { "not a COSE structure (text string)", [0x63, 0x66, 0x6F, 0x6F] },
        { "array of 3 elements", [0x83, 0x40, 0xA0, 0x40] },
        { "array of 5 elements", [0x85, 0x40, 0xA0, 0x40, 0x40, 0x40] },
        { "protected bucket is not a byte string", [0xD2, 0x84, 0xA0, 0xA0, 0x40, 0x40] },
        { "payload is a text string", [0xD2, 0x84, 0x40, 0xA0, 0x60, 0x40] },
        // protected byte string h'41' contains a truncated header map
        { "protected bucket contains malformed CBOR", [0xD2, 0x84, 0x41, 0xA1, 0xA0, 0x40, 0x40] },
    };

    [Theory]
    [MemberData(nameof(MalformedInputs))]
    public void MalformedInputYieldsStructuredFailure(string description, byte[] input)
    {
        CoseSign1VerificationResult result = CoseSign1.Verify(input, KeyType.P256, P256Key.PublicKey);

        result.Verified.Should().BeFalse(description);
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.MalformedMessage, description);
    }

    [Fact]
    public void TrailingBytesAreRejected()
    {
        byte[] valid = TestCose.BuildSign1(TestCose.ProtectedAlg(-7), null, Payload, GarbageSignature64);
        byte[] withTrailer = [.. valid, 0x00];

        CoseSign1.Verify(withTrailer, KeyType.P256, P256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.MalformedMessage);
    }

    [Fact]
    public void DecodeThrowsCoseExceptionOnMalformedInput()
    {
        Action act = () => CoseSign1.Decode(new byte[] { 0xD2, 0x84, 0x41 });
        act.Should().Throw<CoseException>();
    }

    [Fact]
    public void DecodeExposesHeadersWithoutVerifying()
    {
        byte[] encoded = TestCose.BuildSign1(
            writer =>
            {
                writer.WriteStartMap(2);
                writer.WriteInt64(1);
                writer.WriteInt64(-7);
                writer.WriteInt64(3);
                writer.WriteTextString("application/example");
                writer.WriteEndMap();
            },
            writer =>
            {
                writer.WriteStartMap(1);
                writer.WriteInt64(4);
                writer.WriteByteString("kid-1"u8);
                writer.WriteEndMap();
            },
            Payload,
            GarbageSignature64);

        CoseSign1Message message = CoseSign1.Decode(encoded);

        message.Algorithm.Should().Be(CoseAlgorithm.ES256);
        message.ContentType.Should().Be("application/example");
        message.KeyId!.Value.ToArray().Should().Equal("kid-1"u8.ToArray());
        message.Payload!.Value.ToArray().Should().Equal(Payload);
        message.IsTagged.Should().BeTrue();
    }

    // ----- tag abuse -----

    public static TheoryData<string, ulong, CoseVerificationErrorCode> WrongTags => new()
    {
        { "COSE_Encrypt0 (16)", 16, CoseVerificationErrorCode.UnsupportedCoseStructure },
        { "COSE_Mac0 (17)", 17, CoseVerificationErrorCode.UnsupportedCoseStructure },
        { "COSE_Encrypt (96)", 96, CoseVerificationErrorCode.UnsupportedCoseStructure },
        { "COSE_Mac (97)", 97, CoseVerificationErrorCode.UnsupportedCoseStructure },
        { "COSE_Sign (98)", 98, CoseVerificationErrorCode.UnsupportedCoseStructure },
        { "CWT tag (61) routed to the Sign1 API", 61, CoseVerificationErrorCode.UnexpectedCborTag },
        { "arbitrary tag (998)", 998, CoseVerificationErrorCode.UnexpectedCborTag },
    };

    [Theory]
    [MemberData(nameof(WrongTags))]
    public void WrongOuterTagIsRejected(string description, ulong tag, CoseVerificationErrorCode expected)
    {
        byte[] encoded = TestCose.BuildSign1(TestCose.ProtectedAlg(-7), null, Payload, GarbageSignature64, tag);

        CoseSign1VerificationResult result = CoseSign1.Verify(encoded, KeyType.P256, P256Key.PublicKey);

        result.Verified.Should().BeFalse(description);
        result.Failure!.Code.Should().Be(expected, description);
    }

    [Fact]
    public void ExcessiveTagNestingIsRejected()
    {
        byte[] untagged = TestCose.BuildSign1(TestCose.ProtectedAlg(-7), null, Payload, GarbageSignature64, tag: null);
        byte[] tripleTagged = TestCose.PrependTag(61, TestCose.PrependTag(18, TestCose.PrependTag(18, untagged)));

        CoseSign1.Verify(tripleTagged, KeyType.P256, P256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.UnexpectedCborTag);
    }

    // ----- algorithm header abuse -----

    [Fact]
    public void MissingAlgorithmIsRejected()
    {
        byte[] encoded = TestCose.BuildSign1(null, null, Payload, GarbageSignature64);

        CoseSign1.Verify(encoded, KeyType.P256, P256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.MissingAlgorithm);
    }

    [Fact]
    public void AlgorithmWithInvalidCborTypeIsRejected()
    {
        byte[] encoded = TestCose.BuildSign1(
            writer =>
            {
                writer.WriteStartMap(1);
                writer.WriteInt64(1);
                writer.WriteDouble(1.5); // alg must be int or tstr (RFC 9052 §3)
                writer.WriteEndMap();
            },
            null,
            Payload,
            GarbageSignature64);

        CoseSign1.Verify(encoded, KeyType.P256, P256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.UnsupportedAlgorithm);
    }

    [Fact]
    public async Task AlgorithmConfusionAcrossKeyTypesIsRejected()
    {
        // A validly signed EdDSA message must not verify when the caller pins a P-256 key:
        // the alg/key-type cross-check fires before any signature math.
        KeyPair edKey = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(edKey, TestCose.Crypto);
        byte[] encoded = await CoseSign1.SignAsync(Payload, signer, new CoseSign1SignOptions { Algorithm = CoseAlgorithm.EdDsa });

        CoseSign1VerificationResult result = CoseSign1.Verify(encoded, KeyType.P256, P256Key.PublicKey);

        result.Verified.Should().BeFalse();
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.AlgorithmKeyMismatch);
    }

    [Fact]
    public void WrongSignatureLengthIsRejectedWithoutCryptoCall()
    {
        byte[] encoded = TestCose.BuildSign1(TestCose.ProtectedAlg(-7), null, Payload, new byte[63]);

        CoseSign1.Verify(encoded, KeyType.P256, P256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidSignature);
    }

    // ----- critical headers (RFC 9052 §3.1) -----

    [Fact]
    public void UnknownCriticalIntegerLabelIsRejected()
    {
        byte[] encoded = TestCose.BuildSign1(
            writer =>
            {
                writer.WriteStartMap(3);
                writer.WriteInt64(1);
                writer.WriteInt64(-7);
                writer.WriteInt64(2); // crit
                writer.WriteStartArray(1);
                writer.WriteInt64(42);
                writer.WriteEndArray();
                writer.WriteInt64(42); // the critical, not-understood header itself
                writer.WriteTextString("x");
                writer.WriteEndMap();
            },
            null,
            Payload,
            GarbageSignature64);

        CoseSign1.Verify(encoded, KeyType.P256, P256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.UnknownCriticalHeader);
    }

    [Fact]
    public void UnknownCriticalTextLabelIsRejected()
    {
        byte[] encoded = TestCose.BuildSign1(
            writer =>
            {
                writer.WriteStartMap(2);
                writer.WriteInt64(1);
                writer.WriteInt64(-7);
                writer.WriteInt64(2);
                writer.WriteStartArray(1);
                writer.WriteTextString("vendor-extension");
                writer.WriteEndArray();
                writer.WriteEndMap();
            },
            null,
            Payload,
            GarbageSignature64);

        CoseSign1.Verify(encoded, KeyType.P256, P256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.UnknownCriticalHeader);
    }

    [Fact]
    public void CriticalListOfUnderstoodLabelsPassesTheCritGate()
    {
        // crit naming only labels this implementation understands (alg) must get past the crit
        // check and fail later on the garbage signature — proving the gate is label-specific.
        byte[] encoded = TestCose.BuildSign1(
            writer =>
            {
                writer.WriteStartMap(2);
                writer.WriteInt64(1);
                writer.WriteInt64(-7);
                writer.WriteInt64(2);
                writer.WriteStartArray(1);
                writer.WriteInt64(1);
                writer.WriteEndArray();
                writer.WriteEndMap();
            },
            null,
            Payload,
            GarbageSignature64);

        CoseSign1.Verify(encoded, KeyType.P256, P256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidSignature);
    }

    [Fact]
    public void EmptyCriticalArrayIsMalformed()
    {
        byte[] encoded = TestCose.BuildSign1(
            writer =>
            {
                writer.WriteStartMap(2);
                writer.WriteInt64(1);
                writer.WriteInt64(-7);
                writer.WriteInt64(2);
                writer.WriteStartArray(0);
                writer.WriteEndArray();
                writer.WriteEndMap();
            },
            null,
            Payload,
            GarbageSignature64);

        CoseSign1.Verify(encoded, KeyType.P256, P256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.MalformedMessage);
    }

    [Fact]
    public void CriticalHeaderInUnprotectedBucketIsMalformed()
    {
        byte[] encoded = TestCose.BuildSign1(
            TestCose.ProtectedAlg(-7),
            writer =>
            {
                writer.WriteStartMap(1);
                writer.WriteInt64(2); // crit must live in the protected bucket
                writer.WriteStartArray(1);
                writer.WriteInt64(1);
                writer.WriteEndArray();
                writer.WriteEndMap();
            },
            Payload,
            GarbageSignature64);

        CoseSign1.Verify(encoded, KeyType.P256, P256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.MalformedMessage);
    }

    // ----- header uniqueness (RFC 9052 §3) -----

    [Fact]
    public void DuplicateLabelAcrossBucketsIsMalformed()
    {
        byte[] encoded = TestCose.BuildSign1(
            TestCose.ProtectedAlg(-7),
            writer =>
            {
                writer.WriteStartMap(1);
                writer.WriteInt64(1); // alg again, now unprotected
                writer.WriteInt64(-7);
                writer.WriteEndMap();
            },
            Payload,
            GarbageSignature64);

        CoseSign1.Verify(encoded, KeyType.P256, P256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.MalformedMessage);
    }

    [Fact]
    public void NonIntegerNonTextHeaderLabelIsMalformed()
    {
        byte[] encoded = TestCose.BuildSign1(
            TestCose.ProtectedAlg(-7),
            writer =>
            {
                writer.WriteStartMap(1);
                writer.WriteStartArray(0); // a CBOR array is not a valid header label
                writer.WriteEndArray();
                writer.WriteInt64(0);
                writer.WriteEndMap();
            },
            Payload,
            GarbageSignature64);

        CoseSign1.Verify(encoded, KeyType.P256, P256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.MalformedMessage);
    }
}
