using System.Formats.Cbor;
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

    // ----- malformed public key (COSE A1, FR-23 fail-closed) -----

    /// <summary>
    /// COSE A1 regression. VerifyCore hands the caller-supplied public key straight to the
    /// NetCrypto key import inside CoseCryptography.Verify. A genuinely malformed key
    /// (wrong-length Ed25519, an all-zero "EC point") makes that import throw FormatException /
    /// ArgumentException / CryptographicException. Before the fix that exception escaped
    /// CoseSign1.Verify, violating the contract that verification never throws on
    /// attacker-controlled input (FR-3/FR-23). This proves the verify path now fails closed —
    /// a structured InvalidSignature result, no exception. Run against the unfixed VerifyCore
    /// (no try/catch around CoseCryptography.Verify) this test throws instead of returning.
    /// </summary>
    [Fact]
    public async Task MalformedEd25519PublicKeyYieldsStructuredFailure()
    {
        // A genuinely signed EdDSA message verified against a 31-byte (too short) Ed25519 key.
        KeyPair edKey = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(edKey, TestCose.Crypto);
        byte[] encoded = await CoseSign1.SignAsync(Payload, signer, new CoseSign1SignOptions { Algorithm = CoseAlgorithm.EdDsa });

        byte[] malformedKey = new byte[31]; // Ed25519 raw keys are exactly 32 bytes

        CoseSign1VerificationResult result = default!;
        Action act = () => result = CoseSign1.Verify(encoded, KeyType.Ed25519, malformedKey);

        act.Should().NotThrow("a malformed public key must fail closed, never crash the verifier");
        result.Verified.Should().BeFalse();
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidSignature);
    }

    /// <summary>
    /// COSE A1 regression, EC variant: an all-zero 33-byte buffer is not a valid SEC1 compressed
    /// point (0x00 is not a legal compression prefix and the point is not on the curve), so the
    /// NIST EC import throws. Verification must convert that into a structured failure.
    /// </summary>
    [Fact]
    public async Task MalformedEcPublicKeyYieldsStructuredFailure()
    {
        KeyPair ecKey = TestCose.KeyGenerator.Generate(KeyType.P256);
        var signer = new KeyPairSigner(ecKey, TestCose.Crypto);
        byte[] encoded = await CoseSign1.SignAsync(Payload, signer, new CoseSign1SignOptions { Algorithm = CoseAlgorithm.ES256 });

        byte[] malformedKey = new byte[33]; // all-zero: not a valid compressed SEC1 point

        CoseSign1VerificationResult result = default!;
        Action act = () => result = CoseSign1.Verify(encoded, KeyType.P256, malformedKey);

        act.Should().NotThrow("a malformed EC public key must fail closed, never crash the verifier");
        result.Verified.Should().BeFalse();
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidSignature);
    }

    // ----- crit label absent from protected bucket (COSE A3, RFC 9052 §3.1) -----

    /// <summary>
    /// COSE A3 regression. RFC 9052 §3.1: "If the 'crit' value list includes a label for which
    /// the header parameter is not in the protected-header-parameters bucket, this is a fatal
    /// error in processing the message." The crit array below names label 3 (content type — a
    /// label this implementation understands, so the unknown-critical gate does not fire) but no
    /// label-3 parameter is present in the protected bucket. Before the fix this verified true
    /// (the absent-but-declared crit label was silently accepted); now it is rejected as a
    /// malformed message. Uses a real key/signature so the only thing standing between the
    /// message and a signature check is the crit-presence rule.
    /// </summary>
    [Fact]
    public async Task CriticalLabelAbsentFromProtectedBucketIsRejected()
    {
        // Sign a real message, then re-wrap it with a protected header that declares crit:[3]
        // without carrying a label-3 parameter. We rebuild the protected bucket and re-sign so
        // the signature is valid over the tampered protected bytes — isolating the crit rule as
        // the sole reason for rejection (proving it is not just an InvalidSignature side effect).
        KeyPair edKey = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(edKey, TestCose.Crypto);

        // {1: -8 (EdDSA), 2: [3]} — alg present, crit names label 3, but no label-3 parameter.
        byte[] encoded = await SignWithProtectedMapAsync(
            signer,
            writeProtectedMap: writer =>
            {
                writer.WriteStartMap(2);
                writer.WriteInt64(1);
                writer.WriteInt64(-8);
                writer.WriteInt64(2);
                writer.WriteStartArray(1);
                writer.WriteInt64(3); // content type, understood — so this is NOT an unknown-crit failure
                writer.WriteEndArray();
                writer.WriteEndMap();
            });

        CoseSign1VerificationResult result = CoseSign1.Verify(encoded, KeyType.Ed25519, edKey.PublicKey);

        result.Verified.Should().BeFalse("a crit label absent from the protected bucket is a fatal error (RFC 9052 §3.1)");
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.MalformedMessage);
    }

    /// <summary>
    /// COSE A3 positive control: when the crit label IS present in the protected bucket the
    /// message must still verify — proving the new rule is presence-specific and does not reject
    /// well-formed crit usage. Here crit:[3] is satisfied by a label-3 (content type) parameter.
    /// </summary>
    [Fact]
    public async Task CriticalLabelPresentInProtectedBucketStillVerifies()
    {
        KeyPair edKey = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(edKey, TestCose.Crypto);

        byte[] encoded = await SignWithProtectedMapAsync(
            signer,
            writeProtectedMap: writer =>
            {
                writer.WriteStartMap(3);
                writer.WriteInt64(1);
                writer.WriteInt64(-8);
                writer.WriteInt64(2);
                writer.WriteStartArray(1);
                writer.WriteInt64(3);
                writer.WriteEndArray();
                writer.WriteInt64(3); // the label-3 parameter the crit array requires
                writer.WriteTextString("application/example");
                writer.WriteEndMap();
            });

        CoseSign1.Verify(encoded, KeyType.Ed25519, edKey.PublicKey)
            .Verified.Should().BeTrue("crit:[3] is satisfied by a present label-3 parameter");
    }

    /// <summary>
    /// Builds a tagged COSE_Sign1 with a caller-controlled protected header and a valid EdDSA
    /// signature computed over it, so a verification failure can only come from header-processing
    /// rules — not from a bad signature.
    /// </summary>
    private static async Task<byte[]> SignWithProtectedMapAsync(ISigner signer, Action<CborWriter> writeProtectedMap)
    {
        var protectedWriter = new CborWriter(CborConformanceMode.Lax);
        writeProtectedMap(protectedWriter);
        byte[] protectedBytes = protectedWriter.Encode();

        // Sig_structure = ["Signature1", protected, external_aad (empty), payload] (RFC 9052 §4.4).
        var sigInput = new CborWriter(CborConformanceMode.Canonical);
        sigInput.WriteStartArray(4);
        sigInput.WriteTextString("Signature1");
        sigInput.WriteByteString(protectedBytes);
        sigInput.WriteByteString([]);
        sigInput.WriteByteString(Payload);
        sigInput.WriteEndArray();
        byte[] signature = await signer.SignAsync(sigInput.Encode());

        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteTag((CborTag)18);
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedBytes);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString(Payload);
        writer.WriteByteString(signature);
        writer.WriteEndArray();
        return writer.Encode();
    }
}
