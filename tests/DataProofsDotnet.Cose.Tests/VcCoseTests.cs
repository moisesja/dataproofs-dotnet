using System.Text;
using DataProofsDotnet.Cose.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Cose.Tests;

/// <summary>
/// AC-4 VC-JOSE-COSE (COSE half, FR-19): enveloping a VCDM 2.0 payload as a COSE_Sign1 with
/// the spec's media types — content type (3) <c>application/vc</c> and typ (16)
/// <c>application/vc+cose</c>, both integrity-protected — validated on the round trip; wrong,
/// absent, or unprotected values rejected with the documented failure codes. The credential is
/// opaque JSON bytes; data-model validation is out of scope (PRD §11).
/// </summary>
public sealed class VcCoseTests
{
    /// <summary>A minimal VCDM 2.0 credential (enveloped-proof shape; no embedded proof member).</summary>
    private static readonly byte[] Credential = Encoding.UTF8.GetBytes(
        """
        {"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"https://university.example/issuers/565049","credentialSubject":{"id":"did:example:ebfeb1f712ebc6f1c276e12ec21","degree":"Bachelor of Science and Arts"}}
        """);

    public static TheoryData<CoseAlgorithm, KeyType> Algorithms => new()
    {
        { CoseAlgorithm.EdDsa, KeyType.Ed25519 },
        { CoseAlgorithm.ES256, KeyType.P256 },
        { CoseAlgorithm.ES384, KeyType.P384 },
        { CoseAlgorithm.ES256K, KeyType.Secp256k1 },
    };

    [Theory]
    [MemberData(nameof(Algorithms))]
    public async Task EnvelopeRoundTripsWithSpecHeaders(CoseAlgorithm algorithm, KeyType keyType)
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(keyType);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);

        byte[] envelope = await VcCose.EnvelopeCredentialAsync(Credential, signer, algorithm, keyId: "issuer-key"u8.ToArray());

        CoseSign1VerificationResult result = VcCose.Verify(envelope, keyType, keyPair.PublicKey);

        result.Verified.Should().BeTrue(result.Failure?.Message);
        result.Message!.ContentType.Should().Be(VcCose.CredentialContentType, "the spec's content type (3) header is produced");
        result.Message.Type.Should().Be(VcCose.EnvelopeType, "the spec's typ (16, RFC 9596) header is produced");
        result.Message.Payload!.Value.ToArray().Should().Equal(Credential, "the enveloped credential is carried opaquely");
        result.Message.KeyId!.Value.ToArray().Should().Equal("issuer-key"u8.ToArray());
        result.Message.IsTagged.Should().BeTrue();
    }

    [Fact]
    public async Task TamperedCredentialFails()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] envelope = await VcCose.EnvelopeCredentialAsync(Credential, signer, CoseAlgorithm.EdDsa);

        // The signature byte string (0x58 0x40 + 64 bytes) closes the message; the byte just
        // ahead of it is the credential's final '}'.
        byte[] tampered = TestCose.FlipByte(envelope, envelope.Length - 64 - 2 - 1);

        CoseSign1VerificationResult result = VcCose.Verify(tampered, KeyType.Ed25519, keyPair.PublicKey);
        result.Verified.Should().BeFalse();
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidSignature);
    }

    [Fact]
    public async Task AlgorithmConfusionFails()
    {
        KeyPair edKey = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        KeyPair p256Key = TestCose.KeyGenerator.Generate(KeyType.P256);
        var signer = new KeyPairSigner(edKey, TestCose.Crypto);
        byte[] envelope = await VcCose.EnvelopeCredentialAsync(Credential, signer, CoseAlgorithm.EdDsa);

        VcCose.Verify(envelope, KeyType.P256, p256Key.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.AlgorithmKeyMismatch);
    }

    // ----- content type (3) rejection -----

    [Fact]
    public async Task WrongContentTypeIsRejected()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] envelope = await CoseSign1.SignAsync(
            Credential,
            signer,
            new CoseSign1SignOptions
            {
                Algorithm = CoseAlgorithm.EdDsa,
                ContentType = "application/json", // wrong: must be application/vc
                Type = VcCose.EnvelopeType,
            });

        CoseSign1VerificationResult result = VcCose.Verify(envelope, KeyType.Ed25519, keyPair.PublicKey);
        result.Verified.Should().BeFalse();
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidContentType);
    }

    [Fact]
    public async Task AbsentContentTypeIsRejected()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] envelope = await CoseSign1.SignAsync(
            Credential,
            signer,
            new CoseSign1SignOptions { Algorithm = CoseAlgorithm.EdDsa, Type = VcCose.EnvelopeType });

        VcCose.Verify(envelope, KeyType.Ed25519, keyPair.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidContentType);
    }

    [Fact]
    public void UnprotectedContentTypeIsRejected()
    {
        // The headers must be integrity-protected; a content type in the unprotected bucket is
        // attacker-writable and must be refused before any signature math.
        byte[] envelope = TestCose.BuildSign1(
            writer =>
            {
                writer.WriteStartMap(2);
                writer.WriteInt64(1);
                writer.WriteInt64(-8);
                writer.WriteInt64(16);
                writer.WriteTextString(VcCose.EnvelopeType);
                writer.WriteEndMap();
            },
            writer =>
            {
                writer.WriteStartMap(1);
                writer.WriteInt64(3);
                writer.WriteTextString(VcCose.CredentialContentType);
                writer.WriteEndMap();
            },
            Credential,
            new byte[64]);

        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        VcCose.Verify(envelope, KeyType.Ed25519, keyPair.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidContentType);
    }

    // ----- typ (16) rejection -----

    [Fact]
    public async Task WrongTypeIsRejected()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] envelope = await CoseSign1.SignAsync(
            Credential,
            signer,
            new CoseSign1SignOptions
            {
                Algorithm = CoseAlgorithm.EdDsa,
                ContentType = VcCose.CredentialContentType,
                Type = "application/sd-jwt", // wrong: must be application/vc+cose
            });

        VcCose.Verify(envelope, KeyType.Ed25519, keyPair.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidType);
    }

    [Fact]
    public async Task AbsentTypeIsRejected()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] envelope = await CoseSign1.SignAsync(
            Credential,
            signer,
            new CoseSign1SignOptions { Algorithm = CoseAlgorithm.EdDsa, ContentType = VcCose.CredentialContentType });

        VcCose.Verify(envelope, KeyType.Ed25519, keyPair.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidType);
    }

    [Fact]
    public void UnprotectedTypeIsRejected()
    {
        byte[] envelope = TestCose.BuildSign1(
            writer =>
            {
                writer.WriteStartMap(2);
                writer.WriteInt64(1);
                writer.WriteInt64(-8);
                writer.WriteInt64(3);
                writer.WriteTextString(VcCose.CredentialContentType);
                writer.WriteEndMap();
            },
            writer =>
            {
                writer.WriteStartMap(1);
                writer.WriteInt64(16);
                writer.WriteTextString(VcCose.EnvelopeType);
                writer.WriteEndMap();
            },
            Credential,
            new byte[64]);

        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        VcCose.Verify(envelope, KeyType.Ed25519, keyPair.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidType);
    }

    // ----- a plain COSE_Sign1 is not a VC envelope -----

    [Fact]
    public async Task PlainCoseSign1IsRejectedAsVcEnvelope()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] plain = await CoseSign1.SignAsync(Credential, signer, new CoseSign1SignOptions { Algorithm = CoseAlgorithm.EdDsa });

        // Verifies as a generic COSE_Sign1 but is rejected by the VC-JOSE-COSE profile.
        CoseSign1.Verify(plain, KeyType.Ed25519, keyPair.PublicKey).Verified.Should().BeTrue();
        VcCose.Verify(plain, KeyType.Ed25519, keyPair.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidType);
    }

    // ----- payload shape misconfiguration (exceptions, FR-23) -----

    [Fact]
    public async Task MalformedJsonCredentialThrows()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);

        Func<Task> act = () => VcCose.EnvelopeCredentialAsync("{not json"u8.ToArray(), signer, CoseAlgorithm.EdDsa);

        await act.Should().ThrowAsync<CoseException>();
    }

    [Fact]
    public async Task NonObjectJsonCredentialThrows()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);

        Func<Task> act = () => VcCose.EnvelopeCredentialAsync("[1,2,3]"u8.ToArray(), signer, CoseAlgorithm.EdDsa);

        await act.Should().ThrowAsync<CoseException>();
    }
}
