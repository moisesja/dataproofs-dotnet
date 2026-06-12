using DataProofsDotnet.Cose.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Cose.Tests;

/// <summary>
/// AC-4 creation round-trips for every v1 algorithm (FR-19: EdDSA -8, ES256 -7, ES384 -35,
/// ES256K -47), including the ES256K coverage that the cose-wg corpus cannot provide (the
/// upstream repository carries no secp256k1 vectors at the pinned commit — see PROVENANCE.md).
/// Also exercises detached payloads, external AAD, tag emission control, key-store-backed
/// signing (the AC-8 posture), and Ed25519 output determinism (NFR-5).
/// </summary>
public sealed class CoseSign1RoundTripTests
{
    private static readonly byte[] Payload = "Round-trip payload."u8.ToArray();

    public static TheoryData<CoseAlgorithm, KeyType> Algorithms => new()
    {
        { CoseAlgorithm.EdDsa, KeyType.Ed25519 },
        { CoseAlgorithm.ES256, KeyType.P256 },
        { CoseAlgorithm.ES384, KeyType.P384 },
        { CoseAlgorithm.ES256K, KeyType.Secp256k1 },
    };

    [Theory]
    [MemberData(nameof(Algorithms))]
    public async Task SignThenVerifyRoundTrips(CoseAlgorithm algorithm, KeyType keyType)
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(keyType);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);

        byte[] encoded = await CoseSign1.SignAsync(
            Payload,
            signer,
            new CoseSign1SignOptions { Algorithm = algorithm, KeyId = "key-1"u8.ToArray() });

        CoseSign1VerificationResult result = CoseSign1.Verify(encoded, keyType, keyPair.PublicKey);

        result.Verified.Should().BeTrue(result.Failure?.Message);
        result.Message!.Algorithm.Should().Be(algorithm);
        result.Message.IsTagged.Should().BeTrue("tag 18 is emitted by default");
        result.Message.KeyId!.Value.ToArray().Should().Equal("key-1"u8.ToArray());
        result.Message.Payload!.Value.ToArray().Should().Equal(Payload);
        result.Message.Signature.Length.Should().Be(
            algorithm == CoseAlgorithm.ES384 ? 96 : 64,
            "COSE signatures are fixed-width R‖S (RFC 9053)");
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public async Task TamperedPayloadFailsVerification(CoseAlgorithm algorithm, KeyType keyType)
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(keyType);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] encoded = await CoseSign1.SignAsync(Payload, signer, new CoseSign1SignOptions { Algorithm = algorithm });

        // The signature byte string closes the message: 0x58 <len> <sig>. The byte immediately
        // before that framing is the last payload byte — flip it.
        int signatureLength = algorithm == CoseAlgorithm.ES384 ? 96 : 64;
        byte[] tampered = TestCose.FlipByte(encoded, encoded.Length - signatureLength - 2 - 1);

        CoseSign1VerificationResult result = CoseSign1.Verify(tampered, keyType, keyPair.PublicKey);
        result.Verified.Should().BeFalse();
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidSignature);
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public async Task WrongKeyFailsVerification(CoseAlgorithm algorithm, KeyType keyType)
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(keyType);
        KeyPair otherKeyPair = TestCose.KeyGenerator.Generate(keyType);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] encoded = await CoseSign1.SignAsync(Payload, signer, new CoseSign1SignOptions { Algorithm = algorithm });

        CoseSign1VerificationResult result = CoseSign1.Verify(encoded, keyType, otherKeyPair.PublicKey);

        result.Verified.Should().BeFalse();
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidSignature);
    }

    [Fact]
    public async Task KeyStoreBackedSignerSuffices()
    {
        // FR-19/AC-8 posture: a signer backed by a non-exporting IKeyStore must be sufficient —
        // including for the NIST curves whose store signature arrives as DER and is transcoded.
        var store = new InMemoryKeyStore(TestCose.KeyGenerator, TestCose.Crypto);
        StoredKeyInfo info = await store.GenerateAsync("cose-key", KeyType.P256);
        ISigner signer = await store.CreateSignerAsync("cose-key");

        byte[] encoded = await CoseSign1.SignAsync(
            Payload,
            signer,
            new CoseSign1SignOptions { Algorithm = CoseAlgorithm.ES256 });

        CoseSign1.Verify(encoded, KeyType.P256, info.PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task Ed25519OutputIsDeterministic()
    {
        // NFR-5: identical inputs + key + suite ⇒ byte-identical envelope (Ed25519 signing is
        // deterministic; ECDSA is inherently randomized and covered by round-trips instead).
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        var options = new CoseSign1SignOptions { Algorithm = CoseAlgorithm.EdDsa, ContentType = "text/plain" };

        byte[] first = await CoseSign1.SignAsync(Payload, signer, options);
        byte[] second = await CoseSign1.SignAsync(Payload, signer, options);

        second.Should().Equal(first);
    }

    [Fact]
    public async Task UntaggedEmissionRoundTrips()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);

        byte[] encoded = await CoseSign1.SignAsync(
            Payload,
            signer,
            new CoseSign1SignOptions { Algorithm = CoseAlgorithm.EdDsa, IncludeCoseSign1Tag = false });

        encoded[0].Should().Be(0x84, "an untagged COSE_Sign1 starts with the 4-element array header");
        CoseSign1VerificationResult result = CoseSign1.Verify(encoded, KeyType.Ed25519, keyPair.PublicKey);
        result.Verified.Should().BeTrue();
        result.Message!.IsTagged.Should().BeFalse();
        result.Message.KeyId.Should().BeNull("no kid was emitted — absence must surface as null, not empty");
    }

    // ----- detached payload (RFC 9052 §4.1: nil payload, supplied at verification) -----

    [Fact]
    public async Task DetachedPayloadRoundTrips()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.P256);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);

        byte[] encoded = await CoseSign1.SignAsync(
            Payload,
            signer,
            new CoseSign1SignOptions { Algorithm = CoseAlgorithm.ES256, DetachedPayload = true });

        CoseSign1.Decode(encoded).Payload.Should().BeNull("the payload travels detached");

        CoseSign1VerificationResult result = CoseSign1.Verify(
            encoded,
            KeyType.P256,
            keyPair.PublicKey,
            new CoseSign1VerifyOptions { DetachedPayload = Payload });
        result.Verified.Should().BeTrue();
    }

    [Fact]
    public async Task DetachedPayloadMissingAtVerificationFails()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.P256);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] encoded = await CoseSign1.SignAsync(
            Payload,
            signer,
            new CoseSign1SignOptions { Algorithm = CoseAlgorithm.ES256, DetachedPayload = true });

        CoseSign1VerificationResult result = CoseSign1.Verify(encoded, KeyType.P256, keyPair.PublicKey);

        result.Verified.Should().BeFalse();
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.PayloadMissing);
    }

    [Fact]
    public async Task WrongDetachedPayloadFails()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.P256);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] encoded = await CoseSign1.SignAsync(
            Payload,
            signer,
            new CoseSign1SignOptions { Algorithm = CoseAlgorithm.ES256, DetachedPayload = true });

        CoseSign1VerificationResult result = CoseSign1.Verify(
            encoded,
            KeyType.P256,
            keyPair.PublicKey,
            new CoseSign1VerifyOptions { DetachedPayload = "Different payload."u8.ToArray() });

        result.Verified.Should().BeFalse();
        result.Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidSignature);
    }

    [Fact]
    public async Task SupplyingDetachedPayloadForEmbeddedMessageIsMisconfiguration()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.P256);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] encoded = await CoseSign1.SignAsync(Payload, signer, new CoseSign1SignOptions { Algorithm = CoseAlgorithm.ES256 });

        Action act = () => CoseSign1.Verify(
            encoded,
            KeyType.P256,
            keyPair.PublicKey,
            new CoseSign1VerifyOptions { DetachedPayload = Payload });

        act.Should().Throw<ArgumentException>("an embedded payload plus a detached payload is a caller bug, not message data");
    }

    // ----- external AAD (RFC 9052 §4.4) -----

    [Fact]
    public async Task ExternalDataRoundTripsAndMismatchFails()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);
        byte[] aad = "external-authenticated-data"u8.ToArray();

        byte[] encoded = await CoseSign1.SignAsync(
            Payload,
            signer,
            new CoseSign1SignOptions { Algorithm = CoseAlgorithm.EdDsa, ExternalData = aad });

        CoseSign1.Verify(encoded, KeyType.Ed25519, keyPair.PublicKey, new CoseSign1VerifyOptions { ExternalData = aad })
            .Verified.Should().BeTrue();

        CoseSign1.Verify(encoded, KeyType.Ed25519, keyPair.PublicKey)
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidSignature, "omitting the AAD must fail");

        CoseSign1.Verify(
                encoded,
                KeyType.Ed25519,
                keyPair.PublicKey,
                new CoseSign1VerifyOptions { ExternalData = "different-aad"u8.ToArray() })
            .Failure!.Code.Should().Be(CoseVerificationErrorCode.InvalidSignature, "a different AAD must fail");
    }

    // ----- signing misconfiguration: exceptions, not results (FR-23) -----

    [Fact]
    public async Task AlgorithmKeyTypeMismatchAtSigningThrows()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);

        Func<Task> act = () => CoseSign1.SignAsync(Payload, signer, new CoseSign1SignOptions { Algorithm = CoseAlgorithm.ES256 });

        await act.Should().ThrowAsync<CoseException>();
    }

    [Fact]
    public async Task UndefinedAlgorithmValueThrows()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);

        Func<Task> act = () => CoseSign1.SignAsync(Payload, signer, new CoseSign1SignOptions { Algorithm = (CoseAlgorithm)(-999) });

        await act.Should().ThrowAsync<CoseException>();
    }

    [Fact]
    public async Task ContentTypeAndContentFormatAreMutuallyExclusive()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);

        Func<Task> act = () => CoseSign1.SignAsync(
            Payload,
            signer,
            new CoseSign1SignOptions
            {
                Algorithm = CoseAlgorithm.EdDsa,
                ContentType = "application/json",
                ContentFormat = 50,
            });

        await act.Should().ThrowAsync<CoseException>();
    }

    [Fact]
    public async Task NegativeContentFormatThrows()
    {
        KeyPair keyPair = TestCose.KeyGenerator.Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(keyPair, TestCose.Crypto);

        Func<Task> act = () => CoseSign1.SignAsync(
            Payload,
            signer,
            new CoseSign1SignOptions { Algorithm = CoseAlgorithm.EdDsa, ContentFormat = -1 });

        await act.Should().ThrowAsync<CoseException>();
    }
}
