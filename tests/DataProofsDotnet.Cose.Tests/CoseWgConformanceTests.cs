using DataProofsDotnet.Cose.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Cose.Tests;

/// <summary>
/// AC-4 verify-direction theories over every vendored cose-wg/Examples fixture
/// (<c>tests/fixtures/cose-wg/</c>, pinned commit in PROVENANCE.md), plus Sig_structure
/// byte-exactness against the fixtures' <c>ToBeSign_hex</c> intermediates and
/// creation-direction byte checks. The vendored set is the complete upstream COSE_Sign1
/// population for the v1 algorithm set; exclusions are recorded in PROVENANCE.md and
/// re-asserted by the manifest test below.
/// </summary>
public sealed class CoseWgConformanceTests
{
    // ----- manifest -----

    /// <summary>
    /// Guards against silently dropped fixture files: the on-disk fixture set must be exactly
    /// the 12 files recorded in PROVENANCE.md. Upstream files NOT vendored, and why
    /// (full enumeration in PROVENANCE.md):
    ///   - eddsa-examples/eddsa-01.json, eddsa-02.json; ecdsa-examples/ecdsa-01..04.json —
    ///     COSE_Sign (multi-signer), not COSE_Sign1;
    ///   - eddsa-examples/eddsa-sig-02.json — Ed448 (v1 EdDSA scope is Ed25519 only);
    ///   - ecdsa-examples/ecdsa-sig-03.json, ecdsa-sig-04.json — ES512 / P-521, outside the v1 set;
    ///   - sign1-tests/sign-fail-05.json — does not exist upstream (numbering skips 05);
    ///   - all MAC/encryption/ECDH/RSA/countersign/CWT/X25519/x509/hashsig directories — not
    ///     COSE_Sign1 signature vectors (CWT coverage comes from RFC 8392 Appendix A instead);
    ///   - ES256K — upstream carries no secp256k1 vectors at the pinned commit; ES256K is
    ///     covered by creation round-trips in <see cref="CoseSign1RoundTripTests"/>.
    /// </summary>
    [Fact]
    public void VendoredFixtureSetMatchesProvenanceManifest()
    {
        string root = Fixtures.PathOf("cose-wg");
        string[] actual = Directory
            .EnumerateFiles(root, "*.json", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/'))
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToArray();

        actual.Should().BeEquivalentTo(
        [
            "ecdsa-examples/ecdsa-sig-01.json",
            "ecdsa-examples/ecdsa-sig-02.json",
            "eddsa-examples/eddsa-sig-01.json",
            "sign1-tests/sign-fail-01.json",
            "sign1-tests/sign-fail-02.json",
            "sign1-tests/sign-fail-03.json",
            "sign1-tests/sign-fail-04.json",
            "sign1-tests/sign-fail-06.json",
            "sign1-tests/sign-fail-07.json",
            "sign1-tests/sign-pass-01.json",
            "sign1-tests/sign-pass-02.json",
            "sign1-tests/sign-pass-03.json",
        ]);

        File.Exists(Path.Combine(root, "PROVENANCE.md")).Should().BeTrue();
        File.Exists(Path.Combine(root, "LICENSE")).Should().BeTrue();
    }

    // ----- verify direction: positive fixtures -----

    public static TheoryData<string> PositiveFixtures => new()
    {
        "sign1-tests/sign-pass-01.json",  // alg in unprotected bucket; protected wire-encoded as h'A0' ("redo protected")
        "sign1-tests/sign-pass-02.json",  // external AAD mixed into Sig_structure
        "sign1-tests/sign-pass-03.json",  // untagged COSE_Sign1
        "eddsa-examples/eddsa-sig-01.json",
        "ecdsa-examples/ecdsa-sig-01.json",
        "ecdsa-examples/ecdsa-sig-02.json",
    };

    [Theory]
    [MemberData(nameof(PositiveFixtures))]
    public void PositiveFixturesVerify(string relativePath)
    {
        CoseWgExample example = CoseWgExample.Load(relativePath);
        example.ExpectFail.Should().BeFalse("the fixture is a positive case");

        CoseSign1VerificationResult result = CoseSign1.Verify(
            example.Cbor,
            example.KeyType,
            example.PublicKey,
            new CoseSign1VerifyOptions { ExternalData = example.ExternalData });

        result.Verified.Should().BeTrue($"{example.Title}: {result.Failure?.Message}");
        result.Failure.Should().BeNull();
        result.Message.Should().NotBeNull();
        result.Message!.Payload!.Value.ToArray().Should().Equal("This is the content."u8.ToArray());
    }

    // ----- verify direction: negative fixtures, each with its documented failure code -----

    public static TheoryData<string, CoseVerificationErrorCode> NegativeFixtures => new()
    {
        // Wrong CBOR tag (998) wrapping the structure.
        { "sign1-tests/sign-fail-01.json", CoseVerificationErrorCode.UnexpectedCborTag },
        // Payload byte changed after signing.
        { "sign1-tests/sign-fail-02.json", CoseVerificationErrorCode.InvalidSignature },
        // alg header changed to the unregistered integer -999.
        { "sign1-tests/sign-fail-03.json", CoseVerificationErrorCode.UnsupportedAlgorithm },
        // alg header changed to the text string "unknown".
        { "sign1-tests/sign-fail-04.json", CoseVerificationErrorCode.UnsupportedAlgorithm },
        // Protected header added after signing — protected bytes no longer match the signature.
        { "sign1-tests/sign-fail-06.json", CoseVerificationErrorCode.InvalidSignature },
        // Protected header removed after signing.
        { "sign1-tests/sign-fail-07.json", CoseVerificationErrorCode.InvalidSignature },
    };

    [Theory]
    [MemberData(nameof(NegativeFixtures))]
    public void NegativeFixturesFailWithDocumentedCode(string relativePath, CoseVerificationErrorCode expectedCode)
    {
        CoseWgExample example = CoseWgExample.Load(relativePath);
        example.ExpectFail.Should().BeTrue("the fixture is an upstream negative case");

        CoseSign1VerificationResult result = CoseSign1.Verify(example.Cbor, example.KeyType, example.PublicKey);

        result.Verified.Should().BeFalse(example.Title);
        result.Failure.Should().NotBeNull();
        result.Failure!.Code.Should().Be(expectedCode, example.Title);
    }

    // ----- Sig_structure byte-exactness (RFC 9052 §4.4) -----

    /// <summary>
    /// Fixtures whose ToBeSign_hex matches their final wire bytes. The other negative fixtures
    /// (fail-02/03/04/06/07) tamper with the payload or protected bucket *after* signing, so
    /// their recorded intermediate deliberately differs from what their wire bytes re-derive;
    /// they are excluded here and covered by the failure-code theory above. sign-fail-01 only
    /// changes the outer tag, which is not part of Sig_structure, so it stays in.
    /// </summary>
    public static TheoryData<string> SigStructureFixtures => new()
    {
        "sign1-tests/sign-pass-01.json",  // exercises the h'A0' → zero-length protected normalization
        "sign1-tests/sign-pass-02.json",  // exercises external AAD placement
        "sign1-tests/sign-pass-03.json",
        "sign1-tests/sign-fail-01.json",
        "eddsa-examples/eddsa-sig-01.json",
        "ecdsa-examples/ecdsa-sig-01.json",
        "ecdsa-examples/ecdsa-sig-02.json",
    };

    [Theory]
    [MemberData(nameof(SigStructureFixtures))]
    public void SignatureInputIsByteExact(string relativePath)
    {
        CoseWgExample example = CoseWgExample.Load(relativePath);
        example.ToBeSign.Should().NotBeNull("the fixture provides a ToBeSign_hex intermediate");

        // sign-fail-01 carries tag 998, which Decode rejects; its Sig_structure is unaffected
        // by the outer tag, so strip the tag and decode the bare structure.
        byte[] encoded = relativePath == "sign1-tests/sign-fail-01.json"
            ? TestCose.StripLeadingTag(example.Cbor)
            : example.Cbor;

        CoseSign1Message message = CoseSign1.Decode(encoded);
        byte[] signatureInput = CoseSign1.GetSignatureInput(message, example.ExternalData);

        signatureInput.Should().Equal(example.ToBeSign!, example.Title);
    }

    // ----- creation direction -----

    /// <summary>
    /// Ed25519 signing is deterministic (RFC 8032), so re-creating eddsa-sig-01 from its inputs
    /// must reproduce the fixture wire bytes exactly — protected headers {1: -8, 3: 0},
    /// unprotected {4: h'3131'}, tag 18, and the signature itself.
    /// </summary>
    [Fact]
    public async Task EdDsaCreationIsByteExact()
    {
        CoseWgExample example = CoseWgExample.Load("eddsa-examples/eddsa-sig-01.json");
        ISigner signer = TestCose.SignerFor(KeyType.Ed25519, example.PrivateKey);

        byte[] created = await CoseSign1.SignAsync(
            "This is the content."u8.ToArray(),
            signer,
            new CoseSign1SignOptions
            {
                Algorithm = CoseAlgorithm.EdDsa,
                ContentFormat = 0,
                KeyId = "11"u8.ToArray(),
            });

        created.Should().Equal(example.Cbor);
    }

    /// <summary>
    /// ECDSA signing is randomized, so the creation direction asserts the deterministic
    /// intermediates byte-exactly (protected bucket and Sig_structure must equal the vector's)
    /// and round-trips the final signature through verification.
    /// </summary>
    public static TheoryData<string, CoseAlgorithm> EcdsaCreationFixtures => new()
    {
        { "ecdsa-examples/ecdsa-sig-01.json", CoseAlgorithm.ES256 },
        { "ecdsa-examples/ecdsa-sig-02.json", CoseAlgorithm.ES384 },
    };

    [Theory]
    [MemberData(nameof(EcdsaCreationFixtures))]
    public async Task EcdsaCreationMatchesVectorIntermediatesAndRoundTrips(string relativePath, CoseAlgorithm algorithm)
    {
        CoseWgExample example = CoseWgExample.Load(relativePath);
        ISigner signer = TestCose.SignerFor(example.KeyType, example.PrivateKey);

        // ecdsa-sig-01 carries ctyp 0 in its protected bucket; ecdsa-sig-02 carries alg only.
        var options = new CoseSign1SignOptions
        {
            Algorithm = algorithm,
            ContentFormat = relativePath.EndsWith("ecdsa-sig-01.json", StringComparison.Ordinal) ? 0 : null,
            KeyId = relativePath.EndsWith("ecdsa-sig-01.json", StringComparison.Ordinal)
                ? "11"u8.ToArray()
                : "P384"u8.ToArray(),
        };
        byte[] created = await CoseSign1.SignAsync("This is the content."u8.ToArray(), signer, options);

        CoseSign1Message message = CoseSign1.Decode(created);
        CoseSign1Message expected = CoseSign1.Decode(example.Cbor);
        message.EncodedProtectedHeaders.ToArray().Should().Equal(
            expected.EncodedProtectedHeaders.ToArray(),
            "the protected bucket is deterministic CBOR");
        CoseSign1.GetSignatureInput(message).Should().Equal(example.ToBeSign!,
            "the Sig_structure must be byte-identical to the vector even though the signature is randomized");

        CoseSign1.Verify(created, example.KeyType, example.PublicKey).Verified.Should().BeTrue();
    }
}
