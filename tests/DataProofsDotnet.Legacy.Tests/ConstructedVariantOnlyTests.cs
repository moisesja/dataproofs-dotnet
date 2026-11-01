using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// <see cref="LegacyVariantVerification.ConstructedVariantOnly"/>: a verifier whose profile allows
/// one canonicalization variant must not accept a proof made with the other. The default,
/// <see cref="LegacyVariantVerification.Both"/>, still falls back (see <see cref="VariantIsolationTests"/>).
/// </summary>
public class ConstructedVariantOnlyTests
{
    // ed25519-2020/v1 defines the Ed25519Signature2020 proof terms. EcdsaSecp256r1Signature2019 has
    // no published context, so its proof terms come from undefined-terms/v2 (VCDM 2.0 §5.2).
    private const string Ed25519Contexts = """
        "https://www.w3.org/ns/credentials/v2", "https://w3id.org/security/suites/ed25519-2020/v1",
        "https://www.w3.org/ns/credentials/undefined-terms/v2"
        """;

    private const string P256Contexts = """
        "https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/undefined-terms/v2"
        """;

    public static TheoryData<string, LegacyCanonicalization> Matrix() => new()
    {
        { Ed25519Signature2020Cryptosuite.ProofType, LegacyCanonicalization.Jcs },
        { Ed25519Signature2020Cryptosuite.ProofType, LegacyCanonicalization.Rdfc },
        { EcdsaSecp256r1Signature2019Cryptosuite.ProofType, LegacyCanonicalization.Jcs },
        { EcdsaSecp256r1Signature2019Cryptosuite.ProofType, LegacyCanonicalization.Rdfc },
    };

    private static ICryptosuite Suite(
        string legacyType, LegacyCanonicalization variant, LegacyVariantVerification verification)
        => legacyType == Ed25519Signature2020Cryptosuite.ProofType
            ? new Ed25519Signature2020Cryptosuite(variant, verification: verification)
            : new EcdsaSecp256r1Signature2019Cryptosuite(variant, verification: verification);

    private static LegacyCanonicalization Other(LegacyCanonicalization variant)
        => variant == LegacyCanonicalization.Jcs ? LegacyCanonicalization.Rdfc : LegacyCanonicalization.Jcs;

    private static JsonElement Document(string legacyType) => JsonSerializer.Deserialize<JsonElement>($$"""
        {
          "@context": [{{(legacyType == Ed25519Signature2020Cryptosuite.ProofType ? Ed25519Contexts : P256Contexts)}}],
          "id": "urn:uuid:constructed-variant-only",
          "claim": "value"
        }
        """);

    private static async Task<(DataIntegrityProof Proof, PublicKeyMaterial PublicKey)> SignAsync(
        string legacyType, LegacyCanonicalization variant)
    {
        var keyType = legacyType == Ed25519Signature2020Cryptosuite.ProofType ? KeyType.Ed25519 : KeyType.P256;
        var keyPair = Fx.SeedKey(0x2c, keyType);
        var signer = Fx.Signer(keyPair);
        var options = new DataIntegrityProof
        {
            Type = legacyType,
            VerificationMethod = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}",
            ProofPurpose = ProofPurposes.AssertionMethod,
            Created = "2026-10-28T00:00:00Z",
        };
        var proof = await Suite(legacyType, variant, LegacyVariantVerification.Both)
            .CreateProofAsync(Document(legacyType), options, signer);
        return (proof, PublicKeyMaterial.FromRaw(keyType, keyPair.PublicKey));
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public async Task AcceptsItsOwnVariant(string legacyType, LegacyCanonicalization variant)
    {
        var (proof, publicKey) = await SignAsync(legacyType, variant);

        Suite(legacyType, variant, LegacyVariantVerification.ConstructedVariantOnly)
            .VerifyProof(Document(legacyType), proof, publicKey).Verified.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public async Task RejectsTheOtherVariant(string legacyType, LegacyCanonicalization variant)
    {
        var (proof, publicKey) = await SignAsync(legacyType, Other(variant));

        var result = Suite(legacyType, variant, LegacyVariantVerification.ConstructedVariantOnly)
            .VerifyProof(Document(legacyType), proof, publicKey);

        result.Verified.Should().BeFalse("a proof made with the other variant must not verify");
        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError);
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public async Task Default_StillAcceptsTheOtherVariant(string legacyType, LegacyCanonicalization variant)
    {
        var (proof, publicKey) = await SignAsync(legacyType, Other(variant));

        Suite(legacyType, variant, LegacyVariantVerification.Both)
            .VerifyProof(Document(legacyType), proof, publicKey).Verified.Should().BeTrue();
        (legacyType == Ed25519Signature2020Cryptosuite.ProofType
                ? (ICryptosuite)new Ed25519Signature2020Cryptosuite(variant)
                : new EcdsaSecp256r1Signature2019Cryptosuite(variant))
            .VerifyProof(Document(legacyType), proof, publicKey).Verified.Should().BeTrue(
                "omitting the verification argument keeps the fallback");
    }

    [Fact]
    public async Task Rdfc_DataLoss_IsReportedAsDataLossDetectionError()
    {
        // With one variant the failure is unambiguous, so it is reported as the RDFC suites do.
        var legacyType = Ed25519Signature2020Cryptosuite.ProofType;
        var (proof, publicKey) = await SignAsync(legacyType, LegacyCanonicalization.Rdfc);
        // RDFC would sign this id as https://e.example/users/alice, so the canonicalizer refuses it.
        var tampered = Fx.Mutate(Document(legacyType), document => document["id"] = "https://e.example/x/%2E%2E/users/alice");

        var strict = Suite(legacyType, LegacyCanonicalization.Rdfc, LegacyVariantVerification.ConstructedVariantOnly)
            .VerifyProof(tampered, proof, publicKey);
        var both = Suite(legacyType, LegacyCanonicalization.Rdfc, LegacyVariantVerification.Both)
            .VerifyProof(tampered, proof, publicKey);

        strict.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.DataLossDetectionError);
        both.Verified.Should().BeFalse();
        both.Problems.Should().ContainSingle().Which.Code.Should().NotBe(ProofProblemCodes.DataLossDetectionError,
            "Both keeps its dual-variant result codes");
    }

    [Fact]
    public async Task Rdfc_SignsAStringsBaseDirection()
    {
        // The RDFC canonicalizer carries @direction in the i18n datatype (issue #40), so the legacy RDFC
        // variant signs it and a flipped direction fails. The strict mode shows the RDFC result alone.
        var legacyType = Ed25519Signature2020Cryptosuite.ProofType;
        var document = Fx.Mutate(Document(legacyType), d => d["name"] = new JsonObject
        {
            ["@value"] = "x", ["@language"] = "ar", ["@direction"] = "rtl",
        });
        var keyPair = Fx.SeedKey(0x40);
        var signer = Fx.Signer(keyPair);
        var publicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, keyPair.PublicKey);
        var options = new DataIntegrityProof
        {
            Type = legacyType,
            VerificationMethod = $"did:key:{signer.MultibasePublicKey}#{signer.MultibasePublicKey}",
            ProofPurpose = ProofPurposes.AssertionMethod,
            Created = "2026-10-30T00:00:00Z",
        };
        var strict = Suite(legacyType, LegacyCanonicalization.Rdfc, LegacyVariantVerification.ConstructedVariantOnly);

        var proof = await strict.CreateProofAsync(document, options, signer);
        var flipped = Fx.Mutate(document, d => d["name"]!["@direction"] = "ltr");

        strict.VerifyProof(document, proof, publicKey).Verified.Should().BeTrue();
        var result = strict.VerifyProof(flipped, proof, publicKey);
        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public async Task Jcs_DocumentWithProofMember_IsATransformationError()
    {
        var legacyType = Ed25519Signature2020Cryptosuite.ProofType;
        var (proof, publicKey) = await SignAsync(legacyType, LegacyCanonicalization.Jcs);
        var chained = Fx.Mutate(Document(legacyType), document => document["proof"] = new System.Text.Json.Nodes.JsonObject());

        var result = Suite(legacyType, LegacyCanonicalization.Jcs, LegacyVariantVerification.ConstructedVariantOnly)
            .VerifyProof(chained, proof, publicKey);

        result.Problems.Should().ContainSingle().Which.Code.Should().Be(ProofProblemCodes.ProofTransformationError);
    }

    [Theory]
    [InlineData(typeof(Ed25519Signature2020Cryptosuite))]
    [InlineData(typeof(EcdsaSecp256r1Signature2019Cryptosuite))]
    public void UndefinedVerificationValue_IsRefused(Type suite)
    {
        // Enum.TryParse and configuration binding accept "2"; it must not act as Both.
        Enum.TryParse<LegacyVariantVerification>("2", out var undefined).Should().BeTrue();

        var act = () => Activator.CreateInstance(suite, LegacyCanonicalization.Rdfc, null, undefined);

        act.Should().Throw<System.Reflection.TargetInvocationException>()
            .WithInnerException<ArgumentOutOfRangeException>().Which.ParamName.Should().Be("verification");
    }

    [Theory]
    [InlineData(typeof(Ed25519Signature2020Cryptosuite))]
    [InlineData(typeof(EcdsaSecp256r1Signature2019Cryptosuite))]
    public void UndefinedCanonicalizationValue_IsRefused(Type suite)
    {
        // Every variant comparison reads "== Rdfc", so an undefined value would act as JCS: a verifier
        // configured "RDFC only" from a bad setting would accept JCS proofs, which is what strict mode
        // exists to refuse (PR #39 adversarial review).
        Enum.TryParse<LegacyCanonicalization>("2", out var undefined).Should().BeTrue();

        var act = () => Activator.CreateInstance(suite, undefined, null, LegacyVariantVerification.ConstructedVariantOnly);

        act.Should().Throw<System.Reflection.TargetInvocationException>()
            .WithInnerException<ArgumentOutOfRangeException>().Which.ParamName.Should().Be("canonicalization");
    }
}
