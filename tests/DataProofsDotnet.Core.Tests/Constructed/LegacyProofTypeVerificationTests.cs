using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.Core.Tests.TestSupport;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCid;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Constructed;

/// <summary>
/// Issue #4 / FR-4: the verify pipeline must dispatch a proof to a registered cryptosuite
/// by proof <c>type</c> when the proof carries no <c>cryptosuite</c> member — the shape of
/// legacy Linked-Data-Signature proofs (e.g. <c>Ed25519Signature2020</c>). A custom
/// <see cref="ICryptosuite"/> that emits and verifies that legacy shape must round-trip on
/// the same pipeline, closing the create→verify inconsistency, without disturbing the
/// shipped 2022/2019 JCS suites.
/// </summary>
public class LegacyProofTypeVerificationTests
{
    private const string LegacyType = "Ed25519Signature2020";
    private const string VerificationMethod = "did:example:legacy#key-1";
    private const string Controller = "did:example:legacy";

    private static JsonElement UnsignedDocument()
        => Fx.Json("constructed", "controller", "unsigned-credential.json");

    private static (DataIntegrityProofPipeline Pipeline, KeyPair Key) LegacyPipeline()
    {
        // The legacy suite registered ALONGSIDE the shipped JCS suites, so coexistence is
        // exercised: dispatch by cryptosuite name (JCS) and by type (legacy) on one registry.
        var registry = CryptosuiteRegistry.CreateDefault();
        registry.Register(new LegacyEd25519Suite());
        return (new DataIntegrityProofPipeline(registry), Fx.SeedKey(0x42));
    }

    private static async Task<JsonElement> SignLegacyAsync(DataIntegrityProofPipeline pipeline, KeyPair key)
        => await pipeline.AddProofAsync(
            UnsignedDocument(),
            new DataIntegrityProof
            {
                Cryptosuite = LegacyType,   // dispatch key on the create path
                Type = LegacyType,
                Created = "2026-01-02T00:00:00Z",
                VerificationMethod = VerificationMethod,
                ProofPurpose = ProofPurposes.AssertionMethod,
            },
            Fx.Signer(key));

    [Fact]
    public async Task AddProof_EmitsLegacyShape_NoCryptosuiteMember()
    {
        var (pipeline, key) = LegacyPipeline();

        var secured = await SignLegacyAsync(pipeline, key);

        var proof = secured.GetProperty("proof");
        proof.GetProperty("type").GetString().Should().Be(LegacyType);
        proof.TryGetProperty("cryptosuite", out _).Should().BeFalse("a legacy proof names its algorithm by type");
        proof.GetProperty("proofValue").GetString().Should().StartWith("z", "base58-btc multibase");
    }

    [Fact]
    public async Task LegacyProof_RoundTrips_OnTheSamePipeline_RawKey()
    {
        // The create→verify inconsistency from issue #4: the pipeline emits a legacy-shaped
        // proof and must then verify that very document.
        var (pipeline, key) = LegacyPipeline();
        var secured = await SignLegacyAsync(pipeline, key);

        var result = pipeline.Verify(secured, PublicKeyMaterial.FromRaw(KeyType.Ed25519, key.PublicKey));

        result.Verified.Should().BeTrue();
    }

    [Fact]
    public async Task LegacyProof_TamperedDocument_FailsClosed()
    {
        var (pipeline, key) = LegacyPipeline();
        var secured = await SignLegacyAsync(pipeline, key);
        var tampered = Fx.Mutate(secured, node => node["credentialSubject"] = "tampered");

        var result = pipeline.Verify(tampered, PublicKeyMaterial.FromRaw(KeyType.Ed25519, key.PublicKey));

        result.Verified.Should().BeFalse();
    }

    [Fact]
    public async Task LegacyProof_WrongKey_FailsClosed()
    {
        var (pipeline, key) = LegacyPipeline();
        var secured = await SignLegacyAsync(pipeline, key);

        var result = pipeline.Verify(
            secured, PublicKeyMaterial.FromRaw(KeyType.Ed25519, Fx.SeedKey(0x01).PublicKey));

        result.Verified.Should().BeFalse();
    }

    [Fact]
    public async Task ProofType_WithNoRegisteredSuite_IsRejected()
    {
        // Negative: a proof whose type matches no registered suite (here a different legacy
        // type) is rejected with PROOF_VERIFICATION_ERROR — no silent acceptance.
        var (pipeline, key) = LegacyPipeline();
        var secured = await SignLegacyAsync(pipeline, key);
        var retyped = Fx.Mutate(secured, node => node["proof"]!["type"] = "Ed25519Signature2018");

        var result = pipeline.Verify(retyped, PublicKeyMaterial.FromRaw(KeyType.Ed25519, key.PublicKey));

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public async Task JcsSuites_StillRoundTrip_AlongsideARegisteredLegacySuite()
    {
        // Coexistence: registering a legacy type-named suite must not disturb dispatch of
        // the shipped JCS suites (still keyed by cryptosuite name).
        var (pipeline, _) = LegacyPipeline();
        var key = Fx.SeedKey(0x42);

        var secured = await pipeline.AddProofAsync(
            UnsignedDocument(),
            new DataIntegrityProof
            {
                Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
                Created = "2026-01-02T00:00:00Z",
                VerificationMethod = VerificationMethod,
                ProofPurpose = ProofPurposes.AssertionMethod,
            },
            Fx.Signer(key));

        secured.GetProperty("proof").GetProperty("cryptosuite").GetString()
            .Should().Be(EddsaJcs2022Cryptosuite.CryptosuiteName);
        pipeline.Verify(secured, PublicKeyMaterial.FromRaw(KeyType.Ed25519, key.PublicKey))
            .Verified.Should().BeTrue();
    }

    [Fact]
    public async Task LegacyProof_VerifiesOnResolverPath_WhenAuthorized()
    {
        var (pipeline, key) = LegacyPipeline();
        var secured = await SignLegacyAsync(pipeline, key);

        var result = await pipeline.VerifyAsync(
            secured,
            Resolver(key, ProofPurposes.AssertionMethod),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeTrue();
    }

    [Fact]
    public async Task LegacyProof_ResolverPath_EnforcesControllerAuthorization()
    {
        // FR-7 controller authorization still gates legacy-type proofs: the method's
        // signature is valid, but the controller lists it under authentication only.
        var (pipeline, key) = LegacyPipeline();
        var secured = await SignLegacyAsync(pipeline, key);

        var result = await pipeline.VerifyAsync(
            secured,
            Resolver(key, ProofPurposes.Authentication),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.InvalidVerificationMethod);
    }

    private static StaticVerificationMethodResolver Resolver(KeyPair key, string relationship)
        => new(
        [
            new ResolvedVerificationMethod
            {
                Id = VerificationMethod,
                Controller = Controller,
                PublicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, key.PublicKey),
                ControllerControlsMethod = true,
                Relationships = new HashSet<string>(StringComparer.Ordinal) { relationship },
            },
        ]);

    /// <summary>
    /// A minimal custom suite that emits and verifies the legacy <c>Ed25519Signature2020</c>
    /// shape (type-named, no <c>cryptosuite</c>). Its internal signing payload is a real
    /// Ed25519 signature over <c>SHA-256(documentBytes ‖ proofConfigBytes)</c>; the mechanic
    /// only needs to be self-consistent — the point under test is the pipeline's dispatch.
    /// </summary>
    private sealed class LegacyEd25519Suite : ICryptosuite
    {
        public string Name => LegacyType;   // registry key for the create-path dispatch

        public IReadOnlyCollection<string> SupportedProofTypes => [LegacyType];

        public async Task<DataIntegrityProof> CreateProofAsync(
            JsonElement unsecuredDocument, DataIntegrityProof proofOptions, ISigner signer,
            CancellationToken cancellationToken = default)
        {
            var proofConfig = proofOptions with { Type = LegacyType, Cryptosuite = null, ProofValue = null };
            var signature = await signer.SignAsync(Payload(unsecuredDocument, proofConfig), cancellationToken)
                .ConfigureAwait(false);
            return proofConfig with { ProofValue = Multibase.Encode(signature, MultibaseEncoding.Base58Btc) };
        }

        public ProofVerificationResult VerifyProof(
            JsonElement unsecuredDocument, DataIntegrityProof proof, PublicKeyMaterial publicKey)
        {
            if (!string.Equals(proof.Type, LegacyType, StringComparison.Ordinal) || proof.Cryptosuite is not null)
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "Not a legacy Ed25519Signature2020 proof.", proof);
            }

            if (string.IsNullOrEmpty(proof.ProofValue)
                || !Multibase.TryDecode(proof.ProofValue, out var signature, out var encoding)
                || encoding != MultibaseEncoding.Base58Btc)
            {
                return ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The proofValue is not base58-btc multibase.", proof);
            }

            var payload = Payload(unsecuredDocument, proof with { ProofValue = null });
            return Fx.Crypto.Verify(publicKey.KeyType, publicKey.KeyBytes.Span, payload, signature)
                ? ProofVerificationResult.Success(proof)
                : ProofVerificationResult.Failure(
                    ProofProblemCodes.ProofVerificationError, "The signature did not verify.", proof);
        }

        private static byte[] Payload(JsonElement document, DataIntegrityProof proofConfig)
        {
            var documentBytes = JsonSerializer.SerializeToUtf8Bytes(document, DataProofsJsonOptions.Default);
            var proofConfigBytes = JsonSerializer.SerializeToUtf8Bytes(proofConfig, DataProofsJsonOptions.Default);
            return Hash.Sha256([.. documentBytes, .. proofConfigBytes]);
        }
    }
}
