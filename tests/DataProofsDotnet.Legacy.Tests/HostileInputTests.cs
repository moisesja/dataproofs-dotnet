using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// Hostile / malformed input must fail closed — <see cref="ICryptosuite.VerifyProof"/> returns a
/// <see cref="ProofVerificationResult.Failure"/>, never throws (FR-3). These exercise the suite
/// directly (the pipeline already removes the proof before calling), so the suite's own
/// fail-closed guards are covered.
/// </summary>
public class HostileInputTests
{
    private static readonly Ed25519Signature2020Cryptosuite Suite = new(LegacyCanonicalization.Jcs);

    private static readonly PublicKeyMaterial Key =
        PublicKeyMaterial.FromRaw(KeyType.Ed25519, Fx.SeedKey(0x0D, KeyType.Ed25519).PublicKey);

    private static JsonElement Document() => JsonSerializer.Deserialize<JsonElement>("""
        { "@context": "https://www.w3.org/ns/credentials/v2", "id": "urn:uuid:hostile" }
        """);

    private static DataIntegrityProof BaseProof() => new()
    {
        Type = Ed25519Signature2020Cryptosuite.ProofType,
        VerificationMethod = "did:key:zMethod#zMethod",
        ProofPurpose = ProofPurposes.AssertionMethod,
        Created = "2026-06-14T00:00:00.000000Z",
    };

    [Fact]
    public void ProofValueThatIsNotMultibase_FailsClosed()
    {
        var proof = BaseProof() with { ProofValue = "this-is-not-multibase!!" };

        var act = () => Suite.VerifyProof(Document(), proof, Key);
        var result = act.Should().NotThrow().Subject;
        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public void ProofValueInWrongMultibase_FailsClosed()
    {
        // base16 multibase ('f' header) — structurally valid multibase, wrong base for the
        // legacy family (which REQUIRES base58-btc / 'z').
        var proof = BaseProof() with { ProofValue = "f00112233" };

        var result = Suite.VerifyProof(Document(), proof, Key);
        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public void MissingProofValue_FailsClosed()
    {
        var proof = BaseProof(); // ProofValue is null

        var result = Suite.VerifyProof(Document(), proof, Key);
        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public void NonObjectDocument_FailsClosed()
    {
        var proof = BaseProof() with { ProofValue = "z111111111111111111111111111111111111111111111" };
        var array = JsonSerializer.Deserialize<JsonElement>("""["not","an","object"]""");

        var act = () => Suite.VerifyProof(array, proof, Key);
        var result = act.Should().NotThrow().Subject;
        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public void ProofCarryingCryptosuite_IsRejected()
    {
        // The legacy wire shape must NOT carry a cryptosuite; a proof that does is rejected.
        var proof = BaseProof() with
        {
            Cryptosuite = Ed25519Signature2020Cryptosuite.ProofType,
            ProofValue = "z111111111111111111111111111111111111111111111",
        };

        var result = Suite.VerifyProof(Document(), proof, Key);
        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public void WrongProofType_IsRejected()
    {
        var proof = BaseProof() with
        {
            Type = "SomeOtherSignature2099",
            ProofValue = "z111111111111111111111111111111111111111111111",
        };

        var result = Suite.VerifyProof(Document(), proof, Key);
        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public void NonObjectDocument_ThroughPipeline_FailsClosed()
    {
        // Defense in depth: the same hostile shape via the pipeline must also fail closed.
        var registry = CryptosuiteRegistry.CreateDefault();
        registry.Register(new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Jcs));
        var pipeline = new DataIntegrityProofPipeline(registry);
        var array = JsonSerializer.Deserialize<JsonElement>("""["not","an","object"]""");

        var act = () => pipeline.Verify(array, Key);
        var result = act.Should().NotThrow().Subject;
        result.Verified.Should().BeFalse();
    }
}
