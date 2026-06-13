using DataProofsDotnet;
using DataProofsDotnet.Core.Tests.TestSupport;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Constructed;

/// <summary>
/// AC-1 step 5: controller authorization on the resolver path (FR-3/FR-7), driven by
/// the constructed fixtures under <c>tests/fixtures/constructed/controller/</c>
/// (see that directory's PROVENANCE.md).
/// </summary>
public class ControllerAuthorizationTests
{
    private static readonly string[] Root = ["constructed", "controller"];
    private static readonly DataIntegrityProofPipeline Pipeline = new();

    private static string[] In(string file) => [.. Root, file];

    private static string PublicKeyMultibase(string key)
        => Fx.Json(In("keys.json")).GetProperty(key).GetProperty("publicKeyMultibase").GetString()!;

    [Fact]
    public async Task AuthorizedMethod_VerifiesOnResolverPath()
    {
        // (a) key-a is listed under assertionMethod by the controller document.
        var result = await Pipeline.VerifyAsync(
            Fx.Json(In("signed-assertion.json")),
            Fx.ControllerResolver(Fx.Json(In("controller-document.json"))),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeTrue();
        result.ProofResults.Should().ContainSingle().Which.Verified.Should().BeTrue();
    }

    [Fact]
    public async Task UnlistedRelationship_FailsWithInvalidVerificationMethod()
    {
        // (b) key-b's signature is valid, but the controller document lists key-b under
        // authentication only — never assertionMethod.
        var result = await Pipeline.VerifyAsync(
            Fx.Json(In("signed-unauthorized.json")),
            Fx.ControllerResolver(Fx.Json(In("controller-document.json"))),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.InvalidVerificationMethod);
    }

    [Fact]
    public async Task AuthorizationFailure_IsDistinctFromProofPurposeFieldMismatch()
    {
        // (b, distinctness) Same document, same valid signature:
        //   - controller authorization failure -> INVALID_VERIFICATION_METHOD;
        //   - proofPurpose FIELD mismatch       -> PROOF_VERIFICATION_ERROR.
        var signed = Fx.Json(In("signed-unauthorized.json"));
        var resolver = Fx.ControllerResolver(Fx.Json(In("controller-document.json")));

        var authorizationFailure = await Pipeline.VerifyAsync(
            signed, resolver, new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });
        var purposeFieldMismatch = await Pipeline.VerifyAsync(
            signed, resolver, new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.Authentication });

        var authorizationCode = authorizationFailure.ProofResults.Single().Problems.Single().Code;
        var mismatchCode = purposeFieldMismatch.ProofResults.Single().Problems.Single().Code;

        authorizationCode.Should().Be(ProofProblemCodes.InvalidVerificationMethod);
        mismatchCode.Should().Be(ProofProblemCodes.ProofVerificationError);
        authorizationCode.Should().NotBe(mismatchCode);
    }

    [Fact]
    public async Task NonControllingController_FailsWithInvalidVerificationMethod()
    {
        // (c) The rogue controller document claims key-a, but the method's controller
        // property names a different subject -> the controller does not control it.
        var result = await Pipeline.VerifyAsync(
            Fx.Json(In("signed-assertion.json")),
            Fx.ControllerResolver(Fx.Json(In("controller-document-rogue.json"))),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.InvalidVerificationMethod);
    }

    [Fact]
    public void RawKeyOverload_VerifiesTheSameSignature_WithoutAuthorizationGate()
    {
        // (d) The very signature that fails controller authorization verifies through
        // the raw-key overload — the gate lives only on the resolver path.
        var result = Pipeline.Verify(
            Fx.Json(In("signed-unauthorized.json")),
            PublicKeyMaterial.FromMultikey(PublicKeyMultibase("key-b")),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeTrue();
    }

    [Fact]
    public async Task UnresolvableMethod_FailsWithInvalidVerificationMethod()
    {
        var result = await Pipeline.VerifyAsync(
            Fx.Json(In("signed-assertion.json")),
            new StaticVerificationMethodResolver([]),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.InvalidVerificationMethod);
    }

    [Fact]
    public async Task ThrowingResolver_FailsClosed_WithProofVerificationError()
    {
        var result = await Pipeline.VerifyAsync(
            Fx.Json(In("signed-assertion.json")),
            new ThrowingResolver(),
            new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    private sealed class ThrowingResolver : IVerificationMethodResolver
    {
        public Task<ResolvedVerificationMethod?> ResolveAsync(
            string verificationMethodUrl, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("Resolver infrastructure fault.");
    }
}
