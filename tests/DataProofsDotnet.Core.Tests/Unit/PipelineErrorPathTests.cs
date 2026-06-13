using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.Core.Tests.TestSupport;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>
/// FR-2/FR-3/FR-23 error paths: creation faults throw <see cref="ProofGenerationException"/>;
/// verification of invalid/hostile input returns failed results with the spec-aligned
/// problem codes and NEVER throws.
/// </summary>
public class PipelineErrorPathTests
{
    private static readonly DataIntegrityProofPipeline Pipeline = new();

    private static readonly PublicKeyMaterial Ed25519Key =
        PublicKeyMaterial.FromRaw(KeyType.Ed25519, Fx.SeedKey(0x01).PublicKey);

    // MaxDepth 256 so hostile deeply-nested inputs reach the pipeline (whose canonicalizer
    // enforces its own 64-level limit) instead of failing in the test helper's parse.
    private static JsonElement Doc(string json) =>
        JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 256 }).RootElement.Clone();

    // A duplicate-tolerant parse: JsonDocument's default rejects duplicate member names, so a
    // duplicate-key document would fail in the test helper before reaching the pipeline. Setting
    // AllowDuplicateProperties=true lets the duplicate survive into the JsonElement so the
    // pipeline's OWN materialization (JsonObject.Create(...).Remove(...)) is what must fail closed.
    private static JsonElement DocAllowingDuplicateKeys(string json) =>
        JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 256, AllowDuplicateProperties = true }).RootElement.Clone();

    private static DataIntegrityProof ValidOptions() => new()
    {
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-01T00:00:00Z",
        VerificationMethod = "did:example:alice#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    private static Task<JsonElement> Sign(JsonElement document, DataIntegrityProof options)
        => Pipeline.AddProofAsync(document, options, Fx.Signer(Fx.SeedKey(0x01)));

    // --------------------------------------------------- creation: exceptions (FR-23)

    [Fact]
    public async Task AddProof_NonObjectDocument_Throws()
        => await FluentActions.Invoking(() => Sign(Doc("[1,2]"), ValidOptions()))
            .Should().ThrowAsync<ProofGenerationException>();

    [Fact]
    public async Task AddProof_MissingCryptosuite_Throws()
        => await FluentActions.Invoking(() => Sign(Doc("{}"), ValidOptions() with { Cryptosuite = null }))
            .Should().ThrowAsync<ProofGenerationException>();

    [Fact]
    public async Task AddProof_UnknownCryptosuite_Throws()
        => await FluentActions.Invoking(() => Sign(Doc("{}"), ValidOptions() with { Cryptosuite = "no-such-suite" }))
            .Should().ThrowAsync<ProofGenerationException>();

    [Fact]
    public async Task AddProof_OptionsCarryingProofValue_Throws()
        => await FluentActions.Invoking(() => Sign(Doc("{}"), ValidOptions() with { ProofValue = "z1" }))
            .Should().ThrowAsync<ProofGenerationException>();

    [Fact]
    public async Task AddProof_MissingProofPurposeOrVerificationMethod_Throws()
    {
        await FluentActions.Invoking(() => Sign(Doc("{}"), ValidOptions() with { ProofPurpose = null }))
            .Should().ThrowAsync<ProofGenerationException>();
        await FluentActions.Invoking(() => Sign(Doc("{}"), ValidOptions() with { VerificationMethod = null }))
            .Should().ThrowAsync<ProofGenerationException>();
    }

    [Fact]
    public async Task AddProof_WrongOptionsType_Throws()
        => await FluentActions.Invoking(() => Sign(Doc("{}"), ValidOptions() with { Type = "Ed25519Signature2020" }))
            .Should().ThrowAsync<ProofGenerationException>();

    [Theory]
    [InlineData("2026-01-01T00:00:00")] // no timezone designator
    [InlineData("2026-01-01")]
    [InlineData("not-a-date")]
    public async Task AddProof_InvalidCreatedTimestamp_Throws(string created)
        => await FluentActions.Invoking(() => Sign(Doc("{}"), ValidOptions() with { Created = created }))
            .Should().ThrowAsync<ProofGenerationException>();

    [Fact]
    public async Task AddProof_WrongSignerKeyType_Throws()
    {
        var ecdsaSigner = Fx.Signer(Fx.SeedKey(0x01, KeyType.P256));

        await FluentActions.Invoking(() => Pipeline.AddProofAsync(Doc("{}"), ValidOptions(), ecdsaSigner))
            .Should().ThrowAsync<ProofGenerationException>();
    }

    [Fact]
    public async Task AddProof_MalformedExistingProofMember_Throws()
        => await FluentActions.Invoking(() => Sign(Doc("""{"proof":"not-an-object"}"""), ValidOptions()))
            .Should().ThrowAsync<ProofGenerationException>();

    [Fact]
    public async Task AddProof_NullArguments_ThrowArgumentNullException()
    {
        await FluentActions.Invoking(() => Pipeline.AddProofAsync(Doc("{}"), null!, Fx.Signer(Fx.SeedKey(0x01))))
            .Should().ThrowAsync<ArgumentNullException>();
        await FluentActions.Invoking(() => Pipeline.AddProofAsync(Doc("{}"), ValidOptions(), null!))
            .Should().ThrowAsync<ArgumentNullException>();
    }

    // ------------------------------------------- verification: results, never throws

    [Theory]
    [InlineData("42")]
    [InlineData("\"text\"")]
    [InlineData("[]")]
    public void Verify_NonObjectDocument_FailsWithoutThrowing(string json)
    {
        var result = Pipeline.Verify(Doc(json), Ed25519Key);

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Theory]
    [InlineData("""{"a":1}""")] // no proof member
    [InlineData("""{"proof":[]}""")] // empty proof array
    [InlineData("""{"proof":"zzz"}""")] // proof member is a string
    [InlineData("""{"proof":17}""")] // proof member is a number
    public void Verify_MissingOrMalformedProofMember_FailsWithoutThrowing(string json)
    {
        var result = Pipeline.Verify(Doc(json), Ed25519Key);

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public void Verify_ProofArrayWithNonObjectEntry_FailsThatEntryWithoutThrowing()
    {
        var result = Pipeline.Verify(Doc("""{"proof":[17]}"""), Ed25519Key);

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Theory]
    [InlineData("""{"proof":{"cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:example:a#1","proofPurpose":"assertionMethod","proofValue":"z1"}}""")] // missing type
    [InlineData("""{"proof":{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","proofPurpose":"assertionMethod","proofValue":"z1"}}""")] // missing verificationMethod
    [InlineData("""{"proof":{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:example:a#1","proofValue":"z1"}}""")] // missing proofPurpose
    public void Verify_MissingMandatoryProofMembers_FailsWithoutThrowing(string json)
    {
        var result = Pipeline.Verify(Doc(json), Ed25519Key);

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public void Verify_UnparsableProof_FailsWithoutThrowing()
    {
        // previousProof of the wrong JSON kind makes the proof unparsable.
        var result = Pipeline.Verify(
            Doc("""{"proof":{"type":"DataIntegrityProof","previousProof":42}}"""), Ed25519Key);

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Should()
            .ContainSingle(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public void Verify_UnknownSuiteOrWrongType_FailsWithoutThrowing()
    {
        var unknownSuite = Pipeline.Verify(
            Doc("""{"proof":{"type":"DataIntegrityProof","cryptosuite":"no-such-suite","verificationMethod":"did:example:a#1","proofPurpose":"assertionMethod","proofValue":"z1"}}"""),
            Ed25519Key);
        var wrongType = Pipeline.Verify(
            Doc("""{"proof":{"type":"Ed25519Signature2020","cryptosuite":"eddsa-jcs-2022","verificationMethod":"did:example:a#1","proofPurpose":"assertionMethod","proofValue":"z1"}}"""),
            Ed25519Key);

        unknownSuite.Verified.Should().BeFalse();
        unknownSuite.ProofResults.Single().Problems.Single().Code.Should().Be(ProofProblemCodes.ProofVerificationError);
        wrongType.Verified.Should().BeFalse();
        wrongType.ProofResults.Single().Problems.Single().Code.Should().Be(ProofProblemCodes.ProofVerificationError);
    }

    // ------------------------------------------------ domain / challenge / expiry

    private static async Task<JsonElement> SignedWith(DataIntegrityProof options)
        => await Sign(Doc("""{"@context":["https://www.w3.org/ns/credentials/v2"],"k":"v"}"""), options);

    [Fact]
    public async Task Verify_DomainMismatch_FailsWithInvalidDomainError()
    {
        var signed = await SignedWith(ValidOptions() with { Domain = "https://rp.example" });

        var mismatch = Pipeline.Verify(signed, Ed25519Key,
            new ProofVerificationOptions { ExpectedDomain = "https://other.example" });
        var missing = Pipeline.Verify(await SignedWith(ValidOptions()), Ed25519Key,
            new ProofVerificationOptions { ExpectedDomain = "https://rp.example" });
        var match = Pipeline.Verify(signed, Ed25519Key,
            new ProofVerificationOptions { ExpectedDomain = "https://rp.example" });

        mismatch.ProofResults.Single().Problems.Single().Code.Should().Be(ProofProblemCodes.InvalidDomainError);
        missing.ProofResults.Single().Problems.Single().Code.Should().Be(ProofProblemCodes.InvalidDomainError);
        match.Verified.Should().BeTrue();
    }

    [Fact]
    public async Task Verify_ChallengeMismatch_FailsWithInvalidChallengeError()
    {
        var signed = await SignedWith(ValidOptions() with { Challenge = "expected-challenge" });

        var mismatch = Pipeline.Verify(signed, Ed25519Key,
            new ProofVerificationOptions { ExpectedChallenge = "other-challenge" });
        var match = Pipeline.Verify(signed, Ed25519Key,
            new ProofVerificationOptions { ExpectedChallenge = "expected-challenge" });

        mismatch.ProofResults.Single().Problems.Single().Code.Should().Be(ProofProblemCodes.InvalidChallengeError);
        match.Verified.Should().BeTrue();
    }

    [Fact]
    public async Task Verify_ExpiredProof_Fails_AndUnexpiredProofVerifies()
    {
        var signed = await SignedWith(ValidOptions() with { Expires = "2026-06-01T00:00:00Z" });

        var expired = Pipeline.Verify(signed, Ed25519Key,
            new ProofVerificationOptions { VerificationTime = new DateTimeOffset(2026, 7, 1, 0, 0, 0, TimeSpan.Zero) });
        var unexpired = Pipeline.Verify(signed, Ed25519Key,
            new ProofVerificationOptions { VerificationTime = new DateTimeOffset(2026, 5, 1, 0, 0, 0, TimeSpan.Zero) });

        expired.Verified.Should().BeFalse();
        expired.ProofResults.Single().Problems.Single().Code.Should().Be(ProofProblemCodes.ProofVerificationError);
        unexpired.Verified.Should().BeTrue();
    }

    [Fact]
    public async Task Verify_MalformedTimestamps_FailWithoutThrowing()
    {
        var signed = await SignedWith(ValidOptions());
        var badExpires = Fx.Mutate(signed, n => ((JsonObject)n["proof"]!)["expires"] = "not-a-date");
        var badCreated = Fx.Mutate(signed, n => ((JsonObject)n["proof"]!)["created"] = "2026-01-01T00:00:00");

        Pipeline.Verify(badExpires, Ed25519Key).Verified.Should().BeFalse();
        Pipeline.Verify(badCreated, Ed25519Key).Verified.Should().BeFalse();
    }

    // -------------------------------------------------- proofValue and @context

    [Fact]
    public async Task Verify_MissingOrNonBase58ProofValue_FailsWithoutThrowing()
    {
        var signed = await SignedWith(ValidOptions());
        var missing = Fx.Mutate(signed, n => ((JsonObject)n["proof"]!).Remove("proofValue"));
        var base64url = Fx.Mutate(signed, n => ((JsonObject)n["proof"]!)["proofValue"] = "uAAAA");
        var garbage = Fx.Mutate(signed, n => ((JsonObject)n["proof"]!)["proofValue"] = "!!!not-multibase");

        foreach (var hostile in new[] { missing, base64url, garbage })
        {
            var result = Pipeline.Verify(hostile, Ed25519Key);
            result.Verified.Should().BeFalse();
            result.ProofResults.Single().Problems.Single().Code
                .Should().Be(ProofProblemCodes.ProofVerificationError);
        }
    }

    [Fact]
    public async Task Verify_DocumentContextNotStartingWithProofContext_Fails()
    {
        var signed = await SignedWith(ValidOptions());
        var rewritten = Fx.Mutate(signed, n =>
            n["@context"] = new JsonArray("https://example.org/replaced-context/v1"));

        var result = Pipeline.Verify(rewritten, Ed25519Key);

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Single().Code
            .Should().Be(ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public async Task Verify_DocumentContextExtendedAfterProofContext_StillVerifies()
    {
        // The JCS suites canonicalize under the proof's @context when the document's
        // @context merely EXTENDS it (starts-with rule).
        var signed = await SignedWith(ValidOptions());
        var extended = Fx.Mutate(signed, n =>
            ((JsonArray)n["@context"]!).Add("https://example.org/extra-context/v1"));

        Pipeline.Verify(extended, Ed25519Key).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task Verify_DuplicateTopLevelMember_FailsWithTransformationError_NotThrow()
    {
        // FR-3/FR-23 regression. A secured document with a DUPLICATE top-level member is hostile
        // input: when the pipeline materializes it via JsonObject.Create(securedDocument).Remove(...)
        // the backing dictionary build throws ArgumentException on the duplicate key. Before the
        // fix that exception escaped Verify (it only caught JsonException) and crashed the verifier.
        // Now ArgumentException is caught → PROOF_TRANSFORMATION_ERROR. This test exercises the
        // pipeline's OWN parse path: the duplicate is preserved into the JsonElement (the test
        // helper tolerates duplicates at parse), so the pipeline — not the helper — is what fails.
        // Run against the unfixed Verify (catch covering only JsonException) this throws
        // ArgumentException instead of returning a result.
        var signed = await SignedWith(ValidOptions());

        // Re-serialize the signed document and splice in a duplicate top-level member ("v":"a"/"v":"b").
        var asJson = JsonSerializer.Serialize(signed);
        asJson.Should().StartWith("{");
        var withDuplicate = "{\"v\":\"a\",\"v\":\"b\"," + asJson[1..];
        var hostile = DocAllowingDuplicateKeys(withDuplicate);

        DocumentVerificationResult? result = null;
        Action act = () => result = Pipeline.Verify(hostile, Ed25519Key);

        act.Should().NotThrow("a duplicate top-level member is attacker-controlled input and must fail closed (FR-23)");
        result!.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Single().Code
            .Should().Be(ProofProblemCodes.ProofTransformationError);
    }

    [Fact]
    public void Verify_OversizedHostileDocument_FailsWithTransformationError_NotThrow()
    {
        // 70 levels of nesting exceeds the JCS canonicalizer's 64-level hard limit; the
        // pipeline must map that to PROOF_TRANSFORMATION_ERROR, not an exception.
        var deep = string.Concat(Enumerable.Repeat("{\"a\":", 70)) + "1" + new string('}', 70);
        var document = Doc($$$"""
            {"@context":["https://www.w3.org/ns/credentials/v2"],"nested":{{{deep}}},"proof":{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2026-01-01T00:00:00Z","verificationMethod":"did:example:a#1","proofPurpose":"assertionMethod","proofValue":"z3FXQ"}}
            """);

        var result = Pipeline.Verify(document, Ed25519Key);

        result.Verified.Should().BeFalse();
        result.ProofResults.Single().Problems.Single().Code
            .Should().Be(ProofProblemCodes.ProofTransformationError);
    }
}
