using System.Text.Json;
using DataProofsDotnet;
using DataProofsDotnet.Core.Tests.TestSupport;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Internal;
using DataProofsDotnet.Tests.Shared;
using FluentAssertions;
using NetCrypto;
using Xunit;
using static DataProofsDotnet.Tests.Shared.HostileJson;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>Issue #33: the shared pipeline matrix through <c>eddsa-jcs-2022</c>.</summary>
public sealed class Issue33JcsPipelineTests : Issue33PipelineTestsBase
{
    protected override DataIntegrityProofPipeline Pipeline { get; } = new();

    protected override string Cryptosuite => EddsaJcs2022Cryptosuite.CryptosuiteName;
}

/// <summary>Issue #33: the shared suite matrix through <c>eddsa-jcs-2022</c>'s own <c>CreateProofAsync</c>.</summary>
public sealed class Issue33EddsaJcsCreateTests : Issue33SuiteCreateTestsBase
{
    protected override ICryptosuite Suite { get; } = new EddsaJcs2022Cryptosuite();

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x01));

    protected override DataIntegrityProof Options() => new()
    {
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-01T00:00:00Z",
        VerificationMethod = "did:example:alice#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };
}

/// <summary>Issue #33: the shared suite matrix through <c>ecdsa-jcs-2019</c>'s own <c>CreateProofAsync</c>.</summary>
public sealed class Issue33EcdsaJcsCreateTests : Issue33SuiteCreateTestsBase
{
    protected override ICryptosuite Suite { get; } = new EcdsaJcs2019Cryptosuite();

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x01, KeyType.P256));

    protected override DataIntegrityProof Options() => new()
    {
        Cryptosuite = EcdsaJcs2019Cryptosuite.CryptosuiteName,
        Created = "2026-01-01T00:00:00Z",
        VerificationMethod = "did:example:alice#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };
}

/// <summary>Issue #33: the input check itself.</summary>
public sealed class Issue33ContractEscapeTests
{
    // ------------------------------------------------------------- JsonInputCheck

    public static TheoryData<string, string, string?> CheckCases() => new()
    {
        { "unpaired high surrogate value", "{\"v\":\"" + Esc(0xD800) + "\"}", Surrogate },
        { "unpaired low surrogate name", "{\"" + Esc(0xDC00) + "\":1}", Surrogate },
        { "reversed pair", "{\"v\":\"" + Esc(0xDE00) + Esc(0xD83D) + "\"}", Surrogate },
        { "string root", "\"" + Esc(0xD800) + "\"", Surrogate },
        { "duplicate", "{\"v\":1,\"v\":2}", Duplicate },
        { "duplicate by escaped spelling", "{\"a\":1,\"" + Esc(0x61) + "\":2}", Duplicate },
        { "duplicate in an array root", "[{\"a\":1},{\"b\":1,\"b\":2}]", Duplicate },
        { "65 levels", Nest(65), TooDeep },
        { "64 levels", Nest(64), null },
        { "65 nested arrays", NestArrays(65), TooDeep },
        { "64 nested arrays", NestArrays(64), null },
        { "an object holding 64 nested arrays", "{\"a\":" + NestArrays(64) + "}", TooDeep },
        { "names differing only in case", "{\"id\":1,\"ID\":2,\"Id\":3}", null },
        { "the same name in many sibling objects", "[" + string.Join(",", Enumerable.Repeat("{\"a\":1,\"b\":2}", 40)) + "]", null },
        { "a duplicate after a wide sibling", "[{" + string.Join(",", Enumerable.Range(0, 40).Select(i => "\"k" + i + "\":1")) + "},{\"a\":1,\"a\":2}]", Duplicate },
        { "same name in sibling objects", "{\"x\":{\"a\":1},\"y\":{\"a\":2},\"a\":3}", null },
        { "surrogate-pair escape", "{\"" + Esc(0xD83D) + Esc(0xDE00) + "\":\"" + Esc(0xD83D) + Esc(0xDE00) + "\"}", null },
        { "BMP escape", "{\"" + Esc(0xE9) + "\":\"" + Esc(0xE9) + "\"}", null },
        { "escaped solidus and controls", "{\"s\":\"a\\/b\\n\\t\\\"\"}", null },
        { "empty object", "{}", null },
    };

    [Theory]
    [MemberData(nameof(CheckCases))]
    public void FindProblem_ClassifiesTheInput(string label, string json, string? expected)
        => JsonInputCheck.FindProblem(Parse(json)).Should().Be(expected, label);

    [Fact]
    public void FindProblem_InvalidUtf8_IsReported()
    {
        JsonInputCheck.FindProblem(Parse(WithBytes("{\"XX\":1}", "XX", 0xFF, 0x58))).Should().Be(NotUtf8);
        JsonInputCheck.FindProblem(Parse(WithBytes("{\"v\":\"XXX\"}", "XXX", 0xED, 0xA0, 0x80))).Should().Be(NotUtf8);
    }

    [Fact]
    public void FindProblem_RawNonBmpText_IsAccepted()
        => JsonInputCheck.FindProblem(Parse("{\"" + char.ConvertFromUtf32(0x1F600) + "\":\"" + char.ConvertFromUtf32(0x1F600) + "\"}"))
            .Should().BeNull();

    [Fact]
    public void FindProblem_CommentsAndTrailingCommas_AreSkipped()
        => JsonInputCheck.FindProblem(ParseLenient("{/* c */\"a\":[1,2,], // x\n\"b\":{\"c\":1,},}")).Should().BeNull();

    [Fact]
    public void FindProblem_DepthBudget_IsReportedAgainstTheBudget()
    {
        JsonInputCheck.FindProblem(Parse(Nest(62)), 62).Should().BeNull();
        JsonInputCheck.FindProblem(Parse(Nest(63)), 62).Should().Be("nests deeper than 62 levels");
        JsonInputCheck.FindProblem(Parse(NestArrays(63)), 62).Should().Be("nests deeper than 62 levels");
    }

    [Fact]
    public void TryAccept_LenientText_ReturnsAStrictCopyOfTheSameJson()
    {
        // Comments and trailing commas are not faults, but some later steps re-parse raw text
        // strictly, so the caller carries on with a copy that has neither.
        var lenient = ParseLenient("{/* c */\"a\":[1,2,],\"b\":{\"c\":\"x\",}, // line\n}");

        JsonInputCheck.TryAccept(lenient, out var accepted, out var problem).Should().BeTrue();

        problem.Should().BeNull();
        var raw = accepted.GetRawText();
        raw.Should().NotContain("/*").And.NotContain("//").And.NotContain(",]").And.NotContain(",}");
        JsonElement.DeepEquals(accepted, lenient).Should().BeTrue();
        JsonInputCheck.RequireValid(lenient, "The thing").GetRawText().Should().Be(raw);
    }

    [Theory]
    [InlineData("{\"a\":[1,2,]}")]
    [InlineData("{\"a\":{\"b\":1 ,\n}}")]
    [InlineData("[{\"a\":1},]")]
    public void TryAccept_TrailingCommaWithoutComments_ReturnsAStrictCopy(string json)
    {
        // A trailing comma is detected on its own, not only alongside a comment.
        var lenient = ParseLenient(json);

        JsonInputCheck.TryAccept(lenient, out var accepted, out _).Should().BeTrue();

        accepted.GetRawText().Should().NotContain(",]").And.NotContain(",}").And.NotMatchRegex(",\\s+[\\]}]");
        JsonElement.DeepEquals(accepted, lenient).Should().BeTrue();
    }

    [Fact]
    public void TryAccept_StrictText_IsReturnedUnchanged()
    {
        // A comma inside a string before a closing bracket is not a trailing comma; an escaped
        // solidus would be rewritten by a copy, so an unchanged raw text proves no copy was made.
        var strict = Parse("{\"a\":\"x,\",\"b\":[\"y,\"],\"c\":\"\\/\"}");

        JsonInputCheck.TryAccept(strict, out var accepted, out _).Should().BeTrue();

        accepted.GetRawText().Should().Be(strict.GetRawText());
    }

    [Fact]
    public void TryAccept_Fault_IsReported()
    {
        JsonInputCheck.TryAccept(Parse("{\"v\":1,\"v\":2}"), out _, out var problem).Should().BeFalse();
        problem.Should().Be(Duplicate);
    }

    [Theory]
    [InlineData("invalid-operation")]
    [InlineData("json")]
    [InlineData("argument")]
    public void Verify_SuiteThrowingATransformationFault_IsAPerProofTransformationError(string kind)
    {
        // Defence in depth on the verify side: a registered suite that throws one of the
        // System.Text.Json fault types fails that proof as a result, with a fixed message.
        var registry = new CryptosuiteRegistry();
        registry.Register(new ThrowingSuite(kind));
        var document = Parse("{\"proof\":{\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"" + ThrowingSuite.SuiteName
            + "\",\"verificationMethod\":\"did:example:a#1\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"z1\"}}");

        var result = new DataIntegrityProofPipeline(registry).Verify(document, PublicKeyMaterial.FromRaw(KeyType.Ed25519, Fx.SeedKey(0x01).PublicKey));

        result.Verified.Should().BeFalse();
        var problem = result.ProofResults.Should().ContainSingle().Subject.Problems.Should().ContainSingle().Subject;
        problem.Code.Should().Be(ProofProblemCodes.ProofTransformationError);
        problem.Message.Should().Be("The secured document could not be transformed for verification.");
    }

    private sealed class ThrowingSuite(string kind) : ICryptosuite
    {
        public const string SuiteName = "throwing-test-suite";

        public string Name => SuiteName;

        public Task<DataIntegrityProof> CreateProofAsync(JsonElement unsecuredDocument, DataIntegrityProof proofOptions, ISigner signer, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ProofVerificationResult VerifyProof(JsonElement unsecuredDocument, DataIntegrityProof proof, PublicKeyMaterial publicKey)
            => throw (kind switch
            {
                "invalid-operation" => new InvalidOperationException("suite fault"),
                "json" => (Exception)new JsonException("suite fault"),
                _ => new ArgumentException("suite fault"),
            });
    }

    [Fact]
    public void RequireValid_NamesTheInputInTheMessage()
        => FluentActions.Invoking(() => JsonInputCheck.RequireValid(Parse("{\"v\":1,\"v\":2}"), "The thing"))
            .Should().ThrowExactly<ProofGenerationException>().WithMessage("The thing has a duplicate member name.");

    [Fact]
    public void SerializeChecked_UnwritableExtension_ThrowsWithCause()
    {
        // 64 levels as given passes the raw check; written under its member name it is 65.
        var proof = new DataIntegrityProof
        {
            AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = Parse(Nest(64)) },
        };

        FluentActions.Invoking(() => JsonInputCheck.SerializeChecked(proof, DataProofsJsonOptions.ProofTypeInfo, "The thing"))
            .Should().ThrowExactly<ProofGenerationException>().WithMessage("The thing could not be serialized as JSON.")
            .WithInnerException<JsonException>();
    }

    [Fact]
    public void SerializeChecked_RawElementFaults_AreReportedBeforeSerialization()
    {
        // Serialization would rewrite the invalid UTF-8 as U+FFFD, and throw
        // InvalidOperationException for an element with no value.
        static DataIntegrityProof WithExtension(JsonElement value)
            => new() { AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = value } };

        FluentActions.Invoking(() => JsonInputCheck.SerializeChecked(WithExtension(Parse(WithBytes("\"XX\"", "XX", 0xFF, 0xFF))), DataProofsJsonOptions.ProofTypeInfo, "The thing"))
            .Should().ThrowExactly<ProofGenerationException>().WithMessage($"The thing {NotUtf8}.");
        FluentActions.Invoking(() => JsonInputCheck.SerializeChecked(WithExtension(Parse("\"" + Esc(0xD800) + "\"")), DataProofsJsonOptions.ProofTypeInfo, "The thing"))
            .Should().ThrowExactly<ProofGenerationException>().WithMessage($"The thing {Surrogate}.");
        FluentActions.Invoking(() => JsonInputCheck.SerializeChecked(WithExtension(default), DataProofsJsonOptions.ProofTypeInfo, "The thing"))
            .Should().ThrowExactly<ProofGenerationException>().WithMessage("The thing has a member with no JSON value.");
        FluentActions.Invoking(() => JsonInputCheck.SerializeChecked(new DataIntegrityProof { Context = Parse("{\"a\":1,\"a\":2}") }, DataProofsJsonOptions.ProofTypeInfo, "The thing"))
            .Should().ThrowExactly<ProofGenerationException>().WithMessage($"The thing {Duplicate}.");
    }

    [Fact]
    public void SerializeChecked_CleanProof_ReturnsItsJson()
    {
        var proof = new DataIntegrityProof { ProofPurpose = ProofPurposes.AssertionMethod };

        var element = JsonInputCheck.SerializeChecked(proof, DataProofsJsonOptions.ProofTypeInfo, "The thing");

        element.GetProperty("proofPurpose").GetString().Should().Be(ProofPurposes.AssertionMethod);
    }
}
