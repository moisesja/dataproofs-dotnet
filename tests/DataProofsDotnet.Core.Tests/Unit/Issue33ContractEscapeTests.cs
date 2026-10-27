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

/// <summary>
/// Issue #33: the input check itself, and the JCS suites' own <c>CreateProofAsync</c>, which is
/// public and documented to throw only <see cref="ProofGenerationException"/> for invalid input.
/// </summary>
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

    // ------------------------------------------- the JCS suites' own CreateProofAsync

    private static readonly string[] SuiteNames = [EddsaJcs2022Cryptosuite.CryptosuiteName, EcdsaJcs2019Cryptosuite.CryptosuiteName];

    public static TheoryData<string> Suites() => [.. SuiteNames];

    public static TheoryData<string, string, string> SuiteSurrogateCases()
    {
        var data = new TheoryData<string, string, string>();
        foreach (var suite in SuiteNames)
        {
            foreach (var placement in new[] { "first member name", "last member name", "member value" })
            {
                foreach (var escape in LoneEscapeNames)
                {
                    data.Add(suite, placement, escape);
                }
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(SuiteSurrogateCases))]
    public Task CreateProof_UnpairedSurrogateEscape_ThrowsProofGenerationException(string suite, string placement, string escape)
    {
        var e = LoneEscape(escape);
        var document = placement switch
        {
            "first member name" => FirstMember(BaseDocument, "\"" + e + "\":1"),
            "last member name" => LastMember(BaseDocument, "\"" + e + "\":1"),
            "member value" => LastMember(BaseDocument, "\"v\":\"" + e + "\""),
            _ => throw new ArgumentOutOfRangeException(nameof(placement)),
        };

        return AssertCreateFailsAsync(suite, Parse(document), Options(suite), $"The document to secure {Surrogate}.");
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task CreateProof_DuplicateDepthOrInvalidUtf8_ThrowsProofGenerationException(string suite)
    {
        await AssertCreateFailsAsync(suite, Parse(LastMember(BaseDocument, "\"v\":1,\"v\":2")), Options(suite), $"The document to secure {Duplicate}.");
        await AssertCreateFailsAsync(suite, Parse(LastMember(BaseDocument, "\"n\":{\"v\":1,\"v\":2}")), Options(suite), $"The document to secure {Duplicate}.");
        await AssertCreateFailsAsync(suite, Parse(LastMember(BaseDocument, "\"d\":" + Nest(64))), Options(suite), $"The document to secure {TooDeep}.");
        await AssertCreateFailsAsync(suite, Parse(WithBytes(LastMember(BaseDocument, "\"v\":\"XX\""), "XX", 0xC3, 0x28)), Options(suite), $"The document to secure {NotUtf8}.");
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task CreateProof_UnwritableOrRepeatedConfigurationMember_ThrowsProofGenerationException(string suite)
    {
        var unwritable = Options(suite) with
        {
            AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = Parse("\"" + Esc(0xD800) + "\"") },
        };
        var repeated = Options(suite) with
        {
            AdditionalProperties = new Dictionary<string, JsonElement> { ["proofPurpose"] = Parse("\"authentication\"") },
        };
        // With no document @context, the configuration keeps the options' own.
        var unwritableContext = Options(suite) with { Context = Parse("[\"" + Esc(0xDC00) + "\"]") };

        await AssertCreateFailsAsync(suite, Parse(BaseDocument), unwritable, $"The proof configuration {Surrogate}.");
        await AssertCreateFailsAsync(suite, Parse(BaseDocument), repeated, $"The proof configuration {Duplicate}.");
        await AssertCreateFailsAsync(suite, Parse("{\"a\":1}"), unwritableContext, $"The proof configuration {Surrogate}.");
    }

    [Theory]
    [MemberData(nameof(Suites))]
    public async Task CreateProof_EscapedSpellings_StillSign(string suite)
    {
        var document = LastMember(BaseDocument, "\"" + Esc(0xE9) + "\":\"" + Esc(0xD83D) + Esc(0xDE00) + "\",\"s\":\"a\\/b\"");

        var proof = await Suite(suite).CreateProofAsync(Parse(document), Options(suite), Signer(suite));

        proof.ProofValue.Should().StartWith("z");
    }

    private static ICryptosuite Suite(string name) => name == EddsaJcs2022Cryptosuite.CryptosuiteName
        ? new EddsaJcs2022Cryptosuite()
        : new EcdsaJcs2019Cryptosuite();

    private static ISigner Signer(string name) => Fx.Signer(Fx.SeedKey(0x01, name == EddsaJcs2022Cryptosuite.CryptosuiteName ? KeyType.Ed25519 : KeyType.P256));

    private static DataIntegrityProof Options(string suite) => new()
    {
        Cryptosuite = suite,
        Created = "2026-01-01T00:00:00Z",
        VerificationMethod = "did:example:alice#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    private static Task AssertCreateFailsAsync(string suite, JsonElement document, DataIntegrityProof options, string message)
        => FluentActions.Invoking(() => Suite(suite).CreateProofAsync(document, options, Signer(suite)))
            .Should().ThrowExactlyAsync<ProofGenerationException>().WithMessage(message);
}
