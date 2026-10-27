using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Tests.Shared;

/// <summary>
/// Issue #33: a cryptosuite's own <see cref="ICryptosuite.CreateProofAsync"/> is public and
/// documented to throw only <see cref="ProofGenerationException"/> for invalid options or
/// documents, so it holds that contract for JSON it cannot process — the same input classes
/// as the pipeline matrix — whether or not the pipeline checked the input first. One derived
/// class per suite (and variant).
/// </summary>
public abstract class Issue33SuiteCreateTestsBase
{
    /// <summary>The suite under test.</summary>
    protected abstract ICryptosuite Suite { get; }

    /// <summary>A signer whose key type the suite supports.</summary>
    protected abstract ISigner Signer { get; }

    /// <summary>Valid proof options for the suite.</summary>
    protected abstract DataIntegrityProof Options();

    private static readonly string[] SurrogatePlacements = ["first member name", "last member name", "nested member name", "member value"];

    public static TheoryData<string, string> SurrogateCases()
    {
        var data = new TheoryData<string, string>();
        foreach (var placement in SurrogatePlacements)
        {
            foreach (var escape in HostileJson.LoneEscapeNames)
            {
                data.Add(placement, escape);
            }
        }

        return data;
    }

    public static TheoryData<string> OtherDocumentCases() =>
    [
        "duplicate", "nested duplicate", "duplicate by escaped spelling", "65 levels",
        "invalid UTF-8 name", "invalid UTF-8 value", "encoded surrogate",
    ];

    public static TheoryData<string> LoneEscapes() => [.. HostileJson.LoneEscapeNames];

    [Theory]
    [MemberData(nameof(SurrogateCases), MemberType = typeof(Issue33SuiteCreateTestsBase))]
    public Task CreateProof_UnpairedSurrogateEscape_ThrowsProofGenerationException(string placement, string escape)
    {
        var e = HostileJson.LoneEscape(escape);
        var document = placement switch
        {
            "first member name" => HostileJson.FirstMember(HostileJson.BaseDocument, "\"" + e + "\":1"),
            "last member name" => HostileJson.LastMember(HostileJson.BaseDocument, "\"" + e + "\":1"),
            "nested member name" => HostileJson.LastMember(HostileJson.BaseDocument, "\"n\":{\"" + e + "\":1}"),
            "member value" => HostileJson.LastMember(HostileJson.BaseDocument, "\"v\":\"" + e + "\""),
            _ => throw new ArgumentOutOfRangeException(nameof(placement), placement, null),
        };

        return AssertCreateFailsAsync(HostileJson.Parse(document), Options(), $"The document to secure {HostileJson.Surrogate}.");
    }

    [Theory]
    [MemberData(nameof(OtherDocumentCases), MemberType = typeof(Issue33SuiteCreateTestsBase))]
    public Task CreateProof_DuplicateDepthOrInvalidUtf8_ThrowsProofGenerationException(string kind)
    {
        var (document, phrase) = kind switch
        {
            "duplicate" => (HostileJson.Parse(HostileJson.LastMember(HostileJson.BaseDocument, "\"v\":1,\"v\":2")), HostileJson.Duplicate),
            "nested duplicate" => (HostileJson.Parse(HostileJson.LastMember(HostileJson.BaseDocument, "\"n\":{\"v\":1,\"v\":2}")), HostileJson.Duplicate),
            "duplicate by escaped spelling" => (HostileJson.Parse(HostileJson.LastMember(HostileJson.BaseDocument, "\"n\":{\"a\":1,\"" + HostileJson.Esc(0x61) + "\":2}")), HostileJson.Duplicate),
            "65 levels" => (HostileJson.Parse(HostileJson.LastMember(HostileJson.BaseDocument, "\"d\":" + HostileJson.Nest(64))), HostileJson.TooDeep),
            "invalid UTF-8 name" => (HostileJson.Parse(HostileJson.WithBytes(HostileJson.LastMember(HostileJson.BaseDocument, "\"XX\":1"), "XX", 0xFF, 0x58)), HostileJson.NotUtf8),
            "invalid UTF-8 value" => (HostileJson.Parse(HostileJson.WithBytes(HostileJson.LastMember(HostileJson.BaseDocument, "\"v\":\"XX\""), "XX", 0xC3, 0x28)), HostileJson.NotUtf8),
            "encoded surrogate" => (HostileJson.Parse(HostileJson.WithBytes(HostileJson.LastMember(HostileJson.BaseDocument, "\"v\":\"XXX\""), "XXX", 0xED, 0xA0, 0x80)), HostileJson.NotUtf8),
            _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
        };

        return AssertCreateFailsAsync(document, Options(), $"The document to secure {phrase}.");
    }

    [Theory]
    [MemberData(nameof(LoneEscapes), MemberType = typeof(Issue33SuiteCreateTestsBase))]
    public Task CreateProof_ConfigurationExtensionWithUnpairedSurrogateEscape_ThrowsProofGenerationException(string escape)
        => AssertCreateFailsAsync(
            HostileJson.Parse(HostileJson.BaseDocument),
            WithExtension("x", HostileJson.Parse("\"" + HostileJson.LoneEscape(escape) + "\"")),
            $"The proof configuration {HostileJson.Surrogate}.");

    [Fact]
    public Task CreateProof_ConfigurationContextWithUnpairedSurrogateEscape_ThrowsProofGenerationException()
        // With no document @context, the configuration keeps the options' own.
        => AssertCreateFailsAsync(
            HostileJson.Parse("{\"a\":1}"),
            Options() with { Context = HostileJson.Parse("[\"" + HostileJson.Esc(0xDC00) + "\"]") },
            $"The proof configuration {HostileJson.Surrogate}.");

    [Fact]
    public Task CreateProof_ConfigurationExtensionRepeatingAModelledMember_ThrowsProofGenerationException()
        => AssertCreateFailsAsync(
            HostileJson.Parse(HostileJson.BaseDocument),
            WithExtension("proofPurpose", HostileJson.Parse("\"authentication\"")),
            $"The proof configuration {HostileJson.Duplicate}.");

    [Fact]
    public Task CreateProof_ConfigurationExtensionWithNoValue_ThrowsProofGenerationException()
        => AssertCreateFailsAsync(
            HostileJson.Parse(HostileJson.BaseDocument),
            WithExtension("x", default),
            "The proof configuration has a member with no JSON value.");

    [Fact]
    public Task CreateProof_ConfigurationExtensionPast64Levels_ThrowsProofGenerationException()
        => AssertCreateFailsAsync(
            HostileJson.Parse(HostileJson.BaseDocument),
            WithExtension("x", HostileJson.Parse(HostileJson.Nest(64))),
            "The proof configuration could not be serialized as JSON.");

    // ------------------------------------------- over-rejection guards: these must still work

    [Fact]
    public async Task CreateProof_EscapedSpellingsCommentsAndDepth64_StillSign()
    {
        var pair = HostileJson.Esc(0xD83D) + HostileJson.Esc(0xDE00);
        var escaped = HostileJson.LastMember(
            HostileJson.BaseDocument,
            "\"" + HostileJson.Esc(0xE9) + "\":\"" + pair + "\",\"s\":\"a\\/b\",\"x\":{\"a\":1},\"y\":{\"a\":2}");
        var lenient = "{/* c */\"@context\":[\"" + HostileJson.Context + "\",],\"a\":1, // line\n}";
        var deep = HostileJson.LastMember(HostileJson.BaseDocument, "\"d\":" + HostileJson.Nest(63));
        var options = WithExtension("x", HostileJson.Parse("\"" + HostileJson.Esc(0xE9) + pair + "\""));

        (await Suite.CreateProofAsync(HostileJson.Parse(escaped), options, Signer)).ProofValue.Should().NotBeNullOrEmpty();
        (await Suite.CreateProofAsync(HostileJson.ParseLenient(lenient), Options(), Signer)).ProofValue.Should().NotBeNullOrEmpty();
        (await Suite.CreateProofAsync(HostileJson.Parse(deep), Options(), Signer)).ProofValue.Should().NotBeNullOrEmpty();
    }

    private DataIntegrityProof WithExtension(string name, JsonElement value)
        => Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { [name] = value } };

    private Task AssertCreateFailsAsync(JsonElement document, DataIntegrityProof options, string message)
        => FluentActions.Invoking(() => Suite.CreateProofAsync(document, options, Signer))
            .Should().ThrowExactlyAsync<ProofGenerationException>().WithMessage(message);
}
