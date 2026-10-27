using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using DataProofsDotnet.Rdfc.Tests.TestSupport;
using DataProofsDotnet.Tests.Shared;
using FluentAssertions;
using NetCrypto;
using Xunit;
using static DataProofsDotnet.Tests.Shared.HostileJson;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>Issue #33: the shared pipeline matrix through <c>eddsa-rdfc-2022</c>.</summary>
public sealed class Issue33RdfcPipelineTests : Issue33PipelineTestsBase
{
    protected override DataIntegrityProofPipeline Pipeline { get; } = new(RdfcCryptosuiteRegistration.CreateWithRdfcSuites());

    protected override string Cryptosuite => EddsaRdfc2022Cryptosuite.CryptosuiteName;
}

/// <summary>Issue #33: the shared suite matrix through <c>eddsa-rdfc-2022</c>'s own <c>CreateProofAsync</c>.</summary>
public sealed class Issue33EddsaRdfcCreateTests : Issue33SuiteCreateTestsBase
{
    protected override ICryptosuite Suite { get; } = new EddsaRdfc2022Cryptosuite();

    protected override ISigner Signer { get; } =
        Fx.Signer(Fx.KeyGen.FromPrivateKey(KeyType.Ed25519, Enumerable.Repeat((byte)0x01, 32).ToArray()));

    protected override DataIntegrityProof Options() => new()
    {
        Cryptosuite = EddsaRdfc2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-01T00:00:00Z",
        VerificationMethod = "did:example:alice#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };
}

/// <summary>Issue #33: the shared suite matrix through <c>ecdsa-rdfc-2019</c>'s own <c>CreateProofAsync</c>.</summary>
public sealed class Issue33EcdsaRdfcCreateTests : Issue33SuiteCreateTestsBase
{
    protected override ICryptosuite Suite { get; } = new EcdsaRdfc2019Cryptosuite();

    protected override ISigner Signer { get; } =
        Fx.Signer(Fx.KeyGen.FromPrivateKey(KeyType.P256, Enumerable.Repeat((byte)0x01, 32).ToArray()));

    protected override DataIntegrityProof Options() => new()
    {
        Cryptosuite = EcdsaRdfc2019Cryptosuite.CryptosuiteName,
        Created = "2026-01-01T00:00:00Z",
        VerificationMethod = "did:example:alice#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };
}

/// <summary>
/// Issue #33: <c>bbs-2023</c>'s issuer and holder entry points, <see cref="Bbs2023Cryptosuite.CreateBaseProofAsync"/>
/// and <see cref="Bbs2023Cryptosuite.DeriveProof"/>, which are documented to throw only
/// <see cref="ProofGenerationException"/> for an invalid document. A holder derives over a
/// document an issuer sent, so this is the holder's hostile-input boundary.
/// </summary>
public sealed class Issue33Bbs2023Tests
{
    private static readonly string[] Placements = ["first member name", "nested member name", "member value"];

    private readonly Bbs2023Cryptosuite _suite = new();

    public static TheoryData<string, string> SurrogateCases()
    {
        var data = new TheoryData<string, string>();
        foreach (var placement in Placements)
        {
            foreach (var escape in LoneEscapeNames)
            {
                data.Add(placement, escape);
            }
        }

        return data;
    }

    public static TheoryData<string> OtherCases() =>
        ["duplicate", "nested duplicate", "65 levels", "invalid UTF-8 value", "encoded surrogate"];

    [BbsTheory]
    [MemberData(nameof(SurrogateCases))]
    public Task CreateBaseProof_UnpairedSurrogateEscape_ThrowsProofGenerationException(string placement, string escape)
        => AssertCreateFailsAsync(Parse(WithSurrogate(Wind, placement, LoneEscape(escape))), BaseOptions(), $"The document to secure {Surrogate}.");

    [BbsTheory]
    [MemberData(nameof(OtherCases))]
    public Task CreateBaseProof_DuplicateDepthOrInvalidUtf8_ThrowsProofGenerationException(string kind)
    {
        var (document, phrase) = Other(Wind, kind);
        return AssertCreateFailsAsync(document, BaseOptions(), $"The document to secure {phrase}.");
    }

    [BbsFact]
    public async Task CreateBaseProof_UnusableConfiguration_ThrowsProofGenerationException()
    {
        await AssertCreateFailsAsync(
            Parse(Wind),
            BaseOptions() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = Parse("\"" + Esc(0xD800) + "\"") } },
            $"The proof configuration {Surrogate}.");
        await AssertCreateFailsAsync(
            Parse(Wind),
            BaseOptions() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["proofPurpose"] = Parse("\"authentication\"") } },
            $"The proof configuration {ReservedName}.");
    }

    public static TheoryData<string> ReservedNames() => [.. ReservedProofNames];

    [BbsTheory]
    [MemberData(nameof(ReservedNames))]
    public Task CreateBaseProof_ReservedExtensionName_ThrowsProofGenerationException(string name)
        => AssertCreateFailsAsync(Parse(Wind),
            BaseOptions() with { AdditionalProperties = new Dictionary<string, JsonElement> { [name] = Parse("null") } },
            $"The proof configuration {ReservedName}.");

    [BbsTheory]
    [MemberData(nameof(SurrogateCases))]
    public async Task DeriveProof_UnpairedSurrogateEscape_ThrowsProofGenerationException(string placement, string escape)
        => AssertDeriveFails(Parse(WithSurrogate(await SecuredBaseAsync(), placement, LoneEscape(escape))), $"The secured base document {Surrogate}.");

    [BbsTheory]
    [MemberData(nameof(OtherCases))]
    public async Task DeriveProof_DuplicateDepthOrInvalidUtf8_ThrowsProofGenerationException(string kind)
    {
        var (document, phrase) = Other(await SecuredBaseAsync(), kind);
        AssertDeriveFails(document, $"The secured base document {phrase}.");
    }

    [BbsFact]
    public async Task DeriveProof_HostileProofMember_ThrowsProofGenerationException()
    {
        var secured = await SecuredBaseAsync();

        AssertDeriveFails(Parse(InProof(secured, "\"" + Esc(0xD800) + "\":1")), $"The secured base document {Surrogate}.");
        AssertDeriveFails(Parse(LastMember(secured, "\"proof\":{}")), $"The secured base document {Duplicate}.");
    }

    [BbsFact]
    public async Task EscapedSpellingsAndComments_StillCreateAndDerive()
    {
        // Over-rejection guards: the issuer's document and the holder's secured document
        // re-spelled with escaped solidi and non-ASCII characters, and with a comment and a
        // trailing comma, are the same JSON.
        var respelled = EscapeNonAscii(Splice(Wind, "/", "\\/"));
        var proof = await _suite.CreateBaseProofAsync(Parse(respelled), BaseOptions(), Key().Sk, Key().HmacKey, Mandatory());
        proof.ProofValue.Should().StartWith("u2V0C");

        var secured = await SecuredBaseAsync();
        _suite.DeriveProof(Parse(EscapeNonAscii(Splice(secured, "/", "\\/"))), Selective, Header).ValueKind.Should().Be(JsonValueKind.Object);
        _suite.DeriveProof(ParseLenient("{/* c */" + secured[1..^1] + ",}"), Selective, Header).ValueKind.Should().Be(JsonValueKind.Object);
    }

    private static readonly string[] Selective = ["/credentialSubject/sails/1"];

    private static readonly ReadOnlyMemory<byte> Header = Convert.FromHexString("113377aa");

    private static string Wind => Fx.Text("w3c", "vc-di-bbs", "TestVectors", "windDoc.json");

    private static (byte[] Sk, byte[] HmacKey) Key()
    {
        var keyMaterial = Fx.Json("w3c", "vc-di-bbs", "TestVectors", "BBSKeyMaterial.json");
        return (
            Convert.FromHexString(keyMaterial.GetProperty("privateKeyHex").GetString()!),
            Convert.FromHexString(keyMaterial.GetProperty("hmacKeyString").GetString()!));
    }

    private static string[] Mandatory()
        => JsonSerializer.Deserialize<string[]>(Fx.Text("w3c", "vc-di-bbs", "TestVectors", "windMandatory.json"))!;

    private static DataIntegrityProof BaseOptions() => new()
    {
        Type = DataIntegrityProof.DataIntegrityProofType,
        Cryptosuite = Bbs2023Cryptosuite.CryptosuiteName,
        Created = "2023-08-15T23:36:38Z",
        VerificationMethod = "did:key:zUC7Derd#zUC7Derd",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    private async Task<string> SecuredBaseAsync()
    {
        var (sk, hmacKey) = Key();
        var baseProof = await _suite.CreateBaseProofAsync(Parse(Wind), BaseOptions(), sk, hmacKey, Mandatory());
        var secured = JsonObject.Create(Parse(Wind))!;
        secured["proof"] = JsonSerializer.SerializeToNode(baseProof, DataProofsJsonOptions.Default);
        return JsonSerializer.Serialize(secured, DataProofsJsonOptions.Default);
    }

    private static string WithSurrogate(string document, string placement, string e) => placement switch
    {
        "first member name" => FirstMember(document, "\"" + e + "\":1"),
        "nested member name" => LastMember(document, "\"n\":{\"" + e + "\":1}"),
        "member value" => LastMember(document, "\"v\":\"" + e + "\""),
        _ => throw new ArgumentOutOfRangeException(nameof(placement), placement, null),
    };

    private static (JsonElement Document, string Phrase) Other(string document, string kind) => kind switch
    {
        "duplicate" => (Parse(FirstMember(document, "\"v\":1,\"v\":2")), Duplicate),
        "nested duplicate" => (Parse(LastMember(document, "\"n\":{\"v\":1,\"v\":2}")), Duplicate),
        "65 levels" => (Parse(LastMember(document, "\"d\":" + Nest(64))), TooDeep),
        "invalid UTF-8 value" => (Parse(WithBytes(LastMember(document, "\"v\":\"XX\""), "XX", 0xC3, 0x28)), NotUtf8),
        "encoded surrogate" => (Parse(WithBytes(LastMember(document, "\"v\":\"XXX\""), "XXX", 0xED, 0xA0, 0x80)), NotUtf8),
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null),
    };

    private Task AssertCreateFailsAsync(JsonElement document, DataIntegrityProof options, string message)
    {
        var (sk, hmacKey) = Key();
        return FluentActions.Invoking(() => _suite.CreateBaseProofAsync(document, options, sk, hmacKey, Mandatory()))
            .Should().ThrowExactlyAsync<ProofGenerationException>().WithMessage(message);
    }

    private void AssertDeriveFails(JsonElement document, string message)
        => FluentActions.Invoking(() => _suite.DeriveProof(document, Selective, Header))
            .Should().ThrowExactly<ProofGenerationException>().WithMessage(message);
}
