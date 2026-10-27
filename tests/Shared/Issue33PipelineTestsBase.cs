using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Tests.Shared;

/// <summary>
/// Issue #33: <see cref="DataIntegrityProofPipeline"/> holds its documented contracts for JSON it
/// cannot process — an unpaired-surrogate escape, a duplicate member name, invalid UTF-8, nesting
/// past 64 levels — wherever in the document it sits. <c>Verify</c> and <c>VerifyAsync</c> return
/// one document-level <c>PROOF_TRANSFORMATION_ERROR</c> before any proof is parsed or any resolver
/// is called; <c>AddProofAsync</c> throws only <see cref="ProofGenerationException"/>. Linked into
/// the test project of each package that ships a suite; one derived class per suite.
/// </summary>
public abstract class Issue33PipelineTestsBase
{
    private static readonly KeyPair Key =
        new DefaultKeyGenerator().FromPrivateKey(KeyType.Ed25519, Enumerable.Repeat((byte)0x01, 32).ToArray());

    private static readonly KeyPairSigner Signer = new(Key, new DefaultCryptoProvider());

    private static readonly PublicKeyMaterial PublicKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, Key.PublicKey);

    private readonly Lazy<Signed> _signed;

    protected Issue33PipelineTestsBase()
    {
        _signed = new Lazy<Signed>(SignFixtures);
    }

    /// <summary>The pipeline under test.</summary>
    protected abstract DataIntegrityProofPipeline Pipeline { get; }

    /// <summary>The Ed25519 cryptosuite the fixtures are signed with.</summary>
    protected abstract string Cryptosuite { get; }

    private static readonly string[] VerifyEntries = ["Verify", "VerifyAsync"];

    private static readonly string[] SurrogateVerifyPlacements =
    [
        "first member name", "last member name", "nested member name", "member value", "array element",
        "@context value", "proof member name", "proof member value", "referenced proof id", "other proof member name",
    ];

    private static readonly string[] DuplicateVerifyPlacements =
    [
        "first members", "last members", "nested object", "object in array", "escaped spelling",
        "proof member", "second proof member", "other proof in chain",
    ];

    private static readonly string[] DepthVerifyPlacements = ["document, 65", "document, 100", "proof, 65"];

    private static readonly string[] Utf8VerifyPlacements = ["member name", "member value", "proof member value", "encoded surrogate"];

    private static readonly string[] SurrogateAddPlacements =
    [
        "first member name", "last member name", "nested member name", "member value", "array element",
        "existing proof member name", "existing proof member value", "referenced proof id",
    ];

    private static readonly string[] DuplicateAddPlacements =
    [
        "first members", "last members", "nested object", "escaped spelling", "existing proof member", "second proof member",
    ];

    private static readonly string[] DepthAddPlacements = ["document, 65", "document, 100"];

    private static readonly string[] Utf8AddPlacements = ["member name", "member value", "encoded surrogate"];

    public static TheoryData<string, string, string> SurrogateVerifyCases() => Cross(VerifyEntries, SurrogateVerifyPlacements, HostileJson.LoneEscapeNames);

    public static TheoryData<string, string> DuplicateVerifyCases() => Cross(VerifyEntries, DuplicateVerifyPlacements);

    public static TheoryData<string, string> DepthVerifyCases() => Cross(VerifyEntries, DepthVerifyPlacements);

    public static TheoryData<string, string> Utf8VerifyCases() => Cross(VerifyEntries, Utf8VerifyPlacements);

    public static TheoryData<string, string> SurrogateAddCases() => Cross(SurrogateAddPlacements, HostileJson.LoneEscapeNames);

    public static TheoryData<string> DuplicateAddCases() => [.. DuplicateAddPlacements];

    public static TheoryData<string> DepthAddCases() => [.. DepthAddPlacements];

    public static TheoryData<string> Utf8AddCases() => [.. Utf8AddPlacements];

    public static TheoryData<string> LoneEscapes() => [.. HostileJson.LoneEscapeNames];

    // ------------------------------------------------------------------ verification

    [Theory]
    [MemberData(nameof(SurrogateVerifyCases), MemberType = typeof(Issue33PipelineTestsBase))]
    public Task Verify_UnpairedSurrogateEscape_IsOneDocumentLevelTransformationError(string entry, string placement, string escape)
        => AssertDocumentFailureAsync(entry, HostileJson.Parse(SurrogateForVerify(placement, HostileJson.LoneEscape(escape))), HostileJson.Surrogate);

    [Theory]
    [MemberData(nameof(DuplicateVerifyCases), MemberType = typeof(Issue33PipelineTestsBase))]
    public Task Verify_DuplicateMemberName_IsOneDocumentLevelTransformationError(string entry, string placement)
        => AssertDocumentFailureAsync(entry, HostileJson.Parse(DuplicateForVerify(placement)), HostileJson.Duplicate);

    [Theory]
    [MemberData(nameof(DepthVerifyCases), MemberType = typeof(Issue33PipelineTestsBase))]
    public Task Verify_NestingPast64Levels_IsOneDocumentLevelTransformationError(string entry, string placement)
        => AssertDocumentFailureAsync(entry, HostileJson.Parse(DepthForVerify(placement)), HostileJson.TooDeep);

    [Theory]
    [MemberData(nameof(Utf8VerifyCases), MemberType = typeof(Issue33PipelineTestsBase))]
    public Task Verify_InvalidUtf8_IsOneDocumentLevelTransformationError(string entry, string placement)
        => AssertDocumentFailureAsync(entry, HostileJson.Parse(Utf8ForVerify(placement)), HostileJson.NotUtf8);

    [Fact]
    public async Task VerifyAsync_Control_CallsTheResolverAndVerifies()
    {
        // Makes "the resolver was never called" in the negative cases meaningful.
        var resolver = new CountingResolver();

        var result = await Pipeline.VerifyAsync(HostileJson.Parse(Fixtures.Single), resolver);

        result.Verified.Should().BeTrue();
        resolver.Calls.Should().Be(1);
    }

    // ---------------------------------------------------------------------- creation

    [Theory]
    [MemberData(nameof(SurrogateAddCases), MemberType = typeof(Issue33PipelineTestsBase))]
    public Task AddProof_UnpairedSurrogateEscape_ThrowsProofGenerationException(string placement, string escape)
    {
        var (document, options) = SurrogateForAdd(placement, HostileJson.LoneEscape(escape));
        return AssertAddFailsAsync(HostileJson.Parse(document), options, $"The document to secure {HostileJson.Surrogate}.");
    }

    [Theory]
    [MemberData(nameof(DuplicateAddCases), MemberType = typeof(Issue33PipelineTestsBase))]
    public Task AddProof_DuplicateMemberName_ThrowsProofGenerationException(string placement)
        => AssertAddFailsAsync(HostileJson.Parse(DuplicateForAdd(placement)), Options(), $"The document to secure {HostileJson.Duplicate}.");

    [Theory]
    [MemberData(nameof(DepthAddCases), MemberType = typeof(Issue33PipelineTestsBase))]
    public Task AddProof_NestingPast64Levels_ThrowsProofGenerationException(string placement)
        => AssertAddFailsAsync(HostileJson.Parse(DepthForAdd(placement)), Options(), $"The document to secure {HostileJson.TooDeep}.");

    [Theory]
    [MemberData(nameof(Utf8AddCases), MemberType = typeof(Issue33PipelineTestsBase))]
    public Task AddProof_InvalidUtf8_ThrowsProofGenerationException(string placement)
        => AssertAddFailsAsync(HostileJson.Parse(Utf8ForAdd(placement)), Options(), $"The document to secure {HostileJson.NotUtf8}.");

    [Theory]
    [MemberData(nameof(LoneEscapes), MemberType = typeof(Issue33PipelineTestsBase))]
    public Task AddProof_OptionsExtensionWithUnpairedSurrogateEscape_ThrowsProofGenerationException(string escape)
        => AssertAddFailsAsync(
            HostileJson.Parse(HostileJson.BaseDocument),
            Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = HostileJson.Parse("\"" + HostileJson.LoneEscape(escape) + "\"") } },
            $"The proof options object {HostileJson.Surrogate}.");

    [Theory]
    [MemberData(nameof(LoneEscapes), MemberType = typeof(Issue33PipelineTestsBase))]
    public Task AddProof_OptionsContextWithUnpairedSurrogateEscape_ThrowsProofGenerationException(string escape)
        => AssertAddFailsAsync(
            HostileJson.Parse(HostileJson.BaseDocument),
            Options() with { Context = HostileJson.Parse("[\"" + HostileJson.LoneEscape(escape) + "\"]") },
            $"The proof options object {HostileJson.Surrogate}.");

    [Theory]
    [InlineData("proofPurpose")]
    [InlineData("proofValue")]
    [InlineData("challenge")]
    public Task AddProof_ReservedExtensionName_ThrowsProofGenerationException(string name)
        => AssertAddFailsAsync(
            HostileJson.Parse(HostileJson.BaseDocument),
            Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { [name] = HostileJson.Parse("\"zFake\"") } },
            $"The proof options object {HostileJson.ReservedName}.");

    [Fact]
    public Task AddProof_OptionsExtensionWithDuplicateMember_ThrowsProofGenerationException()
        => AssertAddFailsAsync(
            HostileJson.Parse(HostileJson.BaseDocument),
            Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = HostileJson.Parse("{\"v\":1,\"v\":2}") } },
            $"The proof options object {HostileJson.Duplicate}.");

    [Fact]
    public Task AddProof_OptionsExtensionWithInvalidUtf8_ThrowsProofGenerationException()
        => AssertAddFailsAsync(
            HostileJson.Parse(HostileJson.BaseDocument),
            Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = HostileJson.Parse(HostileJson.WithBytes("\"XX\"", "XX", 0xFF, 0xFF)) } },
            $"The proof options object {HostileJson.NotUtf8}.");

    [Fact]
    public Task AddProof_OptionsExtensionWithNoValue_ThrowsProofGenerationException()
        // default(JsonElement): the serializer would throw InvalidOperationException for it.
        => AssertAddFailsAsync(
            HostileJson.Parse(HostileJson.BaseDocument),
            Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = default } },
            "The proof options object has a member with no JSON value.");

    [Fact]
    public Task AddProof_OptionsContextWithNoValue_ThrowsProofGenerationException()
        => AssertAddFailsAsync(
            HostileJson.Parse(HostileJson.BaseDocument),
            Options() with { Context = default(JsonElement) },
            "The proof options object has a member with no JSON value.");

    [Fact]
    public Task AddProof_OptionsExtensionPast64Levels_ThrowsProofGenerationException()
        // 64 levels as given, one more once written under its member name.
        => AssertAddFailsAsync(
            HostileJson.Parse(HostileJson.BaseDocument),
            Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = HostileJson.Parse(HostileJson.Nest(64)) } },
            "The proof options object could not be serialized as JSON.");

    [Fact]
    public async Task AddProof_ExistingProofPushedPast64Levels_ThrowsProofGenerationExceptionWithCause()
    {
        // Defence in depth: the document passes the check at exactly 64 levels, but appending a
        // second proof wraps the existing object-form proof in an array, one level deeper, which
        // the serializer refuses. That must still surface as ProofGenerationException.
        var document = HostileJson.InProof(Fixtures.Single, "\"d\":" + HostileJson.Nest(62));

        var thrown = await FluentActions.Invoking(() => Pipeline.AddProofAsync(HostileJson.Parse(document), Options(), Signer))
            .Should().ThrowExactlyAsync<ProofGenerationException>().WithMessage("The secured document could not be assembled.");
        thrown.Which.InnerException.Should().BeOfType<JsonException>();
    }

    [Fact]
    public async Task AddProof_ChainOverProofPushedPast64Levels_ThrowsProofGenerationExceptionWithCause()
    {
        // As above, for a chain: the signing input re-embeds the referenced proof in an array.
        var document = HostileJson.InProof(Fixtures.WithId, "\"d\":" + HostileJson.Nest(62));

        var thrown = await FluentActions.Invoking(() => Pipeline.AddProofAsync(HostileJson.Parse(document), Options() with { PreviousProof = "urn:p1" }, Signer))
            .Should().ThrowExactlyAsync<ProofGenerationException>().WithMessage("The document could not be prepared for signing.");
        thrown.Which.InnerException.Should().BeOfType<JsonException>();
    }

    // ------------------------------------------- over-rejection guards: these must still work

    [Fact]
    public async Task EscapedSpellings_StillSignAndVerify()
    {
        // A BMP escape and a surrogate-pair escape in a member name and a value, and an escaped
        // solidus; then the signed output re-spelled with every non-ASCII character and every
        // solidus escaped, which canonicalizes to the same bytes.
        var pair = HostileJson.Esc(0xD83D) + HostileJson.Esc(0xDE00);
        var bmp = HostileJson.Esc(0xE9);
        var document = HostileJson.LastMember(
            HostileJson.BaseDocument,
            "\"" + bmp + "\":\"" + bmp + "\",\"" + pair + "\":\"" + pair + "\",\"s\":\"a\\/b\"");

        var secured = await Pipeline.AddProofAsync(HostileJson.Parse(document), Options(), Signer);
        var securedText = secured.GetRawText();

        Pipeline.Verify(secured, PublicKey).Verified.Should().BeTrue();
        Pipeline.Verify(HostileJson.Parse(HostileJson.EscapeNonAscii(securedText)), PublicKey).Verified.Should().BeTrue();
        Pipeline.Verify(HostileJson.Parse(HostileJson.Splice(securedText, "/", "\\/")), PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task CommentsAndTrailingCommas_StillSignAndVerify()
    {
        // A lenient parse leaves comments and trailing commas in the element's raw text. They never
        // reach a canonicalizer, and such documents have always signed and verified.
        var lenient = "{/* c */\"@context\":[\"" + HostileJson.Context + "\",],\"a\":1, // line\n}";
        var secured = await Pipeline.AddProofAsync(HostileJson.ParseLenient(lenient), Options(), Signer);
        var commented = "{/* c */" + Fixtures.Single[1..^1] + ",}";

        Pipeline.Verify(secured, PublicKey).Verified.Should().BeTrue();
        Pipeline.Verify(HostileJson.ParseLenient(commented), PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task DepthOf64_StillSignsAndVerifies()
    {
        var document = HostileJson.LastMember(HostileJson.BaseDocument, "\"d\":" + HostileJson.Nest(63));

        var secured = await Pipeline.AddProofAsync(HostileJson.Parse(document), Options(), Signer);

        Pipeline.Verify(secured, PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task SameNameInSiblingObjects_StillSignsAndVerifies()
    {
        // Names that differ only in case are distinct names.
        var document = HostileJson.LastMember(HostileJson.BaseDocument, "\"x\":{\"a\":1},\"y\":{\"a\":2},\"z\":[{\"a\":3},{\"a\":4}],\"w\":{\"id\":1,\"ID\":2}");

        var secured = await Pipeline.AddProofAsync(HostileJson.Parse(document), Options(), Signer);

        Pipeline.Verify(secured, PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task OptionsExtensionWithEscapes_StillSignsAndVerifies()
    {
        var value = "\"" + HostileJson.Esc(0xE9) + HostileJson.Esc(0xD83D) + HostileJson.Esc(0xDE00) + "\"";
        var options = Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = HostileJson.Parse(value) } };

        var secured = await Pipeline.AddProofAsync(HostileJson.Parse(HostileJson.BaseDocument), options, Signer);

        Pipeline.Verify(secured, PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task CommentsInsideProofs_StillSignAndVerify()
    {
        // A comment inside an existing proof, and inside the proof a chain references: steps that
        // embed those proofs re-parse their raw text, so the pipeline carries on with a strict copy.
        var withExisting = HostileJson.ParseLenient(HostileJson.Splice(Fixtures.Single, "\"proofValue\"", "/* c */\"proofValue\""));
        var chain = HostileJson.ParseLenient(HostileJson.Splice(Fixtures.Chain, "\"id\":\"urn:p1\"", "\"id\":\"urn:p1\" /* c */"));

        var proofSet = await Pipeline.AddProofAsync(withExisting, Options(), Signer);

        Pipeline.Verify(proofSet, PublicKey).Verified.Should().BeTrue();
        Pipeline.Verify(chain, PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task AddProof_OptionsAtTheDepthTheyWillOccupy_StillSignAndVerify()
    {
        // The proof sits one level below the document root: options of depth 63 fit.
        var options = Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = HostileJson.Parse(HostileJson.Nest(62)) } };

        var secured = await Pipeline.AddProofAsync(HostileJson.Parse(HostileJson.BaseDocument), options, Signer);

        Pipeline.Verify(secured, PublicKey).Verified.Should().BeTrue();

        // Added to a document that already carries a proof, it becomes an array element, two levels down.
        var deeper = Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = HostileJson.Parse(HostileJson.Nest(61)) } };
        var proofSet = await Pipeline.AddProofAsync(HostileJson.Parse(Fixtures.Single), deeper, Signer);
        Pipeline.Verify(proofSet, PublicKey).Verified.Should().BeTrue();
    }

    [Theory]
    [InlineData(false, 62, 63)]
    [InlineData(true, 61, 62)]
    public async Task AddProof_OptionsTooDeepForTheSecuredDocument_ThrowBeforeSigning(bool existingProof, int lastAcceptedNest, int budget)
    {
        // Rejected before the suite is called, so no signature is spent on a document that could
        // not be written out (PR #35 review). Nest(n) under a member of the proof object is n + 1 deep.
        var signer = new CountingSigner(Signer);
        var options = Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["x"] = HostileJson.Parse(HostileJson.Nest(lastAcceptedNest + 1)) } };
        var document = HostileJson.Parse(existingProof ? Fixtures.Single : HostileJson.BaseDocument);

        await FluentActions.Invoking(() => Pipeline.AddProofAsync(document, options, signer))
            .Should().ThrowExactlyAsync<ProofGenerationException>()
            .WithMessage($"The proof options object nests deeper than {budget} levels.");
        signer.Calls.Should().Be(0);
    }

    [Fact]
    public void Verify_ProofReEmbeddedPast64Levels_IsAPerProofTransformationError()
    {
        // Defence in depth on the verify side: a proof whose previousProof names itself is
        // re-embedded as an array element, one level deeper than it sits in the document. At the
        // depth limit that cannot be written, and the proof fails as a result with a fixed message.
        var proof = "{\"id\":\"urn:self\",\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"" + Cryptosuite
            + "\",\"verificationMethod\":\"did:example:alice#key-1\",\"proofPurpose\":\"assertionMethod\",\"previousProof\":\"urn:self\",\"proofValue\":\"z1\",\"d\":"
            + HostileJson.Nest(62) + "}";
        var document = HostileJson.LastMember(HostileJson.BaseDocument, "\"proof\":" + proof);

        var result = Pipeline.Verify(HostileJson.Parse(document), PublicKey);

        result.Verified.Should().BeFalse();
        result.Problems.Should().BeEmpty("the document itself passes the check");
        var problem = result.ProofResults.Should().ContainSingle().Subject.Problems.Should().ContainSingle().Subject;
        problem.Code.Should().Be(ProofProblemCodes.ProofTransformationError);
        problem.Message.Should().Be("The secured document could not be transformed for verification.");
    }

    [Fact]
    public void ProofChain_StillVerifies()
        => Pipeline.Verify(HostileJson.Parse(Fixtures.Chain), PublicKey).Verified.Should().BeTrue();

    // ------------------------------------------------------------------------ builders

    private Signed Fixtures => _signed.Value;

    private DataIntegrityProof Options() => new()
    {
        Cryptosuite = Cryptosuite,
        Created = "2026-01-01T00:00:00Z",
        VerificationMethod = "did:example:alice#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    private Signed SignFixtures()
    {
        var single = Pipeline.AddProofAsync(HostileJson.Parse(HostileJson.BaseDocument), Options(), Signer).GetAwaiter().GetResult();
        var withId = Pipeline.AddProofAsync(HostileJson.Parse(HostileJson.BaseDocument), Options() with { Id = "urn:p1" }, Signer).GetAwaiter().GetResult();
        var chain = Pipeline.AddProofAsync(withId, Options() with { Id = "urn:p2", PreviousProof = "urn:p1" }, Signer).GetAwaiter().GetResult();
        return new Signed(single.GetRawText(), withId.GetRawText(), chain.GetRawText(), single.GetProperty("proof").GetRawText());
    }

    private string SurrogateForVerify(string placement, string e) => placement switch
    {
        "first member name" => HostileJson.FirstMember(Fixtures.Single, "\"" + e + "\":1"),
        "last member name" => HostileJson.LastMember(Fixtures.Single, "\"" + e + "\":1"),
        "nested member name" => HostileJson.LastMember(Fixtures.Single, "\"n\":{\"" + e + "\":1}"),
        "member value" => HostileJson.LastMember(Fixtures.Single, "\"v\":\"" + e + "\""),
        "array element" => HostileJson.LastMember(Fixtures.Single, "\"n\":[\"" + e + "\"]"),
        "@context value" => HostileJson.Splice(Fixtures.Single, "\"" + HostileJson.Context + "\"]", "\"" + HostileJson.Context + "\",\"" + e + "\"]"),
        "proof member name" => HostileJson.InProof(Fixtures.Single, "\"" + e + "\":1"),
        "proof member value" => HostileJson.InProof(Fixtures.Single, "\"x\":\"" + e + "\""),
        "referenced proof id" => HostileJson.Splice(Fixtures.Chain, "\"id\":\"urn:p1\"", "\"id\":\"" + e + "\""),
        "other proof member name" => HostileJson.Splice(Fixtures.Chain, "\"id\":\"urn:p1\"", "\"id\":\"urn:p1\",\"" + e + "\":1"),
        _ => throw new ArgumentOutOfRangeException(nameof(placement), placement, null),
    };

    private string DuplicateForVerify(string placement) => placement switch
    {
        "first members" => HostileJson.FirstMember(Fixtures.Single, "\"v\":1,\"v\":2"),
        "last members" => HostileJson.LastMember(Fixtures.Single, "\"v\":1,\"v\":2"),
        "nested object" => HostileJson.LastMember(Fixtures.Single, "\"n\":{\"v\":1,\"v\":2}"),
        "object in array" => HostileJson.LastMember(Fixtures.Single, "\"n\":[{\"x\":1},{\"y\":1,\"y\":2}]"),
        "escaped spelling" => HostileJson.LastMember(Fixtures.Single, "\"n\":{\"a\":1,\"" + HostileJson.Esc(0x61) + "\":2}"),
        "proof member" => HostileJson.InProof(Fixtures.Single, "\"x\":1,\"x\":2"),
        "second proof member" => HostileJson.LastMember(Fixtures.Single, "\"proof\":" + Fixtures.Proof),
        "other proof in chain" => HostileJson.Splice(Fixtures.Chain, "\"id\":\"urn:p1\"", "\"id\":\"urn:p1\",\"z\":1,\"z\":2"),
        _ => throw new ArgumentOutOfRangeException(nameof(placement), placement, null),
    };

    private string DepthForVerify(string placement) => placement switch
    {
        // The document object is level 1, so a member holding Nest(n) reaches level n + 1.
        "document, 65" => HostileJson.LastMember(Fixtures.Single, "\"d\":" + HostileJson.Nest(64)),
        "document, 100" => HostileJson.LastMember(Fixtures.Single, "\"d\":" + HostileJson.Nest(99)),
        // The proof object is level 2.
        "proof, 65" => HostileJson.InProof(Fixtures.Single, "\"d\":" + HostileJson.Nest(63)),
        _ => throw new ArgumentOutOfRangeException(nameof(placement), placement, null),
    };

    private byte[] Utf8ForVerify(string placement) => placement switch
    {
        "member name" => HostileJson.WithBytes(HostileJson.LastMember(Fixtures.Single, "\"XX\":1"), "XX", 0xFF, 0x58),
        "member value" => HostileJson.WithBytes(HostileJson.LastMember(Fixtures.Single, "\"v\":\"XX\""), "XX", 0xC3, 0x28),
        "proof member value" => HostileJson.WithBytes(HostileJson.InProof(Fixtures.Single, "\"x\":\"XX\""), "XX", 0xFF, 0xFE),
        // U+D800 encoded directly as UTF-8 bytes, which UTF-8 forbids (RFC 3629 §3).
        "encoded surrogate" => HostileJson.WithBytes(HostileJson.LastMember(Fixtures.Single, "\"v\":\"XXX\""), "XXX", 0xED, 0xA0, 0x80),
        _ => throw new ArgumentOutOfRangeException(nameof(placement), placement, null),
    };

    private (string Document, DataIntegrityProof Options) SurrogateForAdd(string placement, string e) => placement switch
    {
        "first member name" => (HostileJson.FirstMember(HostileJson.BaseDocument, "\"" + e + "\":1"), Options()),
        "last member name" => (HostileJson.LastMember(HostileJson.BaseDocument, "\"" + e + "\":1"), Options()),
        "nested member name" => (HostileJson.LastMember(HostileJson.BaseDocument, "\"n\":{\"" + e + "\":1}"), Options()),
        "member value" => (HostileJson.LastMember(HostileJson.BaseDocument, "\"v\":\"" + e + "\""), Options()),
        "array element" => (HostileJson.LastMember(HostileJson.BaseDocument, "\"n\":[\"" + e + "\"]"), Options()),
        "existing proof member name" => (HostileJson.InProof(Fixtures.Single, "\"" + e + "\":1"), Options()),
        "existing proof member value" => (HostileJson.InProof(Fixtures.Single, "\"x\":\"" + e + "\""), Options()),
        "referenced proof id" => (HostileJson.Splice(Fixtures.WithId, "\"id\":\"urn:p1\"", "\"id\":\"" + e + "\""), Options() with { PreviousProof = "urn:p1" }),
        _ => throw new ArgumentOutOfRangeException(nameof(placement), placement, null),
    };

    private string DuplicateForAdd(string placement) => placement switch
    {
        "first members" => HostileJson.FirstMember(HostileJson.BaseDocument, "\"v\":1,\"v\":2"),
        "last members" => HostileJson.LastMember(HostileJson.BaseDocument, "\"v\":1,\"v\":2"),
        "nested object" => HostileJson.LastMember(HostileJson.BaseDocument, "\"n\":{\"v\":1,\"v\":2}"),
        "escaped spelling" => HostileJson.LastMember(HostileJson.BaseDocument, "\"n\":{\"a\":1,\"" + HostileJson.Esc(0x61) + "\":2}"),
        "existing proof member" => HostileJson.InProof(Fixtures.Single, "\"x\":1,\"x\":2"),
        "second proof member" => HostileJson.LastMember(Fixtures.Single, "\"proof\":" + Fixtures.Proof),
        _ => throw new ArgumentOutOfRangeException(nameof(placement), placement, null),
    };

    private static string DepthForAdd(string placement) => placement switch
    {
        "document, 65" => HostileJson.LastMember(HostileJson.BaseDocument, "\"d\":" + HostileJson.Nest(64)),
        "document, 100" => HostileJson.LastMember(HostileJson.BaseDocument, "\"d\":" + HostileJson.Nest(99)),
        _ => throw new ArgumentOutOfRangeException(nameof(placement), placement, null),
    };

    private static byte[] Utf8ForAdd(string placement) => placement switch
    {
        "member name" => HostileJson.WithBytes(HostileJson.LastMember(HostileJson.BaseDocument, "\"XX\":1"), "XX", 0xFF, 0x58),
        "member value" => HostileJson.WithBytes(HostileJson.LastMember(HostileJson.BaseDocument, "\"v\":\"XX\""), "XX", 0xC3, 0x28),
        "encoded surrogate" => HostileJson.WithBytes(HostileJson.LastMember(HostileJson.BaseDocument, "\"v\":\"XXX\""), "XXX", 0xED, 0xA0, 0x80),
        _ => throw new ArgumentOutOfRangeException(nameof(placement), placement, null),
    };

    private async Task AssertDocumentFailureAsync(string entry, JsonElement document, string phrase)
    {
        DocumentVerificationResult result;
        if (entry == "Verify")
        {
            result = Pipeline.Verify(document, PublicKey);
        }
        else
        {
            var resolver = new CountingResolver();
            result = await Pipeline.VerifyAsync(document, resolver);
            resolver.Calls.Should().Be(0, "the check runs before any resolver call");
        }

        result.Verified.Should().BeFalse();
        result.ProofResults.Should().BeEmpty("the document is rejected before any proof is parsed");
        var problem = result.Problems.Should().ContainSingle().Subject;
        problem.Code.Should().Be(ProofProblemCodes.ProofTransformationError);
        problem.Message.Should().Be($"The secured document {phrase}.");
    }

    private Task AssertAddFailsAsync(JsonElement document, DataIntegrityProof options, string message)
        => FluentActions.Invoking(() => Pipeline.AddProofAsync(document, options, Signer))
            .Should().ThrowExactlyAsync<ProofGenerationException>().WithMessage(message);

    private static TheoryData<string, string> Cross(string[] first, string[] second)
    {
        var data = new TheoryData<string, string>();
        foreach (var a in first)
        {
            foreach (var b in second)
            {
                data.Add(a, b);
            }
        }

        return data;
    }

    private static TheoryData<string, string, string> Cross(string[] first, string[] second, string[] third)
    {
        var data = new TheoryData<string, string, string>();
        foreach (var a in first)
        {
            foreach (var b in second)
            {
                foreach (var c in third)
                {
                    data.Add(a, b, c);
                }
            }
        }

        return data;
    }

    private sealed record Signed(string Single, string WithId, string Chain, string Proof);

    private sealed class CountingSigner(ISigner inner) : ISigner
    {
        public int Calls { get; private set; }

        public KeyType KeyType => inner.KeyType;

        public ReadOnlyMemory<byte> PublicKey => inner.PublicKey;

        public string MultibasePublicKey => inner.MultibasePublicKey;

        public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        {
            Calls++;
            return inner.SignAsync(data, cancellationToken);
        }
    }

    private sealed class CountingResolver : IVerificationMethodResolver
    {
        public int Calls { get; private set; }

        public Task<ResolvedVerificationMethod?> ResolveAsync(string verificationMethodUrl, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult<ResolvedVerificationMethod?>(new ResolvedVerificationMethod
            {
                Id = verificationMethodUrl,
                Controller = "did:example:alice",
                PublicKey = PublicKey,
                Relationships = new HashSet<string>(StringComparer.Ordinal) { ProofPurposes.AssertionMethod },
            });
        }
    }
}
