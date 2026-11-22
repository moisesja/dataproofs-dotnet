using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Tests.Shared;

/// <summary>
/// Issue #61: a suite awaits its signer, so the proof it returns must be built from options the caller can no
/// longer reach. <see cref="DataIntegrityProof.Type"/> and <see cref="DataIntegrityProof.AdditionalProperties"/>
/// are settable, and the options' JSON values live in the caller's documents. A signer that changes the options
/// while it signs, a caller that changes them afterwards, and a caller that disposes the documents behind them
/// must all leave the proof as it was asked for. One derived class per suite (and variant).
/// </summary>
public abstract class Issue61OptionsCopyTestsBase
{
    /// <summary>An extension name the RDFC suites can sign: an absolute IRI needs no context term (issue #36).</summary>
    protected const string NoteName = "https://example.org/vocab#note";

    /// <summary>The suite under test.</summary>
    protected abstract ICryptosuite Suite { get; }

    /// <summary>A signer whose key type the suite supports.</summary>
    protected abstract ISigner Signer { get; }

    /// <summary>Valid proof options for the suite, naming it in <c>cryptosuite</c> so the pipeline can dispatch them.</summary>
    protected abstract DataIntegrityProof Options();

    /// <summary>The <c>type</c> the suite emits.</summary>
    protected virtual string ProofType => DataIntegrityProof.DataIntegrityProofType;

    /// <summary>Whether the suite secures a proof chain; the legacy JCS variant refuses one.</summary>
    protected virtual bool SecuresAProofChain => true;

    /// <summary>
    /// Whether the proof takes the options' <c>@context</c> for a document without one. The JCS suites refuse such
    /// options, since their verifier would refuse the proof (PR #62 follow-up b).
    /// </summary>
    protected virtual bool TakesTheOptionsContext => true;

    /// <summary>
    /// The suite over an RDF canonicalizer that runs <paramref name="during"/> before each canonicalization, as a
    /// canonicalizer of the caller's may; <see langword="null"/> for a suite that takes none.
    /// </summary>
    protected virtual ICryptosuite? SuiteWhoseCanonicalizerRuns(Action during) => null;

    private PublicKeyMaterial PublicKey => PublicKeyMaterial.FromRaw(Signer.KeyType, Signer.PublicKey.Span);

    private static JsonElement Document() => HostileJson.Parse(HostileJson.BaseDocument);

    // No @context, so the proof configuration takes the options' own (the fallback the suites keep).
    private const string ContextlessJson = """{"@id": "urn:example:credential", "https://example.org/vocab#name": "Alice"}""";

    private static JsonElement ContextlessDocument() => HostileJson.Parse(ContextlessJson);

    private const string FallbackContext = "[\"" + HostileJson.Context + "\",\"" + HostileJson.UndefinedTermsContext + "\"]";

    private DataIntegrityProof WithNote() => Options() with
    {
        AdditionalProperties = new Dictionary<string, JsonElement> { [NoteName] = HostileJson.Parse("\"as signed\"") },
    };

    // What a caller, or code sharing its options object, might do: change a settable member, change an
    // extension value, and add a reserved name after the FR-2 check has run.
    private static void Tamper(DataIntegrityProof options)
    {
        options.Type = "ChangedType";
        options.AdditionalProperties![NoteName] = HostileJson.Parse("\"changed\"");
        options.AdditionalProperties["proofValue"] = HostileJson.Parse("\"uFORGED\"");
    }

    // ECDSA signatures are randomized, so two proofs are compared without their proofValue.
    private static string WithoutSignature(DataIntegrityProof proof)
        => JsonSerializer.Serialize(proof with { ProofValue = null }, DataProofsJsonOptions.Default);

    private DataIntegrityProofPipeline Pipeline()
    {
        var registry = new CryptosuiteRegistry();
        registry.Register(Suite);
        return new DataIntegrityProofPipeline(registry);
    }

    [Fact]
    public async Task ASignerThatChangesTheOptionsWhileItSigns_StillGetsTheProofItAskedFor()
    {
        var expected = await Suite.CreateProofAsync(Document(), WithNote(), Signer);
        var options = WithNote();

        var proof = await Suite.CreateProofAsync(Document(), options, new MutatingSigner(Signer, () => Tamper(options)));

        proof.Type.Should().Be(ProofType);
        proof.AdditionalProperties![NoteName].GetString().Should().Be("as signed");
        proof.AdditionalProperties.Should().NotContainKey("proofValue");
        WithoutSignature(proof).Should().Be(WithoutSignature(expected));
        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task ThroughThePipeline_ASignerThatChangesTheOptionsWhileItSigns_StillGetsTheProofItAskedFor()
    {
        var pipeline = Pipeline();
        var options = WithNote();

        var secured = await pipeline.AddProofAsync(Document(), options, new MutatingSigner(Signer, () => Tamper(options)));

        var proof = secured.GetProperty("proof");
        proof.GetProperty("type").GetString().Should().Be(ProofType);
        proof.GetProperty(NoteName).GetString().Should().Be("as signed");
        proof.EnumerateObject().Count(member => member.Name == "proofValue").Should().Be(1);
        pipeline.Verify(secured, PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task ChangingTheOptionsAfterTheCall_LeavesTheProofAsIssued()
    {
        var options = WithNote();
        var proof = await Suite.CreateProofAsync(Document(), options, Signer);
        var issued = JsonSerializer.Serialize(proof, DataProofsJsonOptions.Default);

        Tamper(options);

        JsonSerializer.Serialize(proof, DataProofsJsonOptions.Default).Should().Be(issued);
        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task TheProof_OutlivesTheCallersJsonDocuments()
    {
        // An extension value and the options' fallback @context, read from documents the caller disposes after
        // the call: serializing the proof must not reach back into them. The JCS suites take no fallback @context.
        var expected = await Suite.CreateProofAsync(ContextlessDocument(), Options() with
        {
            Context = TakesTheOptionsContext ? HostileJson.Parse(FallbackContext) : null,
            AdditionalProperties = new Dictionary<string, JsonElement> { [NoteName] = HostileJson.Parse("\"kept\"") },
        }, Signer);

        DataIntegrityProof proof;
        using (var note = JsonDocument.Parse("\"kept\""))
        using (var context = JsonDocument.Parse(FallbackContext))
        {
            proof = await Suite.CreateProofAsync(ContextlessDocument(), Options() with
            {
                Context = TakesTheOptionsContext ? context.RootElement : null,
                AdditionalProperties = new Dictionary<string, JsonElement> { [NoteName] = note.RootElement },
            }, Signer);
        }

        WithoutSignature(proof).Should().Be(WithoutSignature(expected));
        Suite.VerifyProof(ContextlessDocument(), proof, PublicKey).Verified.Should().BeTrue();
    }

    /// <summary>
    /// Tries every public way a caller holding <paramref name="reference"/> might write to its ids through
    /// <see cref="PreviousProofReference.Values"/>, and asserts that each one is refused. The wrapper first used,
    /// <c>ReadOnlyCollection&lt;string&gt;</c>, gave the array away through <c>ICollection.SyncRoot</c> (PR #62 review).
    /// The route at construction, a collection that keeps the array it is copied into, is <see cref="CapturingIds"/>'s.
    /// </summary>
    public static void TryToRewrite(PreviousProofReference reference)
    {
        object values = reference.Values;
        var written = new List<string>();
        void Try(string route, Action write)
        {
            try
            {
                write();
                written.Add(route);
            }
            catch (InvalidCastException)
            {
            }
            catch (NotSupportedException)
            {
            }
        }

        Try("string[]", () => ((string[])values)[0] = "urn:proof:changed");
        Try("IList<string>", () => ((IList<string>)values)[0] = "urn:proof:changed");
        Try("ICollection<string>", () => ((ICollection<string>)values).Clear());
        Try("IList", () => ((IList)values)[0] = "urn:proof:changed");
        Try("ICollection.SyncRoot", () => ((string[])((ICollection)values).SyncRoot)[0] = "urn:proof:changed");
        Try("ICollection.SyncRoot as IList", () => ((IList)((ICollection)values).SyncRoot)[0] = "urn:proof:changed");

        written.Should().BeEmpty("no public route may write to a previousProof reference");
    }

    /// <summary>
    /// The ways a caller builds a <c>previousProof</c>: a bare string, an array, and an array from a collection of its
    /// own that keeps the array its <c>CopyTo</c> is handed (PR #62 review). See <see cref="CallersPreviousProof"/>.
    /// </summary>
    public static TheoryData<string> PreviousProofForms() => ["string", "array", "array from the caller's collection"];

    /// <summary>
    /// The <c>previousProof</c> that <paramref name="form"/> names, with the ids "urn:proof:original" and, in the array
    /// forms, "urn:proof:second", and an action that makes every write its caller can try: each public route through
    /// <see cref="PreviousProofReference.Values"/>, then the array its collection was handed, if it was handed one.
    /// </summary>
    public static (PreviousProofReference Reference, Action Rewrite) CallersPreviousProof(string form)
    {
        var ids = new CapturingIds("urn:proof:original", "urn:proof:second");
        var reference = form switch
        {
            "string" => PreviousProofReference.FromSingle("urn:proof:original"),
            "array" => PreviousProofReference.FromValues(["urn:proof:original", "urn:proof:second"]),
            _ => PreviousProofReference.FromValues(ids),
        };

        return (reference, () =>
        {
            TryToRewrite(reference);
            ids.WriteToHandedArray(0, "urn:proof:changed");
        });
    }

    [Theory]
    [MemberData(nameof(PreviousProofForms), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ACallerThatTriesToRewriteItsPreviousProof_LeavesTheProofAsIssued(string form)
    {
        // The copy shares previousProof because nothing can change it: tried while the signer runs and after the call.
        var expected = await Suite.CreateProofAsync(
            Document(), Options() with { PreviousProof = CallersPreviousProof(form).Reference }, Signer);
        var (previousProof, rewrite) = CallersPreviousProof(form);

        var proof = await Suite.CreateProofAsync(
            Document(), Options() with { PreviousProof = previousProof }, new MutatingSigner(Signer, rewrite));
        rewrite();

        WithoutSignature(proof).Should().Be(WithoutSignature(expected));
        proof.PreviousProof!.Values[0].Should().Be("urn:proof:original");
        proof.PreviousProof.IsArrayForm.Should().Be(form != "string");
        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(PreviousProofForms), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ThroughThePipeline_ACallerThatTriesToRewriteItsPreviousProof_GetsTheProofItAskedFor(string form)
    {
        // The proofs previousProof names are already in the document, so the pipeline's lookup finds them.
        var pipeline = Pipeline();
        var chain = await pipeline.AddProofAsync(Document(), Options() with { Id = "urn:proof:original" }, Signer);
        chain = await pipeline.AddProofAsync(chain, Options() with { Id = "urn:proof:second" }, Signer);
        var (previousProof, rewrite) = CallersPreviousProof(form);
        if (!SecuresAProofChain)
        {
            // No chain to rewrite: the pipeline hands the suite the predecessors under "proof", which it refuses.
            await FluentActions.Awaiting(() => pipeline.AddProofAsync(chain, Options() with { PreviousProof = previousProof }, Signer))
                .Should().ThrowAsync<ProofGenerationException>().WithMessage("*already carries a 'proof' member*");
            return;
        }

        var secured = await pipeline.AddProofAsync(
            chain, Options() with { PreviousProof = previousProof }, new MutatingSigner(Signer, rewrite));

        var proof = secured.GetProperty("proof").EnumerateArray().Last();
        JsonSerializer.Serialize(proof.GetProperty("previousProof")).Should().Be(
            form == "string" ? "\"urn:proof:original\"" : "[\"urn:proof:original\",\"urn:proof:second\"]");
        pipeline.Verify(secured, PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task ASignerThatDisposesTheCallersDocumentWhileItSigns_StillGetsTheProofItAskedFor()
    {
        // After the await nothing reads the caller's document again: the legacy RDFC variant took the proof's
        // @context from it a second time (issue #61 adversarial review).
        var expected = await Suite.CreateProofAsync(Document(), WithNote(), Signer);
        var document = JsonDocument.Parse(HostileJson.BaseDocument);

        var proof = await Suite.CreateProofAsync(document.RootElement, WithNote(), new MutatingSigner(Signer, document.Dispose));

        WithoutSignature(proof).Should().Be(WithoutSignature(expected));
        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    public static TheoryData<string, bool> DisposedValueCases() => new()
    {
        { "@context", false }, { "@context", true }, { "extension value", false }, { "extension value", true },
    };

    [Theory]
    [MemberData(nameof(DisposedValueCases), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task AnOptionsValueFromADisposedDocument_IsAProofGenerationException(string member, bool throughThePipeline)
    {
        // Even an options @context the suite would replace with the document's: the copy reads every value.
        JsonElement disposed;
        using (var source = JsonDocument.Parse(member == "@context" ? FallbackContext : "\"x\""))
        {
            disposed = source.RootElement;
        }

        var options = member == "@context"
            ? Options() with { Context = disposed }
            : Options() with { AdditionalProperties = new Dictionary<string, JsonElement> { [NoteName] = disposed } };

        await CreateAsync(options, throughThePipeline).Should().ThrowAsync<ProofGenerationException>()
            .WithMessage("The proof options hold a JSON value whose document has been disposed.");
    }

    public static TheoryData<string, bool> BadNameCases() => new()
    {
        { "null", false }, { "null", true }, { "repeated", false }, { "repeated", true },
    };

    [Theory]
    [MemberData(nameof(BadNameCases), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ANullOrRepeatedExtensionName_IsAProofGenerationException_ThatQuotesNoName(string fault, bool throughThePipeline)
    {
        // A dictionary of the caller's own making can enumerate either; the message must not quote the name (FR-23).
        const string secret = "https://example.org/vocab#secret-claim-name";
        var value = HostileJson.Parse("\"x\"");
        var members = fault == "null"
            ? new ScriptedDictionary([new(null!, value)], count: 1)
            : new ScriptedDictionary([new(secret, value), new(secret, value)], count: 2);

        var thrown = await CreateAsync(Options() with { AdditionalProperties = members }, throughThePipeline)
            .Should().ThrowAsync<ProofGenerationException>();

        thrown.Which.Message.Should().Be(fault == "null"
            ? "The proof options have an extension member with a null name."
            : "The proof options repeat an extension member name.");
        thrown.Which.ToString().Should().NotContain("secret-claim-name");
    }

    [Fact]
    public async Task ExtensionMembers_AreCopiedAsTheyEnumerate_NotSizedByTheCallersCount()
    {
        // A count of 0 once made the copy skip enumeration and drop the member that serialization would have written.
        var options = Options() with
        {
            AdditionalProperties = new ScriptedDictionary([new(NoteName, HostileJson.Parse("\"as signed\""))], count: 0),
        };

        var proof = await Suite.CreateProofAsync(Document(), options, Signer);

        proof.AdditionalProperties![NoteName].GetString().Should().Be("as signed");
        WithoutSignature(proof).Should().Be(WithoutSignature(await Suite.CreateProofAsync(Document(), WithNote(), Signer)));
        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    public static TheoryData<bool> DirectAndThroughThePipeline() => [false, true];

    [Theory]
    [MemberData(nameof(DirectAndThroughThePipeline), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ASignerWhoseKeyTypeChangesTheOptions_StillGetsTheProofItAskedFor(bool throughThePipeline)
    {
        // Every suite reads KeyType before it checks the options, so this shows the copy comes first; a change made
        // inside SignAsync cannot (PR #62 review: the copy moved below the checks survived every other row).
        var expected = await Suite.CreateProofAsync(Document(), WithNote(), Signer);
        var options = WithNote();
        var signer = new MutatingSigner(Signer, () => { }, onKeyType: () => Tamper(options));

        var proof = await IssueAsync(options, signer, throughThePipeline);

        proof.Type.Should().Be(ProofType);
        proof.AdditionalProperties![NoteName].GetString().Should().Be("as signed");
        proof.AdditionalProperties.Should().NotContainKey("proofValue");
        WithoutSignature(proof).Should().Be(WithoutSignature(expected));
        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(DirectAndThroughThePipeline), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ExtensionMembersThatChangeBetweenReads_AreReadOnce(bool throughThePipeline)
    {
        // A dictionary of the caller's that answers its first read with a note and every later read with another
        // note and a proofValue: the checks and the proof must both see the first answer, the copy's.
        var options = Options() with
        {
            AdditionalProperties = new ScriptedDictionary(
                [new(NoteName, HostileJson.Parse("\"as signed\""))],
                count: 1,
                later: [new(NoteName, HostileJson.Parse("\"changed\"")), new("proofValue", HostileJson.Parse("\"uFORGED\""))]),
        };

        var proof = await IssueAsync(options, Signer, throughThePipeline);

        proof.AdditionalProperties![NoteName].GetString().Should().Be("as signed");
        proof.AdditionalProperties.Should().NotContainKey("proofValue");
        WithoutSignature(proof).Should().Be(WithoutSignature(await Suite.CreateProofAsync(Document(), WithNote(), Signer)));
        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task ExtensionNamesThatDifferOnlyInCase_AreBothKept()
    {
        // JSON member names compare ordinally, so these are two members; a copy that compared names ignoring case
        // would refuse valid options (PR #62 review: OrdinalIgnoreCase survived every other test).
        const string upperName = "https://example.org/vocab#Note";
        var options = Options() with
        {
            AdditionalProperties = new Dictionary<string, JsonElement>
            {
                [NoteName] = HostileJson.Parse("\"lower\""),
                [upperName] = HostileJson.Parse("\"upper\""),
            },
        };

        var proof = await Suite.CreateProofAsync(Document(), options, Signer);

        proof.AdditionalProperties![NoteName].GetString().Should().Be("lower");
        proof.AdditionalProperties[upperName].GetString().Should().Be("upper");
        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(DirectAndThroughThePipeline), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task WhatTheCallersDictionaryThrows_PropagatesUnchanged(bool throughThePipeline)
    {
        // The dictionary is the caller's code, as the signer is: what it throws is not a fault the copy found, so it
        // is not wrapped, even when it is the ObjectDisposedException the copy maps for a value (PR #62 review).
        foreach (var fault in new Exception[]
        {
            new ArgumentException("the caller's own"),
            new ObjectDisposedException("the caller's own"),
            new InvalidOperationException("Collection was modified; enumeration operation may not execute."),
        })
        {
            var options = Options() with { AdditionalProperties = new ScriptedDictionary([], count: 0, fault: fault) };

            var thrown = await CreateAsync(options, throughThePipeline).Should().ThrowAsync<Exception>();

            thrown.Which.Should().BeSameAs(fault);
        }
    }

    [Theory]
    [MemberData(nameof(DirectAndThroughThePipeline), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ASignerWhoseKeyTypeDisposesTheCallersDocument_StillGetsTheProofItAskedFor(bool throughThePipeline)
    {
        // The getter runs before the suite reads the document: the JCS, RDFC and legacy suites let the raw
        // ObjectDisposedException out until the document was copied at entry (PR #62).
        var expected = await Suite.CreateProofAsync(Document(), WithNote(), Signer);
        var document = JsonDocument.Parse(HostileJson.BaseDocument);
        var signer = new MutatingSigner(Signer, () => { }, onKeyType: document.Dispose);

        var proof = await IssueAsync(document.RootElement, WithNote(), signer, throughThePipeline);

        WithoutSignature(proof).Should().Be(WithoutSignature(expected));
        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(DirectAndThroughThePipeline), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ASignerWhoseKeyTypeChangesAfterItsFirstRead_StillGetsTheProofItAskedFor(bool throughThePipeline)
    {
        // The steps that depend on the key type (the support check, the hash, the RDFC canonicalization hash, the
        // signature encoding) each read KeyType again, so a signer that answered differently got a proof made with
        // two key types. The suites now read it once (PR #62 follow-up d3).
        var later = Signer.KeyType == KeyType.P384 ? KeyType.P256 : KeyType.P384;

        var proof = await IssueAsync(WithNote(), new ShiftingKeyTypeSigner(Signer, later), throughThePipeline);

        WithoutSignature(proof).Should().Be(WithoutSignature(await Suite.CreateProofAsync(Document(), WithNote(), Signer)));
        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    public static TheoryData<string, bool> RewriteCases() => new()
    {
        { "KeyType", false }, { "KeyType", true }, { "SignAsync", false }, { "SignAsync", true },
    };

    [Theory]
    [MemberData(nameof(RewriteCases), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ASignerThatRewritesTheCallersBuffer_StillGetsTheProofItAskedFor(string when, bool throughThePipeline)
    {
        // JsonDocument.Parse(ReadOnlyMemory<byte>) reads the caller's memory, so the caller can change the document
        // while caller code runs. The proof must be over the document as given (PR #62).
        var buffer = Encoding.UTF8.GetBytes(HostileJson.BaseDocument);
        using var document = JsonDocument.Parse(buffer.AsMemory());
        var at = Array.LastIndexOf(buffer, (byte)'1');
        void Rewrite() => buffer[at] = (byte)'2';
        var signer = when == "KeyType"
            ? new MutatingSigner(Signer, () => { }, onKeyType: Rewrite)
            : new MutatingSigner(Signer, Rewrite);

        var proof = await IssueAsync(document.RootElement, WithNote(), signer, throughThePipeline);

        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(DirectAndThroughThePipeline), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task AnExtensionDictionaryThatRewritesTheCallersBuffer_CannotChangeTheDocument(bool throughThePipeline)
    {
        // Reading the options' dictionary runs the caller's code, so the document is copied before it (PR #62 review:
        // the dictionary ran first, and the proof was over the rewritten document).
        var buffer = Encoding.UTF8.GetBytes(HostileJson.BaseDocument);
        using var document = JsonDocument.Parse(buffer.AsMemory());
        var at = Array.LastIndexOf(buffer, (byte)'1');
        var options = Options() with
        {
            AdditionalProperties = new ScriptedDictionary(
                [new(NoteName, HostileJson.Parse("\"as signed\""))], count: 1, onRead: () => buffer[at] = (byte)'2'),
        };

        var proof = await IssueAsync(document.RootElement, options, Signer, throughThePipeline);

        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task ASignerWhoseKeyTypeThrows_IsReadOnlyAfterTheDocumentIsChecked()
    {
        // KeyType is read once, where the suites first read it, so a document fault is still reported first
        // (PR #62 review: reading it at entry let the getter's exception out instead).
        var signer = new MutatingSigner(Signer, () => { }, onKeyType: () => throw new NotSupportedException("the caller's own"));

        await FluentActions.Awaiting(() => Suite.CreateProofAsync(HostileJson.Parse("[1]"), WithNote(), signer))
            .Should().ThrowAsync<ProofGenerationException>().WithMessage("The document to secure must be a JSON object.");
    }

    public static TheoryData<string> RenamedMemberValues() => ["\"abc\"", "null", "[\"x\"]"];

    [Theory]
    [MemberData(nameof(RenamedMemberValues), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ThroughThePipeline_AMemberRenamedToProofWhileTheSignerRuns_LeavesTheSecuredDocumentAsGiven(string value)
    {
        // The pipeline assembles its output from the document after the suite is awaited. Renaming a member to
        // "proof" meanwhile made that a raw InvalidCastException, a NullReferenceException, or a document that does
        // not verify (PR #62 review).
        var json = HostileJson.BaseDocument.TrimEnd('}') + ",\"spare\":" + value + "}";
        var buffer = Encoding.UTF8.GetBytes(json);
        using var document = JsonDocument.Parse(buffer.AsMemory());
        var at = buffer.AsSpan().IndexOf("\"spare\""u8);
        var pipeline = Pipeline();
        var signer = new MutatingSigner(Signer, () => "\"proof\""u8.CopyTo(buffer.AsSpan(at)));

        var secured = await pipeline.AddProofAsync(document.RootElement, WithNote(), signer);

        JsonSerializer.Serialize(secured.GetProperty("spare")).Should().Be(value);
        secured.GetProperty("proof").ValueKind.Should().Be(JsonValueKind.Object);
        pipeline.Verify(secured, PublicKey).Verified.Should().BeTrue();
    }

    [Theory]
    [MemberData(nameof(DirectAndThroughThePipeline), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ADocumentDisposedBeforeTheCall_IsAProofGenerationException(bool throughThePipeline)
    {
        // Reading it raised the raw ObjectDisposedException; the copy at entry reports it as a disposed options value is.
        JsonElement disposed;
        using (var document = JsonDocument.Parse(HostileJson.BaseDocument))
        {
            disposed = document.RootElement;
        }

        Func<Task> act = throughThePipeline
            ? () => Pipeline().AddProofAsync(disposed, WithNote(), Signer)
            : () => Suite.CreateProofAsync(disposed, WithNote(), Signer);

        (await act.Should().ThrowAsync<ProofGenerationException>().WithMessage("The document to secure has been disposed."))
            .WithInnerException<ObjectDisposedException>();
    }

    public static TheoryData<string, bool> DisposedWhileCopiedCases() => new()
    {
        { "document", false }, { "document", true }, { "extension value", false }, { "extension value", true },
        { "options @context", false }, { "options @context", true },
    };

    [Theory]
    [MemberData(nameof(DisposedWhileCopiedCases), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task AJsonDocumentDisposedWhileItIsCopied_IsAProofGenerationException(string input, bool throughThePipeline)
    {
        // A document disposed on another thread while it is copied returns its buffers to the pool, and the next parse
        // rents them, so the copy could hold another document's bytes and be signed. The source is read again after
        // the copy, and a document disposed meanwhile is refused (PR #62 review). Here the dispose runs inside the
        // copy, from the memory behind the document, which the copy reads after the document's own metadata.
        var memory = new CallerMemory(input switch
        {
            "document" => HostileJson.BaseDocument,
            "extension value" => "\"as signed\"",
            _ => "\"https://www.w3.org/ns/credentials/v2\"",
        });
        var options = input switch
        {
            "document" => WithNote(),
            "extension value" => Options() with
            {
                AdditionalProperties = new Dictionary<string, JsonElement> { [NoteName] = memory.Document.RootElement },
            },
            // Copied, and so checked, even where the suite takes the document's @context instead (PR #62 review: no
            // row covered it).
            _ => WithNote() with { Context = memory.Document.RootElement },
        };
        var document = input == "document" ? memory.Document.RootElement : Document();
        memory.DisposeOnNextRead();

        var act = () => IssueAsync(document, options, Signer, throughThePipeline);

        (await act.Should().ThrowAsync<ProofGenerationException>().WithMessage(input == "document"
                ? "The document to secure has been disposed."
                : "The proof options hold a JSON value whose document has been disposed."))
            .WithInnerException<ObjectDisposedException>();
    }

    public static TheoryData<string, bool> MidDisposeCases() => new()
    {
        { "before the call", false }, { "before the call", true },
        { "while it is copied", false }, { "while it is copied", true },
        { "while it is copied, and the copy throws", false }, { "while it is copied, and the copy throws", true },
    };

    [Theory]
    [MemberData(nameof(MidDisposeCases), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ADocumentCaughtMidDispose_IsAProofGenerationException(string when, bool throughThePipeline)
    {
        // A read that races Dispose on another thread can find the metadata gone before the document reports itself
        // disposed, and throws ArgumentOutOfRangeException. That escaped raw from the first read and was untested
        // (PR #62 review). The state is set here as the race leaves it.
        var memory = new CallerMemory(HostileJson.BaseDocument);
        switch (when)
        {
            case "before the call":
                CallerMemory.MidDispose(memory.Document);
                break;
            case "while it is copied":
                memory.OnNextRead(CallerMemory.MidDispose);
                break;
            default:
                memory.OnNextRead(document =>
                {
                    CallerMemory.MidDispose(document);
                    throw new ArgumentOutOfRangeException("start");
                });
                break;
        }

        var act = () => IssueAsync(memory.Document.RootElement, WithNote(), Signer, throughThePipeline);

        (await act.Should().ThrowAsync<ProofGenerationException>().WithMessage("The document to secure has been disposed."))
            .WithInnerException<ObjectDisposedException>();
    }

    [Theory]
    [MemberData(nameof(DirectAndThroughThePipeline), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task WhatTheCallersMemoryThrows_PropagatesUnchanged(bool throughThePipeline)
    {
        // An ArgumentOutOfRangeException or ObjectDisposedException from the memory behind a document that was never
        // disposed is the caller's, and not a dispose (PR #62 review: each was reported as "disposed").
        foreach (var fault in new Exception[] { new ArgumentOutOfRangeException("the caller's own"), new ObjectDisposedException("the caller's own") })
        {
            var memory = new CallerMemory(HostileJson.BaseDocument);
            memory.OnNextRead(_ => throw fault);

            var act = () => IssueAsync(memory.Document.RootElement, WithNote(), Signer, throughThePipeline);

            (await act.Should().ThrowAsync<Exception>()).Which.Should().BeSameAs(fault);
        }
    }

    // (whether the document carries @context, whether the document as given is tampered with)
    public static TheoryData<bool, bool> RewritingProofCases() => new()
    {
        { true, true }, { true, false }, { false, true }, { false, false },
    };

    [Theory]
    [MemberData(nameof(RewritingProofCases), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task VerifyProof_IsAboutTheDocumentAsGiven_WhateverReadingTheProofDoes(bool documentHasContext, bool tampered)
    {
        // Reading the proof's extension dictionary runs the caller's code, so the suite copies the document first: a
        // proof that rewrites the caller's buffer as it is read can neither make a tampered document verify nor a
        // signed one fail (PR #62 review: a suite's own VerifyProof read the caller's document as given). Without an
        // @context, JCS reads the caller's document only after the proof (the adversarial pass's route).
        var (buffer, at, original) = SignedBuffer(documentHasContext);
        var signed = await Suite.CreateProofAsync(HostileJson.Parse(Encoding.UTF8.GetString(buffer)), NoteOptions(documentHasContext), Signer);
        var other = (byte)(original + 1);
        if (tampered)
        {
            buffer[at] = other;
        }

        using var document = JsonDocument.Parse(buffer.AsMemory());
        var proof = signed with
        {
            AdditionalProperties = new ScriptedDictionary(
                [new(NoteName, signed.AdditionalProperties![NoteName])], count: 1,
                onRead: () => buffer[at] = tampered ? original : other),
        };

        Suite.VerifyProof(document.RootElement, proof, PublicKey).Verified.Should().Be(!tampered);
    }

    [Theory]
    [MemberData(nameof(RewritingProofCases), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task VerifyProof_IsAboutTheDocumentAsGiven_WhateverTheCallersCanonicalizerDoes(bool documentHasContext, bool tampered)
    {
        // An RDF canonicalizer of the caller's runs during verification and is handed the suite's copy, so rewriting
        // the caller's buffer cannot make a tampered document verify, nor a signed one fail (PR #62 review: no row
        // covered this route, which gave the wrong verdict before). Suites that take no canonicalizer have no such route.
        var (buffer, at, original) = SignedBuffer(documentHasContext);
        var other = (byte)(original + 1);
        var suite = SuiteWhoseCanonicalizerRuns(() => buffer[at] = tampered ? original : other);
        if (suite is null)
        {
            return;
        }

        var signed = await Suite.CreateProofAsync(HostileJson.Parse(Encoding.UTF8.GetString(buffer)), NoteOptions(documentHasContext), Signer);
        if (tampered)
        {
            buffer[at] = other;
        }

        using var document = JsonDocument.Parse(buffer.AsMemory());

        suite.VerifyProof(document.RootElement, signed, PublicKey).Verified.Should().Be(!tampered);
    }

    // The bytes of a document to sign, with the position of one character in it and that character.
    private static (byte[] Buffer, int At, byte Original) SignedBuffer(bool withContext)
    {
        var buffer = Encoding.UTF8.GetBytes(withContext ? HostileJson.BaseDocument : ContextlessJson);
        var at = Array.LastIndexOf(buffer, (byte)(withContext ? '1' : 'e'));
        return (buffer, at, buffer[at]);
    }

    // Options with a note, and for a document without @context the fallback a suite that takes one needs.
    private DataIntegrityProof NoteOptions(bool documentHasContext) => documentHasContext
        ? WithNote()
        : WithNote() with { Context = TakesTheOptionsContext ? HostileJson.Parse(FallbackContext) : null };

    [Fact]
    public async Task VerifyProof_HashesTheCopyItTook()
    {
        // The checks and the hash read the one copy taken of the proof. The caller's extension dictionary answers its
        // second read with another value, so a suite that took the copy and then hashed the caller's proof would sign
        // over that value and fail (PR #62 review: removed in 8786435, it was the one row that caught this).
        var signed = await Suite.CreateProofAsync(Document(), WithNote(), Signer);
        var proof = signed with
        {
            AdditionalProperties = new ScriptedDictionary(
                [new(NoteName, signed.AdditionalProperties![NoteName])], count: 1,
                later: [new(NoteName, HostileJson.Parse("\"changed\""))]),
        };

        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyProof_TheResultHoldsTheProofAsVerified()
    {
        // The result carries the copy that was verified, so changing the caller's proof afterwards changes nothing in
        // it (PR #62 review).
        var signed = await Suite.CreateProofAsync(Document(), WithNote(), Signer);
        var proof = signed with { AdditionalProperties = new Dictionary<string, JsonElement>(signed.AdditionalProperties!) };

        var result = Suite.VerifyProof(Document(), proof, PublicKey);
        Tamper(proof);

        result.Verified.Should().BeTrue();
        var verified = result.Proof!;
        verified.Should().NotBeSameAs(proof);
        verified.Type.Should().Be(ProofType);
        verified.AdditionalProperties![NoteName].GetString().Should().Be("as signed");
        verified.AdditionalProperties.Should().NotContainKey("proofValue");
    }

    public static TheoryData<string> VerifyDisposedCases() =>
    [
        "document disposed before the call",
        "document disposed while it is copied",
        "document caught mid-dispose before the call",
        "document caught mid-dispose while it is copied",
        "document caught mid-dispose, and the copy throws",
        "proof @context disposed while it is copied",
        "proof extension value disposed while it is copied",
    ];

    [Theory]
    [MemberData(nameof(VerifyDisposedCases), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task VerifyProof_ADisposedInput_IsAFailedResult(string how)
    {
        // Verification never throws for its input (FR-3): a document or proof value disposed before or while the suite
        // copies it is a failed result, never one about whichever document rented its buffers (PR #62 review).
        var signed = await Suite.CreateProofAsync(Document(), WithNote(), Signer);
        var memory = new CallerMemory(how.StartsWith("document", StringComparison.Ordinal)
            ? HostileJson.BaseDocument
            : how.Contains("@context", StringComparison.Ordinal) ? FallbackContext : "\"as signed\"");
        var document = how.StartsWith("document", StringComparison.Ordinal) ? memory.Document.RootElement : Document();
        var proof = how switch
        {
            "proof @context disposed while it is copied" => signed with { Context = memory.Document.RootElement },
            "proof extension value disposed while it is copied" => signed with
            {
                AdditionalProperties = new Dictionary<string, JsonElement> { [NoteName] = memory.Document.RootElement },
            },
            _ => signed,
        };
        switch (how)
        {
            case "document disposed before the call":
                memory.Document.Dispose();
                break;
            case "document caught mid-dispose before the call":
                CallerMemory.MidDispose(memory.Document);
                break;
            case "document caught mid-dispose while it is copied":
                memory.OnNextRead(CallerMemory.MidDispose);
                break;
            case "document caught mid-dispose, and the copy throws":
                memory.OnNextRead(disposing =>
                {
                    CallerMemory.MidDispose(disposing);
                    throw new ArgumentOutOfRangeException("start");
                });
                break;
            default:
                memory.DisposeOnNextRead();
                break;
        }

        var result = Suite.VerifyProof(document, proof, PublicKey);

        result.Verified.Should().BeFalse();
        // A disposed proof value is the options copy's fault, reported by the copy as a ProofGenerationException.
        result.Problems.Should().ContainSingle().Which.Message.Should().Be(how.StartsWith("document", StringComparison.Ordinal)
            ? "Verification failed unexpectedly (ObjectDisposedException)."
            : "Verification failed unexpectedly (ProofGenerationException).");
    }

    [Theory]
    [MemberData(nameof(DirectAndThroughThePipeline), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task AnEmptyExtensionDictionaryFilledWhileTheSignerRuns_LeavesTheProofAsAskedFor(bool throughThePipeline)
    {
        // The copy rebuilds even an empty dictionary: one kept by reference carries what the signer adds into the
        // proof, a reserved name included (PR #62 review: no row started from an empty dictionary).
        var members = new Dictionary<string, JsonElement>();
        var signer = new MutatingSigner(Signer, () =>
        {
            members[NoteName] = HostileJson.Parse("\"added\"");
            members["proofValue"] = HostileJson.Parse("\"uFORGED\"");
        });

        var proof = await IssueAsync(Options() with { AdditionalProperties = members }, signer, throughThePipeline);

        (proof.AdditionalProperties ?? new Dictionary<string, JsonElement>()).Should().BeEmpty();
        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
    }

    private Task<DataIntegrityProof> IssueAsync(DataIntegrityProof options, ISigner signer, bool throughThePipeline)
        => IssueAsync(Document(), options, signer, throughThePipeline);

    private async Task<DataIntegrityProof> IssueAsync(
        JsonElement document, DataIntegrityProof options, ISigner signer, bool throughThePipeline)
    {
        if (!throughThePipeline)
        {
            return await Suite.CreateProofAsync(document, options, signer);
        }

        var pipeline = Pipeline();
        var secured = await pipeline.AddProofAsync(document, options, signer);
        pipeline.Verify(secured, PublicKey).Verified.Should().BeTrue();
        secured.GetProperty("proof").EnumerateObject().Count(member => member.Name == "proofValue").Should().Be(1);
        return secured.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
    }

    private Func<Task> CreateAsync(DataIntegrityProof options, bool throughThePipeline) => throughThePipeline
        ? () => Pipeline().AddProofAsync(Document(), options, Signer)
        : () => Suite.CreateProofAsync(Document(), options, Signer);

    /// <summary>
    /// A signer that runs <paramref name="during"/> before it signs, as a key store's await allows, and
    /// <paramref name="onKeyType"/>, if given, each time its <see cref="ISigner.KeyType"/> is read.
    /// </summary>
    private sealed class MutatingSigner(ISigner inner, Action during, Action? onKeyType = null) : ISigner
    {
        public KeyType KeyType
        {
            get
            {
                onKeyType?.Invoke();
                return inner.KeyType;
            }
        }

        public ReadOnlyMemory<byte> PublicKey => inner.PublicKey;

        public string MultibasePublicKey => inner.MultibasePublicKey;

        public async Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        {
            during();
            return await inner.SignAsync(data, ct);
        }
    }

    /// <summary>A signer whose <see cref="ISigner.KeyType"/> is the inner signer's on its first read and <paramref name="later"/> after.</summary>
    private sealed class ShiftingKeyTypeSigner(ISigner inner, KeyType later) : ISigner
    {
        private bool _read;

        public KeyType KeyType
        {
            get
            {
                var first = !_read;
                _read = true;
                return first ? inner.KeyType : later;
            }
        }

        public ReadOnlyMemory<byte> PublicKey => inner.PublicKey;

        public string MultibasePublicKey => inner.MultibasePublicKey;

        public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default) => inner.SignAsync(data, ct);
    }
}

/// <summary>
/// The caller's memory behind a <see cref="JsonDocument"/>, which runs the caller's code the next time it is read once
/// <see cref="OnNextRead"/> is called. A copy of an element reads the document's metadata first and its bytes last, so
/// code run then runs inside the copy, as a racing <c>Dispose</c> on another thread would (PR #62 review). The bytes
/// themselves stay intact, so only a check made after the copy can see what that code did.
/// </summary>
public sealed class CallerMemory : System.Buffers.MemoryManager<byte>
{
    private readonly byte[] _bytes;
    private Action<JsonDocument>? _next;

    public CallerMemory(string json)
    {
        _bytes = Encoding.UTF8.GetBytes(json);
        Document = JsonDocument.Parse(Memory);
    }

    /// <summary>The document parsed over this memory.</summary>
    public JsonDocument Document { get; }

    /// <summary>Runs <paramref name="code"/> with <see cref="Document"/> on the next read of this memory.</summary>
    public void OnNextRead(Action<JsonDocument> code) => _next = code;

    /// <summary>Disposes <see cref="Document"/> on the next read of this memory.</summary>
    public void DisposeOnNextRead() => OnNextRead(document => document.Dispose());

    /// <summary>
    /// Leaves <paramref name="document"/> as a <c>Dispose</c> racing on another thread can be seen to: its metadata
    /// gone, its bytes not yet. A read then throws <see cref="ArgumentOutOfRangeException"/>, not
    /// <see cref="ObjectDisposedException"/>. <c>JsonDocument.Dispose</c> in release/10.0 drops the metadata first;
    /// if these private fields are gone, the order the copy check relies on must be checked again.
    /// </summary>
    public static void MidDispose(JsonDocument document)
    {
        const System.Reflection.BindingFlags Private = System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance;
        var metadataField = typeof(JsonDocument).GetField("_parsedData", Private)
            ?? throw new InvalidOperationException("JsonDocument._parsedData is gone: check the order of JsonDocument.Dispose again.");
        var metadata = metadataField.GetValue(document)!;
        var dataField = metadata.GetType().GetField("_data", Private)
            ?? throw new InvalidOperationException("MetadataDb._data is gone: check the order of JsonDocument.Dispose again.");
        dataField.SetValue(metadata, null);
        metadataField.SetValue(document, metadata);
    }

    public override Span<byte> GetSpan()
    {
        var next = _next;
        _next = null;
        next?.Invoke(Document);
        return _bytes;
    }

    public override System.Buffers.MemoryHandle Pin(int elementIndex = 0) => throw new NotSupportedException();

    public override void Unpin()
    {
    }

    protected override void Dispose(bool disposing)
    {
    }
}

/// <summary>
/// A caller-made dictionary that yields <paramref name="members"/> as given, whatever they hold, and reports
/// <paramref name="count"/> as its <c>Count</c>. Given <paramref name="later"/>, it yields that on every read of its
/// contents after the first, enumeration and lookups alike. Given <paramref name="fault"/>, it throws that on any read.
/// Given <paramref name="onRead"/>, it runs that on every read first.
/// </summary>
public sealed class ScriptedDictionary(
    KeyValuePair<string, JsonElement>[] members,
    int count,
    KeyValuePair<string, JsonElement>[]? later = null,
    Exception? fault = null,
    Action? onRead = null) : IDictionary<string, JsonElement>
{
    private bool _read;

    public int Count => count;

    public bool IsReadOnly => true;

    public ICollection<string> Keys => Read().Select(member => member.Key).ToArray();

    public ICollection<JsonElement> Values => Read().Select(member => member.Value).ToArray();

    public JsonElement this[string key]
    {
        get => Read().First(member => member.Key == key).Value;
        set => throw new NotSupportedException();
    }

    private KeyValuePair<string, JsonElement>[] Read()
    {
        onRead?.Invoke();
        if (fault is not null)
        {
            throw fault;
        }

        var current = _read && later is not null ? later : members;
        _read = true;
        return current;
    }

    public IEnumerator<KeyValuePair<string, JsonElement>> GetEnumerator() => ((IEnumerable<KeyValuePair<string, JsonElement>>)Read()).GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public bool ContainsKey(string key) => Read().Any(member => member.Key == key);

    public bool TryGetValue(string key, [MaybeNullWhen(false)] out JsonElement value)
    {
        var found = Read().Where(member => member.Key == key).ToArray();
        value = found.Length > 0 ? found[0].Value : default;
        return found.Length > 0;
    }

    public bool Contains(KeyValuePair<string, JsonElement> item) => Read().Contains(item);

    public void CopyTo(KeyValuePair<string, JsonElement>[] array, int arrayIndex) => Read().CopyTo(array, arrayIndex);

    public void Add(string key, JsonElement value) => throw new NotSupportedException();

    public void Add(KeyValuePair<string, JsonElement> item) => throw new NotSupportedException();

    public bool Remove(string key) => throw new NotSupportedException();

    public bool Remove(KeyValuePair<string, JsonElement> item) => throw new NotSupportedException();

    public void Clear() => throw new NotSupportedException();
}

/// <summary>
/// A caller's collection of ids that keeps the array its <c>CopyTo</c> is handed. <c>Enumerable.ToArray</c> passes a
/// source that implements <see cref="ICollection{T}"/> the very array it returns, so a copy made that way alone is
/// one the caller can still write to (PR #62 review). It is an <see cref="IReadOnlyList{T}"/> too, the type the
/// bbs-2023 mandatory pointers are given as.
/// </summary>
public sealed class CapturingIds(params string[] ids) : IReadOnlyList<string>, ICollection<string>
{
    private string[]? _handed;

    /// <summary>Runs each time the collection is copied or enumerated, as any code of the caller's could.</summary>
    public Action? OnRead { get; init; }

    /// <summary>The <c>Count</c> the collection reports, if not its true one: a caller's collection can lie.</summary>
    public int? ReportedCount { get; init; }

    public int Count => ReportedCount ?? ids.Length;

    public bool IsReadOnly => true;

    public string this[int index] => ids[index];

    public void CopyTo(string[] array, int arrayIndex)
    {
        OnRead?.Invoke();
        _handed = array;
        ids.CopyTo(array, arrayIndex);
    }

    /// <summary>Writes <paramref name="value"/> at <paramref name="index"/> of the array <c>CopyTo</c> was last handed, if any.</summary>
    public void WriteToHandedArray(int index, string value)
    {
        if (_handed is { } handed)
        {
            handed[index] = value;
        }
    }

    /// <summary>Replaces every <paramref name="from"/> in the array <c>CopyTo</c> was last handed, if any, with <paramref name="to"/>.</summary>
    public void ReplaceInHandedArray(string from, string to)
    {
        if (_handed is { } handed)
        {
            for (var i = 0; i < handed.Length; i++)
            {
                if (handed[i] == from)
                {
                    handed[i] = to;
                }
            }
        }
    }

    public IEnumerator<string> GetEnumerator()
    {
        OnRead?.Invoke();
        return ((IEnumerable<string>)ids).GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    public bool Contains(string item) => Array.IndexOf(ids, item) >= 0;

    public void Add(string item) => throw new NotSupportedException();

    public bool Remove(string item) => throw new NotSupportedException();

    public void Clear() => throw new NotSupportedException();
}
