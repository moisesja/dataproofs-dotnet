using System.Collections;
using System.Diagnostics.CodeAnalysis;
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

    private PublicKeyMaterial PublicKey => PublicKeyMaterial.FromRaw(Signer.KeyType, Signer.PublicKey.Span);

    private static JsonElement Document() => HostileJson.Parse(HostileJson.BaseDocument);

    // No @context, so the proof configuration takes the options' own (the fallback the suites keep).
    private static JsonElement ContextlessDocument() => HostileJson.Parse(
        """{"@id": "urn:example:credential", "https://example.org/vocab#name": "Alice"}""");

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
        // the call: serializing the proof must not reach back into them.
        var expected = await Suite.CreateProofAsync(ContextlessDocument(), Options() with
        {
            Context = HostileJson.Parse(FallbackContext),
            AdditionalProperties = new Dictionary<string, JsonElement> { [NoteName] = HostileJson.Parse("\"kept\"") },
        }, Signer);

        DataIntegrityProof proof;
        using (var note = JsonDocument.Parse("\"kept\""))
        using (var context = JsonDocument.Parse(FallbackContext))
        {
            proof = await Suite.CreateProofAsync(ContextlessDocument(), Options() with
            {
                Context = context.RootElement,
                AdditionalProperties = new Dictionary<string, JsonElement> { [NoteName] = note.RootElement },
            }, Signer);
        }

        WithoutSignature(proof).Should().Be(WithoutSignature(expected));
    }

    /// <summary>
    /// Tries every public way a caller holding <paramref name="reference"/> might write to the ids it holds, and
    /// asserts that each one is refused. The wrapper first used for <see cref="PreviousProofReference.Values"/>,
    /// <c>ReadOnlyCollection&lt;string&gt;</c>, gave the array away through <c>ICollection.SyncRoot</c> (PR #62 review).
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

    public static TheoryData<bool> PreviousProofForms() => [false, true];

    [Theory]
    [MemberData(nameof(PreviousProofForms), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ACallerThatTriesToRewriteItsPreviousProof_LeavesTheProofAsIssued(bool arrayForm)
    {
        // The copy shares previousProof because nothing can change it: tried while the signer runs and after the call.
        DataIntegrityProof Chained() => Options() with
        {
            PreviousProof = arrayForm
                ? PreviousProofReference.FromValues(["urn:proof:original", "urn:proof:second"])
                : PreviousProofReference.FromSingle("urn:proof:original"),
        };
        var expected = await Suite.CreateProofAsync(Document(), Chained(), Signer);
        var options = Chained();

        var proof = await Suite.CreateProofAsync(
            Document(), options, new MutatingSigner(Signer, () => TryToRewrite(options.PreviousProof!)));
        TryToRewrite(options.PreviousProof!);

        WithoutSignature(proof).Should().Be(WithoutSignature(expected));
        proof.PreviousProof!.Values[0].Should().Be("urn:proof:original");
        proof.PreviousProof.IsArrayForm.Should().Be(arrayForm);
        Suite.VerifyProof(Document(), proof, PublicKey).Verified.Should().BeTrue();
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

    private Func<Task> CreateAsync(DataIntegrityProof options, bool throughThePipeline) => throughThePipeline
        ? () => Pipeline().AddProofAsync(Document(), options, Signer)
        : () => Suite.CreateProofAsync(Document(), options, Signer);

    /// <summary>
    /// A caller-made dictionary that enumerates <paramref name="members"/> as given, whatever they hold, and reports
    /// <paramref name="count"/> as its <c>Count</c>.
    /// </summary>
    private sealed class ScriptedDictionary(KeyValuePair<string, JsonElement>[] members, int count) : IDictionary<string, JsonElement>
    {
        public int Count => count;

        public bool IsReadOnly => true;

        public ICollection<string> Keys => members.Select(member => member.Key).ToArray();

        public ICollection<JsonElement> Values => members.Select(member => member.Value).ToArray();

        public JsonElement this[string key]
        {
            get => members.First(member => member.Key == key).Value;
            set => throw new NotSupportedException();
        }

        public IEnumerator<KeyValuePair<string, JsonElement>> GetEnumerator() => ((IEnumerable<KeyValuePair<string, JsonElement>>)members).GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public bool ContainsKey(string key) => members.Any(member => member.Key == key);

        public bool TryGetValue(string key, [MaybeNullWhen(false)] out JsonElement value)
        {
            var found = members.Where(member => member.Key == key).ToArray();
            value = found.Length > 0 ? found[0].Value : default;
            return found.Length > 0;
        }

        public bool Contains(KeyValuePair<string, JsonElement> item) => members.Contains(item);

        public void CopyTo(KeyValuePair<string, JsonElement>[] array, int arrayIndex) => members.CopyTo(array, arrayIndex);

        public void Add(string key, JsonElement value) => throw new NotSupportedException();

        public void Add(KeyValuePair<string, JsonElement> item) => throw new NotSupportedException();

        public bool Remove(string key) => throw new NotSupportedException();

        public bool Remove(KeyValuePair<string, JsonElement> item) => throw new NotSupportedException();

        public void Clear() => throw new NotSupportedException();
    }

    /// <summary>A signer that runs <paramref name="during"/> before it signs, as a key store's await allows.</summary>
    private sealed class MutatingSigner(ISigner inner, Action during) : ISigner
    {
        public KeyType KeyType => inner.KeyType;

        public ReadOnlyMemory<byte> PublicKey => inner.PublicKey;

        public string MultibasePublicKey => inner.MultibasePublicKey;

        public async Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        {
            during();
            return await inner.SignAsync(data, ct);
        }
    }
}
