using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using DataProofsDotnet.Rdfc.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// Issue #44: a <c>bbs-2023</c> base proof created with a BLS12-381-G2 key held in an
/// <see cref="ICapableKeyStore"/> (<see cref="Bbs2023Cryptosuite.CreateBaseProofWithKeyStoreAsync"/>).
/// It equals the raw-key base proof for the same key and inputs, derives and verifies the same way,
/// touches only the store's info and BBS-signing members (AC-8), refuses a store that answers
/// wrongly, and takes no private-key bytes.
/// </summary>
public sealed class Bbs2023KeyStoreTests
{
    private const string Alias = "bbs-issuer";

    private static (byte[] Sk, byte[] HmacKey) KeyMaterial()
    {
        var keyMat = Fx.Json("w3c", "vc-di-bbs", "TestVectors", "BBSKeyMaterial.json");
        return (
            Convert.FromHexString(keyMat.GetProperty("privateKeyHex").GetString()!),
            Convert.FromHexString(keyMat.GetProperty("hmacKeyString").GetString()!));
    }

    private static JsonElement WindDoc() => Fx.Json("w3c", "vc-di-bbs", "TestVectors", "windDoc.json");

    private static string[] WindMandatory()
        => JsonSerializer.Deserialize<string[]>(Fx.Text("w3c", "vc-di-bbs", "TestVectors", "windMandatory.json"))!;

    private static DataIntegrityProof BaseOptions() => new()
    {
        Type = DataIntegrityProof.DataIntegrityProofType,
        Cryptosuite = Bbs2023Cryptosuite.CryptosuiteName,
        Created = "2023-08-15T23:36:38Z",
        VerificationMethod = "did:key:zUC7Derd#zUC7Derd",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    // The vector's private key imported into a recording store; setup calls are cleared.
    private static async Task<(RecordingCapableKeyStore Store, StoredKeyInfo Info)> StoreWithVectorKeyAsync()
    {
        var (sk, _) = KeyMaterial();
        var store = RecordingCapableKeyStore.WithBbs();
        var info = await store.ImportAsync(Alias, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk));
        store.ClearCalls();
        return (store, info);
    }

    private static JsonElement Parse(string json) => JsonSerializer.Deserialize<JsonElement>(json);

    private static JsonElement Embed(JsonElement document, DataIntegrityProof proof)
    {
        var secured = JsonObject.Create(document)!;
        secured["proof"] = JsonSerializer.SerializeToNode(proof, DataProofsJsonOptions.Default);
        return JsonSerializer.SerializeToElement(secured, DataProofsJsonOptions.Default);
    }

    private static ProofVerificationResult VerifyReveal(Bbs2023Cryptosuite suite, JsonElement reveal, PublicKeyMaterial pk)
    {
        var derivedProof = reveal.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
        var unsecured = JsonObject.Create(reveal)!;
        unsecured.Remove("proof");
        return suite.VerifyProof(JsonSerializer.SerializeToElement(unsecured, DataProofsJsonOptions.Default), derivedProof, pk);
    }

    public static TheoryData<string[]> MandatoryPointerSets() => new()
    {
        WindMandatory(),
        Array.Empty<string>(),
        new[] { "/issuer" },
    };

    [BbsTheory]
    [MemberData(nameof(MandatoryPointerSets))]
    public async Task KeyStoreBaseProof_EqualsTheRawKeyBaseProof(string[] mandatory)
    {
        var (sk, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var suite = new Bbs2023Cryptosuite();

        var raw = await suite.CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, mandatory);
        var stored = await suite.CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, mandatory);

        // BBS signing is deterministic, so the whole proof, proofValue included, is the same.
        stored.ProofValue.Should().StartWith("u2V0C").And.Be(raw.ProofValue);
        JsonSerializer.Serialize(stored, DataProofsJsonOptions.Default)
            .Should().Be(JsonSerializer.Serialize(raw, DataProofsJsonOptions.Default));
    }

    [BbsTheory]
    [MemberData(nameof(Bbs2023LifecycleTests.SelectivePointerSets), MemberType = typeof(Bbs2023LifecycleTests))]
    public async Task KeyStoreBaseProof_DerivesAndVerifies(string[] selective)
    {
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var suite = new Bbs2023Cryptosuite();
        var publicKey = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, info.PublicKey);

        var baseProof = await suite.CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());
        var reveal = suite.DeriveProof(Embed(WindDoc(), baseProof), selective, Convert.FromHexString("113377aa"));

        VerifyReveal(suite, reveal, publicKey).Verified.Should().BeTrue();
        new DataIntegrityProofPipeline(CryptosuiteRegistry.CreateDefault().AddBbs2023())
            .Verify(reveal, publicKey).Verified.Should().BeTrue();

        // The mandatory binding holds: a mandatory value changed in the reveal fails.
        var tampered = Fx.Mutate(reveal, document => document["issuer"] = "https://evil.example/");
        VerifyReveal(suite, tampered, publicKey).Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task ProducingABaseProof_TouchesOnlyTheStoresInfoAndBbsSigningMembers()
    {
        // AC-8 for bbs-2023: no other member, no plain IKeyStore member, no export path.
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();

        await new Bbs2023Cryptosuite().CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());

        store.Calls.Should().Equal("GetInfoAsync(alias, instanceId)", nameof(ICapableKeyStore.SignBbsAsync));
        store.LastBbsRequest!.Alias.Should().Be(Alias);
        store.LastBbsRequest.InstanceId.Should().Be(info.InstanceId.Value);
        store.LastBbsRequest.Algorithm.Should().Be(KeyStoreAlgorithms.BbsBls12381Sha256);
    }

    [BbsFact]
    public async Task TheCancellationToken_ReachesBothStoreCalls()
    {
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        using var cts = new CancellationTokenSource();

        await new Bbs2023Cryptosuite().CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory(), cts.Token);

        store.Tokens.Should().HaveCount(2).And.OnlyContain(token => token == cts.Token);
    }

    [BbsFact]
    public async Task ACanceledToken_FailsBeforeTheStoreIsCalled()
    {
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory(), new CancellationToken(canceled: true));

        await act.Should().ThrowAsync<OperationCanceledException>();
        store.Calls.Should().BeEmpty();
    }

    [BbsFact]
    public async Task AStaleInstanceId_IsRefusedWithoutSigning()
    {
        // The alias now holds a different key instance: the request must not sign under it.
        var (sk, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        await store.DeleteAsync(Alias);
        var reimported = await store.ImportAsync(Alias, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk));
        reimported.InstanceId.Should().NotBe(info.InstanceId);
        store.ClearCalls();

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());

        await act.Should().ThrowAsync<KeyNotFoundException>();
        store.Calls.Should().NotContain(nameof(ICapableKeyStore.SignBbsAsync));
    }

    [BbsFact]
    public async Task AKeyThatIsNotBls12381G2_IsRefusedWithoutSigning()
    {
        var (_, hmacKey) = KeyMaterial();
        using var store = RecordingCapableKeyStore.WithBbs();
        var info = await store.ImportAsync(Alias, Fx.KeyGen.Generate(KeyType.Ed25519));
        store.ClearCalls();

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());

        (await act.Should().ThrowAsync<ProofGenerationException>()).WithMessage("*type Ed25519*BLS12-381-G2*");
        store.Calls.Should().NotContain(nameof(ICapableKeyStore.SignBbsAsync));
    }

    [BbsFact]
    public async Task AStoreWithoutBbsSigning_ReportsUnsupported()
    {
        var (sk, hmacKey) = KeyMaterial();
        using var store = new RecordingCapableKeyStore(new CapableInMemoryKeyStore(Fx.KeyGen, Fx.Crypto, bbsProvider: null));
        var info = await store.ImportAsync(Alias, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk));

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());

        (await act.Should().ThrowAsync<KeyStoreException>()).Which.Error.Should().Be(KeyStoreError.Unsupported);
    }

    // What a misbehaving store could answer instead of the genuine signature.
    public static TheoryData<string> WrongSignatures() => new()
    {
        "another key's signature over the same messages and header",
        "the right key over the messages in another order",
        "the right key over the messages with no header",
        "one byte flipped",
        "one byte short",
        "one byte long",
        "empty",
        "null",
        "80 zero bytes",
    };

    private static byte[] WrongSignature(string kind, KeyBbsSignRequest request, byte[] genuine)
    {
        var bbs = new DefaultBbsCryptoProvider(BbsCiphersuite.Bls12381Sha256);
        var (sk, _) = KeyMaterial();
        var messages = request.Messages.Select(message => message.ToArray()).ToList();
        var header = request.Header.ToArray();
        switch (kind)
        {
            case "another key's signature over the same messages and header":
                return bbs.Sign(Fx.KeyGen.Generate(KeyType.Bls12381G2).PrivateKey, messages, header);
            case "the right key over the messages in another order":
                messages.Reverse();
                return bbs.Sign(sk, messages, header);
            case "the right key over the messages with no header":
                return bbs.Sign(sk, messages, ReadOnlySpan<byte>.Empty);
            case "one byte flipped":
                var flipped = genuine.ToArray();
                flipped[^1] ^= 0x01;
                return flipped;
            case "one byte short":
                return genuine[..^1];
            case "one byte long":
                return [.. genuine, 0x00];
            case "empty":
                return [];
            case "null":
                return null!;
            case "80 zero bytes":
                return new byte[80];
            default:
                throw new ArgumentOutOfRangeException(nameof(kind));
        }
    }

    [BbsTheory]
    [MemberData(nameof(WrongSignatures))]
    public async Task AStoreThatAnswersWithAWrongSignature_IssuesNoProof(string kind)
    {
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        store.TamperSignature = (request, genuine) => WrongSignature(kind, request, genuine);

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());

        (await act.Should().ThrowAsync<ProofGenerationException>()).WithMessage("*does not verify*");
    }

    [BbsFact]
    public async Task ACallerThatChangesItsBuffersWhileTheStoreSigns_StillGetsTheProofItAskedFor()
    {
        // The store call is awaited; the HMAC key and the pointers are packed into the proof after it.
        var (sk, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var suite = new Bbs2023Cryptosuite();
        var expected = await suite.CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, WindMandatory());

        var callerHmac = hmacKey.ToArray();
        var callerPointers = WindMandatory().ToList();
        store.TamperSignature = (_, genuine) =>
        {
            callerHmac.AsSpan().Fill(0xAA);
            callerPointers.Clear();
            return genuine;
        };

        var stored = await suite.CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, callerHmac, callerPointers);

        stored.ProofValue.Should().Be(expected.ProofValue);
    }

    [BbsFact]
    public async Task TheStoreIsHandedCopies_SoItCannotChangeWhatTheSignatureIsCheckedAgainst()
    {
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var bbs = new DefaultBbsCryptoProvider(BbsCiphersuite.Bls12381Sha256);
        var (sk, _) = KeyMaterial();

        // A store that rewrites the buffers it was handed and signs what it rewrote: the check runs
        // over the messages the suite computed, so the signature fails it.
        store.TamperSignature = (request, _) =>
        {
            var first = System.Runtime.InteropServices.MemoryMarshal.AsMemory(request.Messages[0]);
            first.Span[0] ^= 0x01;
            return bbs.Sign(sk, request.Messages.Select(message => message.ToArray()).ToList(), request.Header.Span);
        };

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());

        (await act.Should().ThrowAsync<ProofGenerationException>()).WithMessage("*does not verify*");
    }

    // Inputs the suite refuses before it calls the store: the argument checks, and those that need the
    // document transformed (adversarial review: these used to run after the public key was read).
    public static TheoryData<string> InvalidRequests() => new()
    {
        "proof type",
        "cryptosuite",
        "proofValue in options",
        "no proofPurpose",
        "no verificationMethod",
        "HMAC key of 31 bytes",
        "document is an array",
        "duplicate member in document",
        "malformed pointer",
        "null pointer",
        "pointer matches nothing",
        "pointer selects part of a value",
        "every statement mandatory",
        "nested @context in document",
        "urn:bnid: IRI in document",
        "extension member named proofValue",
        "extension member with a duplicate member name",
        "options @context with a duplicate member, no document @context",
    };

    [BbsTheory]
    [MemberData(nameof(InvalidRequests))]
    public async Task AnInvalidRequest_IsRefusedBeforeTheStoreIsCalled(string kind)
    {
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var document = WindDoc();
        var options = BaseOptions();
        var mandatory = WindMandatory();

        switch (kind)
        {
            case "proof type": options = options with { Type = "Ed25519Signature2020" }; break;
            case "cryptosuite": options = options with { Cryptosuite = "eddsa-rdfc-2022" }; break;
            case "proofValue in options": options = options with { ProofValue = "u2V0C" }; break;
            case "no proofPurpose": options = options with { ProofPurpose = null! }; break;
            case "no verificationMethod": options = options with { VerificationMethod = null! }; break;
            case "HMAC key of 31 bytes": hmacKey = hmacKey[..31]; break;
            case "document is an array": document = JsonSerializer.Deserialize<JsonElement>("[]"); break;
            case "duplicate member in document":
                document = JsonSerializer.Deserialize<JsonElement>("""{"@context": "https://www.w3.org/ns/credentials/v2", "a": 1, "a": 2}""");
                break;
            case "malformed pointer": mandatory = ["issuer"]; break;
            case "null pointer": mandatory = [null!]; break;
            case "pointer matches nothing": mandatory = ["/no-such-member"]; break;
            case "pointer selects part of a value":
                document = Fx.Mutate(document, d => d["credentialSubject"]!.AsObject()["name"] = JsonNode.Parse("""{"@value": "Alice", "@language": "en"}"""));
                mandatory = ["/credentialSubject/name/@language"];
                break;
            case "every statement mandatory": mandatory = [""]; break;
            case "nested @context in document":
                document = Fx.Mutate(document, d => d["credentialSubject"]!.AsObject()["@context"] = JsonNode.Parse("""{"x": "https://x.example/"}"""));
                break;
            case "urn:bnid: IRI in document": document = Fx.Mutate(document, d => d["id"] = "urn:bnid:_:b0"); break;
            case "extension member named proofValue":
                options.AdditionalProperties = new Dictionary<string, JsonElement> { ["proofValue"] = Parse("\"x\"") };
                break;
            case "extension member with a duplicate member name":
                options.AdditionalProperties = new Dictionary<string, JsonElement> { ["ext"] = Parse("""{"a": 1, "a": 2}""") };
                break;
            case "options @context with a duplicate member, no document @context":
                document = Fx.Mutate(document, d => d.Remove("@context"));
                options = options with { Context = Parse("""{"@vocab": "https://a.example/", "@vocab": "https://b.example/"}""") };
                break;
        }

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofWithKeyStoreAsync(
            document, options, store, Alias, info.InstanceId!.Value, hmacKey, mandatory);

        await act.Should().ThrowAsync<ProofGenerationException>();
        store.Calls.Should().BeEmpty();
    }

    [BbsFact]
    public async Task AnInputFault_IsReportedBeforeAStoreFault()
    {
        // A pointer that matches nothing and an instance id the store does not hold: the input fault wins.
        var (_, hmacKey) = KeyMaterial();
        var (store, _) = await StoreWithVectorKeyAsync();

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, new KeyInstanceId("not-the-instance"), hmacKey, ["/no-such-member"]);

        await act.Should().ThrowAsync<ProofGenerationException>();
        store.Calls.Should().BeEmpty();
    }

    [BbsFact]
    public async Task ACallerThatChangesItsProofOptionsWhileTheStoreSigns_StillGetsTheProofItAskedFor()
    {
        // Type and AdditionalProperties are settable; the proof carries the options that were checked and signed.
        var (sk, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var suite = new Bbs2023Cryptosuite();
        DataIntegrityProof WithNote() => BaseOptions() with
        {
            AdditionalProperties = new Dictionary<string, JsonElement> { ["note"] = Parse("\"as signed\"") },
        };
        var expected = await suite.CreateBaseProofAsync(WindDoc(), WithNote(), sk, hmacKey, WindMandatory());

        var options = WithNote();
        store.TamperSignature = (_, genuine) =>
        {
            options.Type = "Ed25519Signature2020";
            options.AdditionalProperties!["note"] = Parse("\"changed later\"");
            options.AdditionalProperties["proofValue"] = Parse("\"uFORGED\"");
            return genuine;
        };

        var stored = await suite.CreateBaseProofWithKeyStoreAsync(
            WindDoc(), options, store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());

        JsonSerializer.Serialize(stored, DataProofsJsonOptions.Default)
            .Should().Be(JsonSerializer.Serialize(expected, DataProofsJsonOptions.Default));
        var reveal = suite.DeriveProof(Embed(WindDoc(), stored), ["/credentialSubject/sails/0"], Convert.FromHexString("113377aa"));
        VerifyReveal(suite, reveal, PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, info.PublicKey)).Verified.Should().BeTrue();
    }

    [BbsFact]
    public async Task TheReturnedProof_DoesNotShareTheCallersExtensionMembers()
    {
        // Both methods: changing the options after the call leaves the issued proof as it was.
        var (sk, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var suite = new Bbs2023Cryptosuite();
        var options = BaseOptions() with
        {
            AdditionalProperties = new Dictionary<string, JsonElement> { ["note"] = Parse("\"x\"") },
        };

        var raw = await suite.CreateBaseProofAsync(WindDoc(), options, sk, hmacKey, WindMandatory());
        var stored = await suite.CreateBaseProofWithKeyStoreAsync(
            WindDoc(), options, store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());
        options.AdditionalProperties["note"] = Parse("\"changed\"");

        raw.AdditionalProperties!["note"].GetString().Should().Be("x");
        stored.AdditionalProperties!["note"].GetString().Should().Be("x");
    }

    [BbsFact]
    public async Task TheStoreSeesTheNonMandatoryStatements_ButNotTheMandatoryOnesNorTheHmacKey()
    {
        // What the XML docs say a remote key service learns: BBS signs the messages, not a hash of them.
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();

        await new Bbs2023Cryptosuite().CreateBaseProofWithKeyStoreAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());

        var request = store.LastBbsRequest!;
        var bytes = request.Messages.SelectMany(message => message.ToArray()).Concat(request.Header.ToArray()).ToArray();
        bytes.AsSpan().IndexOf(hmacKey).Should().Be(-1);
        var text = string.Concat(request.Messages.Select(message => System.Text.Encoding.UTF8.GetString(message.Span)));
        text.Should().Contain("Kihei", "a non-mandatory claim reaches the store in the clear");
        text.Should().NotContain("racecommittee", "the mandatory issuer statement reaches it only hashed, in the header");
        request.Header.Length.Should().Be(64);
    }

    [BbsFact]
    public async Task MissingStoreArguments_AreArgumentFaults()
    {
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var suite = new Bbs2023Cryptosuite();
        var id = info.InstanceId!.Value;

        await suite.Invoking(s => s.CreateBaseProofWithKeyStoreAsync(WindDoc(), BaseOptions(), null!, Alias, id, hmacKey, WindMandatory()))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("keyStore");
        await suite.Invoking(s => s.CreateBaseProofWithKeyStoreAsync(WindDoc(), BaseOptions(), store, null!, id, hmacKey, WindMandatory()))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("alias");
        await suite.Invoking(s => s.CreateBaseProofWithKeyStoreAsync(WindDoc(), BaseOptions(), store, "", id, hmacKey, WindMandatory()))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("alias");
        await suite.Invoking(s => s.CreateBaseProofWithKeyStoreAsync(WindDoc(), BaseOptions(), store, Alias, default, hmacKey, WindMandatory()))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("instanceId");
        await suite.Invoking(s => s.CreateBaseProofWithKeyStoreAsync(WindDoc(), null!, store, Alias, id, hmacKey, WindMandatory()))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("proofOptions");
        await suite.Invoking(s => s.CreateBaseProofWithKeyStoreAsync(WindDoc(), BaseOptions(), store, Alias, id, hmacKey, null!))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("mandatoryPointers");

        store.Calls.Should().BeEmpty();
    }

    [Fact]
    [Trait("Category", "BbsAbsent")]
    public void TheKeyStorePath_TakesNoPrivateKeyBytes()
    {
        // The issue's "no API on that path accepts private-key bytes": the only byte parameter is the
        // HMAC key, which the holder receives inside the base proof.
        var method = typeof(Bbs2023Cryptosuite).GetMethod(nameof(Bbs2023Cryptosuite.CreateBaseProofWithKeyStoreAsync))!;
        var parameters = method.GetParameters();

        parameters.Select(p => p.ParameterType).Should().Contain(typeof(ICapableKeyStore));
        parameters.Where(p => IsBytes(p.ParameterType)).Select(p => p.Name).Should().Equal("hmacKey");

        static bool IsBytes(Type type)
            => type == typeof(byte[]) || type == typeof(ReadOnlyMemory<byte>) || type == typeof(Memory<byte>)
                || type == typeof(IEnumerable<byte>) || type == typeof(IReadOnlyList<byte>);
    }
}
