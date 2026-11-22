using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using DataProofsDotnet.Rdfc.Internal;
using DataProofsDotnet.Rdfc.Tests.TestSupport;
using DataProofsDotnet.Tests.Shared;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// Issue #44: a <c>bbs-2023</c> base proof created with a BLS12-381-G2 key held in an
/// <see cref="ICapableKeyStore"/> (the <c>Bbs2023Cryptosuite.CreateBaseProofAsync</c> overload that takes one).
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
        var stored = await suite.CreateBaseProofAsync(
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

        var baseProof = await suite.CreateBaseProofAsync(
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

        await new Bbs2023Cryptosuite().CreateBaseProofAsync(
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

        await new Bbs2023Cryptosuite().CreateBaseProofAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory(), cts.Token);

        store.Tokens.Should().HaveCount(2).And.OnlyContain(token => token == cts.Token);
    }

    [BbsFact]
    public async Task ACanceledToken_FailsBeforeTheStoreIsCalled()
    {
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(
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

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(
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

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(
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

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(
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

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());

        (await act.Should().ThrowAsync<ProofGenerationException>()).WithMessage("*does not verify*");
    }

    // What a misbehaving store could report as the key's public key, and the message each must give.
    public static TheoryData<string, string> WrongPublicKeys() => new()
    {
        { "95 bytes", "*public key of 95 bytes, not 96*" },
        { "192 bytes", "*public key of 192 bytes, not 96*" },
        { "the G2 identity point", "*does not verify*" },
        { "96 zero bytes", "*does not verify*" },
        { "96 random bytes", "*does not verify*" },
        { "another key's valid public key", "*does not verify*" },
    };

    private static byte[] WrongPublicKey(string kind) => kind switch
    {
        "95 bytes" => new byte[95],
        "192 bytes" => new byte[192],
        "the G2 identity point" => [0xC0, .. new byte[95]],
        "96 zero bytes" => new byte[96],
        "96 random bytes" => System.Security.Cryptography.RandomNumberGenerator.GetBytes(96),
        "another key's valid public key" => Fx.KeyGen.Generate(KeyType.Bls12381G2).PublicKey,
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    [BbsTheory]
    [MemberData(nameof(WrongPublicKeys))]
    public async Task AStoreThatReportsAWrongPublicKey_IssuesNoProof(string kind, string message)
    {
        // A key that fails to decode must surface as the documented exception, not the provider's own.
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        store.TamperInfo = genuine => genuine with { PublicKey = WrongPublicKey(kind) };

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());

        (await act.Should().ThrowExactlyAsync<ProofGenerationException>()).WithMessage(message);
    }

    [Fact]
    [Trait("Category", "BbsAbsent")]
    public async Task WithoutTheBbsLibrary_TheInputIsCheckedAndThenBbsUnavailable_BeforeAnyStoreCall()
    {
        // The store is never asked to sign what this host could not check (AC-6).
        var (_, hmacKey) = KeyMaterial();
        var store = new RecordingCapableKeyStore(new CapableInMemoryKeyStore(Fx.KeyGen, Fx.Crypto, bbsProvider: null));
        var suite = new Bbs2023Cryptosuite(canonicalizer: null, new UnavailableBbs());
        var instance = new KeyInstanceId("any-instance");

        var invalid = () => suite.CreateBaseProofAsync(
            WindDoc(), BaseOptions() with { ProofPurpose = null! }, store, Alias, instance, hmacKey, WindMandatory());
        await invalid.Should().ThrowAsync<ProofGenerationException>();

        var valid = () => suite.CreateBaseProofAsync(
            WindDoc(), BaseOptions(), store, Alias, instance, hmacKey, WindMandatory());
        await valid.Should().ThrowAsync<BbsUnavailableException>();

        store.Calls.Should().BeEmpty();
    }

    public static TheoryData<string> VerifyFaults() => new() { "argument", "cryptographic", "unavailable" };

    [BbsTheory]
    [MemberData(nameof(VerifyFaults))]
    public async Task ASignatureCheckThatFaults_IsTheDocumentedException(string fault)
    {
        // NetCrypto's Verify returns false for every 96-byte key and 80-byte signature tried here, so a
        // provider that throws stands in for a key or signature it refuses to decode. A missing library
        // stays BbsUnavailableException.
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        Exception toThrow = fault switch
        {
            "argument" => new ArgumentException("not a point"),
            "cryptographic" => new System.Security.Cryptography.CryptographicException("not a point"),
            _ => new BbsUnavailableException("absent"),
        };
        var suite = new Bbs2023Cryptosuite(canonicalizer: null, new FaultingVerifyBbs(toThrow));

        var act = () => suite.CreateBaseProofAsync(
            WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());

        if (fault == "unavailable")
        {
            await act.Should().ThrowExactlyAsync<BbsUnavailableException>();
        }
        else
        {
            (await act.Should().ThrowExactlyAsync<ProofGenerationException>()).WithMessage("*does not verify*");
        }
    }

    private sealed class FaultingVerifyBbs(Exception toThrow) : IBbsCryptoProvider
    {
        public BbsCiphersuite Ciphersuite => BbsCiphersuite.Bls12381Sha256;

        public bool IsAvailable => true;

        public byte[] Sign(ReadOnlySpan<byte> privateKey, IReadOnlyList<byte[]> messages, ReadOnlySpan<byte> header = default)
            => throw new NotSupportedException();

        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature, IReadOnlyList<byte[]> messages, ReadOnlySpan<byte> header = default)
            => throw toThrow;

        public byte[] DeriveProof(ReadOnlySpan<byte> publicKey, byte[] signature, IReadOnlyList<byte[]> messages,
            IReadOnlyList<int> revealedIndices, ReadOnlySpan<byte> presentationHeader = default, ReadOnlySpan<byte> header = default)
            => throw new NotSupportedException();

        public bool VerifyProof(ReadOnlySpan<byte> publicKey, byte[] proof, IReadOnlyList<byte[]> revealedMessages,
            IReadOnlyList<int> revealedIndices, ReadOnlySpan<byte> presentationHeader = default, ReadOnlySpan<byte> header = default)
            => throw new NotSupportedException();
    }

    private sealed class UnavailableBbs : IBbsCryptoProvider
    {
        public BbsCiphersuite Ciphersuite => BbsCiphersuite.Bls12381Sha256;

        public bool IsAvailable => false;

        public byte[] Sign(ReadOnlySpan<byte> privateKey, IReadOnlyList<byte[]> messages, ReadOnlySpan<byte> header = default)
            => throw new BbsUnavailableException("absent");

        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signature, IReadOnlyList<byte[]> messages, ReadOnlySpan<byte> header = default)
            => throw new BbsUnavailableException("absent");

        public byte[] DeriveProof(ReadOnlySpan<byte> publicKey, byte[] signature, IReadOnlyList<byte[]> messages,
            IReadOnlyList<int> revealedIndices, ReadOnlySpan<byte> presentationHeader = default, ReadOnlySpan<byte> header = default)
            => throw new BbsUnavailableException("absent");

        public bool VerifyProof(ReadOnlySpan<byte> publicKey, byte[] proof, IReadOnlyList<byte[]> revealedMessages,
            IReadOnlyList<int> revealedIndices, ReadOnlySpan<byte> presentationHeader = default, ReadOnlySpan<byte> header = default)
            => throw new BbsUnavailableException("absent");
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

        var stored = await suite.CreateBaseProofAsync(
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

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(
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

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(
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

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(
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

        var stored = await suite.CreateBaseProofAsync(
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
        var stored = await suite.CreateBaseProofAsync(
            WindDoc(), options, store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());
        options.AdditionalProperties["note"] = Parse("\"changed\"");

        raw.AdditionalProperties!["note"].GetString().Should().Be("x");
        stored.AdditionalProperties!["note"].GetString().Should().Be("x");
    }

    // Both overloads, one call: the raw key's, or the key store's.
    private static Func<Task<DataIntegrityProof>> Issue(
        bool keyStore, DataIntegrityProof options, RecordingCapableKeyStore store, StoredKeyInfo info,
        IReadOnlyList<string>? mandatory = null, JsonElement? document = null)
    {
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        mandatory ??= WindMandatory();
        var unsecured = document ?? WindDoc();
        return keyStore
            ? () => suite.CreateBaseProofAsync(unsecured, options, store, Alias, info.InstanceId!.Value, hmacKey, mandatory)
            : () => suite.CreateBaseProofAsync(unsecured, options, sk, hmacKey, mandatory);
    }

    [BbsTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ADocumentDisposedBeforeTheCall_IsAProofGenerationException_BeforeTheStoreIsCalled(bool keyStore)
    {
        // Both overloads copy the document at entry, as every create entry point does (PR #62). Reading it raised the
        // raw ObjectDisposedException.
        var (store, info) = await StoreWithVectorKeyAsync();
        JsonElement disposed;
        using (var source = JsonDocument.Parse(WindDoc().GetRawText()))
        {
            disposed = source.RootElement;
        }

        var thrown = await Issue(keyStore, BaseOptions(), store, info, document: disposed)
            .Should().ThrowAsync<ProofGenerationException>().WithMessage("The document to secure has been disposed.");

        thrown.WithInnerException<ObjectDisposedException>();
        store.Calls.Should().BeEmpty();
    }

    [BbsTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MandatoryPointersWhoseCopyChangesTheOptions_StillGetTheProofThatWasAskedFor(bool keyStore)
    {
        // The pointers are the caller's code too, and the suite reads them after it checks the options, so the
        // options must be copied before the checks (PR #62 review: a copy moved below them survived on bbs-2023).
        var (store, info) = await StoreWithVectorKeyAsync();
        DataIntegrityProof WithNote() => BaseOptions() with
        {
            AdditionalProperties = new Dictionary<string, JsonElement> { ["note"] = Parse("\"as signed\"") },
        };
        var expected = await Issue(false, WithNote(), store, info)();
        var options = WithNote();
        var pointers = new CapturingIds(WindMandatory())
        {
            OnRead = () =>
            {
                options.Type = "Ed25519Signature2020";
                options.AdditionalProperties!["note"] = Parse("\"changed\"");
                options.AdditionalProperties["proofValue"] = Parse("\"uFORGED\"");
            },
        };

        var proof = await Issue(keyStore, options, store, info, pointers)();

        JsonSerializer.Serialize(proof, DataProofsJsonOptions.Default)
            .Should().Be(JsonSerializer.Serialize(expected, DataProofsJsonOptions.Default));
        var suite = new Bbs2023Cryptosuite();
        var reveal = suite.DeriveProof(Embed(WindDoc(), proof), ["/credentialSubject/sails/0"], Convert.FromHexString("113377aa"));
        VerifyReveal(suite, reveal, PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, info.PublicKey)).Verified.Should().BeTrue();
    }

    public static TheoryData<string, bool> OptionsCopyFaults() => new()
    {
        { "disposed value", false }, { "disposed value", true },
        { "null name", false }, { "null name", true },
        { "repeated name", false }, { "repeated name", true },
    };

    [BbsTheory]
    [MemberData(nameof(OptionsCopyFaults))]
    public async Task AFaultTheOptionsCopyFinds_IsAProofGenerationException_BeforeTheStoreIsCalled(string fault, bool keyStore)
    {
        // The three faults the shared copy reports (issue #61), on both overloads (PR #62 review: none had a test here).
        var (store, info) = await StoreWithVectorKeyAsync();
        JsonElement disposed;
        using (var source = JsonDocument.Parse("\"x\""))
        {
            disposed = source.RootElement;
        }

        var value = Parse("\"x\"");
        IDictionary<string, JsonElement> members = fault switch
        {
            "disposed value" => new Dictionary<string, JsonElement> { ["note"] = disposed },
            "null name" => new ScriptedDictionary([new(null!, value)], count: 1),
            _ => new ScriptedDictionary([new("note", value), new("note", value)], count: 2),
        };

        var thrown = await Issue(keyStore, BaseOptions() with { AdditionalProperties = members }, store, info)
            .Should().ThrowAsync<ProofGenerationException>();

        thrown.Which.Message.Should().Be(fault switch
        {
            "disposed value" => "The proof options hold a JSON value whose document has been disposed.",
            "null name" => "The proof options have an extension member with a null name.",
            _ => "The proof options repeat an extension member name.",
        });
        store.Calls.Should().BeEmpty();
    }

    [BbsTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ExtensionMembersThatChangeBetweenReads_AreReadOnce(bool keyStore)
    {
        // The copy is the one read of the caller's dictionary, so the checks and the proof see the same members
        // (PR #62 review: the copy moved below the checks survived on bbs-2023).
        var (store, info) = await StoreWithVectorKeyAsync();
        var expected = await Issue(
            false, BaseOptions() with { AdditionalProperties = new Dictionary<string, JsonElement> { ["note"] = Parse("\"as signed\"") } },
            store, info)();
        var options = BaseOptions() with
        {
            AdditionalProperties = new ScriptedDictionary(
                [new("note", Parse("\"as signed\""))],
                count: 1,
                later: [new("note", Parse("\"changed\"")), new("proofValue", Parse("\"uFORGED\""))]),
        };

        var proof = await Issue(keyStore, options, store, info)();

        JsonSerializer.Serialize(proof, DataProofsJsonOptions.Default)
            .Should().Be(JsonSerializer.Serialize(expected, DataProofsJsonOptions.Default));
        var suite = new Bbs2023Cryptosuite();
        var reveal = suite.DeriveProof(Embed(WindDoc(), proof), ["/credentialSubject/sails/0"], Convert.FromHexString("113377aa"));
        VerifyReveal(suite, reveal, PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, info.PublicKey)).Verified.Should().BeTrue();
    }

    [BbsTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WhatTheCallersDictionaryThrows_PropagatesUnchanged_BeforeTheStoreIsCalled(bool keyStore)
    {
        // The dictionary is the caller's code, as the store is, so what it throws is not wrapped. The copy bbs-2023
        // had before issue #61 wrapped an ArgumentException; the shared one does not (PR #62 review).
        var (store, info) = await StoreWithVectorKeyAsync();
        var fault = new ArgumentException("the caller's own");
        var options = BaseOptions() with { AdditionalProperties = new ScriptedDictionary([], count: 0, fault: fault) };

        var thrown = await Issue(keyStore, options, store, info).Should().ThrowAsync<ArgumentException>();

        thrown.Which.Should().BeSameAs(fault);
        store.Calls.Should().BeEmpty();
    }

    [BbsTheory]
    [MemberData(nameof(Issue61OptionsCopyTestsBase.PreviousProofForms), MemberType = typeof(Issue61OptionsCopyTestsBase))]
    public async Task ACallerThatTriesToRewriteItsPreviousProof_LeavesBothProofsAsIssuedAndDerivable(string form)
    {
        // The options copy shares previousProof, which nothing can change (issue #61). Every write its caller can
        // make is tried while the store signs and again after both calls: each public route through Values,
        // ICollection.SyncRoot included, and the array a collection of the caller's was handed when FromValues copied
        // it (PR #62 review, twice). Both proofs keep the ids and the wire form that were signed, and both still derive.
        var (sk, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var suite = new Bbs2023Cryptosuite();
        var expected = JsonSerializer.Serialize(
            await suite.CreateBaseProofAsync(
                WindDoc(), BaseOptions() with { PreviousProof = Issue61OptionsCopyTestsBase.CallersPreviousProof(form).Reference },
                sk, hmacKey, WindMandatory()),
            DataProofsJsonOptions.Default);

        var (previousProof, rewrite) = Issue61OptionsCopyTestsBase.CallersPreviousProof(form);
        var options = BaseOptions() with { PreviousProof = previousProof };
        store.TamperSignature = (_, genuine) =>
        {
            rewrite();
            return genuine;
        };
        var raw = await suite.CreateBaseProofAsync(WindDoc(), options, sk, hmacKey, WindMandatory());
        var stored = await suite.CreateBaseProofAsync(
            WindDoc(), options, store, Alias, info.InstanceId!.Value, hmacKey, WindMandatory());
        rewrite();

        expected.Should().Contain(form == "string" ? "\"previousProof\":\"urn:proof:original\"" : "\"previousProof\":[\"urn:proof:original\"");
        foreach (var proof in new[] { raw, stored })
        {
            JsonSerializer.Serialize(proof, DataProofsJsonOptions.Default).Should().Be(expected);
            var reveal = suite.DeriveProof(Embed(WindDoc(), proof), ["/credentialSubject/sails/0"], Convert.FromHexString("113377aa"));
            VerifyReveal(suite, reveal, PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, info.PublicKey)).Verified.Should().BeTrue();
        }
    }

    public static TheoryData<string> CallerCodeThatRunsDuringIssuance() => ["the key store", "a canonicalizer of the caller's"];

    [BbsTheory]
    [MemberData(nameof(CallerCodeThatRunsDuringIssuance))]
    public async Task MandatoryPointersFromACollectionThatKeepsItsArray_AreThePointersThatWereAskedFor(string callerCode)
    {
        // ToArray hands a collection that implements ICollection<T> the array it returns. The suite groups the
        // pointers, runs the caller's code, then packs them, so it must keep an array the collection was never
        // handed, whichever overload runs the caller's code (PR #62 review).
        var (sk, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var mandatory = WindMandatory();
        var expected = await new Bbs2023Cryptosuite().CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, mandatory);
        var pointers = new CapturingIds(mandatory);
        void Rewrite() => pointers.WriteToHandedArray(0, mandatory[1]);

        DataIntegrityProof proof;
        if (callerCode == "the key store")
        {
            store.TamperSignature = (_, genuine) =>
            {
                Rewrite();
                return genuine;
            };
            proof = await new Bbs2023Cryptosuite().CreateBaseProofAsync(
                WindDoc(), BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, pointers);
        }
        else
        {
            proof = await new Bbs2023Cryptosuite(new HookedCanonicalizer(Rewrite)).CreateBaseProofAsync(
                WindDoc(), BaseOptions(), sk, hmacKey, pointers);
        }

        proof.ProofValue.Should().Be(expected.ProofValue);
        var suite = new Bbs2023Cryptosuite();
        var reveal = suite.DeriveProof(Embed(WindDoc(), proof), ["/credentialSubject/sails/0"], Convert.FromHexString("113377aa"));
        VerifyReveal(suite, reveal, PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, info.PublicKey)).Verified.Should().BeTrue();
    }

    private static JsonElement WithoutProof(JsonElement document)
    {
        var node = JsonObject.Create(document)!;
        node.Remove("proof");
        return JsonSerializer.SerializeToElement(node, DataProofsJsonOptions.Default);
    }

    [BbsFact]
    public async Task SelectivePointersFromACollectionThatKeepsItsArray_AreThePointersThatWereAskedFor()
    {
        // DeriveProof used the caller's pointers several times, and Concat(...).ToList() handed the collection the
        // list's own array, which the reveal document was selected with after a canonicalizer of the caller's ran
        // (PR #62 follow-up c).
        var (sk, hmacKey) = KeyMaterial();
        var (_, info) = await StoreWithVectorKeyAsync();
        var secured = Embed(WindDoc(), await new Bbs2023Cryptosuite().CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, WindMandatory()));
        var header = Convert.FromHexString("113377aa");
        var expected = new Bbs2023Cryptosuite().DeriveProof(secured, ["/credentialSubject/sails/0"], header);
        var pointers = new CapturingIds("/credentialSubject/sails/0");
        var suite = new Bbs2023Cryptosuite(new HookedCanonicalizer(
            () => pointers.ReplaceInHandedArray("/credentialSubject/sails/0", "/credentialSubject/sails/1")));

        var reveal = suite.DeriveProof(secured, pointers, header);

        JsonElement.DeepEquals(WithoutProof(reveal), WithoutProof(expected)).Should().BeTrue();
        VerifyReveal(new Bbs2023Cryptosuite(), reveal, PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, info.PublicKey)).Verified.Should().BeTrue();
    }

    [BbsFact]
    public async Task APresentationHeaderChangedWhileTheProofIsDerived_IsTheHeaderThatWasGiven()
    {
        // The header was read for the BBS proof and again for the derived proofValue, with a canonicalizer of the
        // caller's in between, so the two could differ and the derived proof did not verify (PR #62 follow-up d2).
        var (sk, hmacKey) = KeyMaterial();
        var (_, info) = await StoreWithVectorKeyAsync();
        var secured = Embed(WindDoc(), await new Bbs2023Cryptosuite().CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, WindMandatory()));
        var header = Convert.FromHexString("113377aa");
        var suite = new Bbs2023Cryptosuite(new HookedCanonicalizer(() => header[0]++));

        var reveal = suite.DeriveProof(secured, ["/credentialSubject/sails/0"], header);

        VerifyReveal(new Bbs2023Cryptosuite(), reveal, PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, info.PublicKey)).Verified.Should().BeTrue();
    }

    [BbsFact]
    public async Task APrivateKeyChangedWhileTheBaseProofIsPrepared_SignsWithTheKeyThatWasGiven()
    {
        // The raw-key overload derived the public key before a canonicalizer of the caller's ran and signed after it,
        // reading the key each time, so the proof could pack one key's public key with another's signature
        // (PR #62 follow-up d1).
        var (sk, hmacKey) = KeyMaterial();
        var (_, info) = await StoreWithVectorKeyAsync();
        var expected = await new Bbs2023Cryptosuite().CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, WindMandatory());
        var other = new byte[sk.Length];
        other[^1] = 7;
        var suite = new Bbs2023Cryptosuite(new HookedCanonicalizer(() => other.CopyTo(sk, 0)));

        var proof = await suite.CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, WindMandatory());

        proof.ProofValue.Should().Be(expected.ProofValue);
        var plain = new Bbs2023Cryptosuite();
        var reveal = plain.DeriveProof(Embed(WindDoc(), proof), ["/credentialSubject/sails/0"], Convert.FromHexString("113377aa"));
        VerifyReveal(plain, reveal, PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, info.PublicKey)).Verified.Should().BeTrue();
    }

    [BbsTheory]
    [InlineData(-1, false)]
    [InlineData(-1, true)]
    [InlineData(0, false)]
    [InlineData(0, true)]
    [InlineData(int.MaxValue, false)]
    [InlineData(int.MaxValue, true)]
    public async Task PointersWhoseCollectionLiesAboutItsCount_AreThePointersThatWereAskedFor(int count, bool keyStore)
    {
        // ToArray sized its array from the caller's Count. At -1 and int.MaxValue a raw OverflowException or
        // OutOfMemoryException escaped from issuance, and since this PR from DeriveProof too, and at 0 the pointers
        // were dropped (PR #62 review). The pointers are now copied by enumeration.
        var (sk, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var expected = await new Bbs2023Cryptosuite().CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, WindMandatory());

        var proof = await Issue(keyStore, BaseOptions(), store, info, new CapturingIds(WindMandatory()) { ReportedCount = count })();

        proof.ProofValue.Should().Be(expected.ProofValue);
        var suite = new Bbs2023Cryptosuite();
        var reveal = suite.DeriveProof(
            Embed(WindDoc(), proof), new CapturingIds("/credentialSubject/sails/0") { ReportedCount = count }, Convert.FromHexString("113377aa"));
        VerifyReveal(suite, reveal, PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, info.PublicKey)).Verified.Should().BeTrue();
    }

    [BbsTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CallerCodeInThePointers_CannotChangeAnInputCopiedBeforeThem(bool keyStore)
    {
        // Reading the pointers runs the caller's code. The document, the HMAC key and the private key are copied before
        // that, because copying them runs none (PR #62 review: the pointers were read first, and could swap the HMAC
        // key and the private key).
        var (sk, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var expected = await new Bbs2023Cryptosuite().CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, WindMandatory());
        var buffer = Encoding.UTF8.GetBytes(WindDoc().GetRawText());
        using var document = JsonDocument.Parse(buffer.AsMemory());
        var at = buffer.AsSpan().IndexOf("Earth101"u8) + 7;
        var flipped = (byte)~hmacKey[0];
        var other = new byte[sk.Length];
        other[^1] = 7;
        var pointers = new CapturingIds(WindMandatory())
        {
            OnRead = () =>
            {
                buffer[at] = (byte)'2';
                hmacKey[0] = flipped;
                other.CopyTo(sk, 0);
            },
        };

        var proof = keyStore
            ? await new Bbs2023Cryptosuite().CreateBaseProofAsync(
                document.RootElement, BaseOptions(), store, Alias, info.InstanceId!.Value, hmacKey, pointers)
            : await new Bbs2023Cryptosuite().CreateBaseProofAsync(document.RootElement, BaseOptions(), sk, hmacKey, pointers);

        proof.ProofValue.Should().Be(expected.ProofValue);
    }

    [BbsFact]
    public async Task DeriveProof_CopiesTheHeaderAndTheDocumentBeforeThePointersAreRead()
    {
        // Enumerating the pointers runs the caller's code, so the header and the base document are copied before it
        // (PR #62 review: the header was copied after the pointers were read).
        var (sk, hmacKey) = KeyMaterial();
        var (_, info) = await StoreWithVectorKeyAsync();
        var secured = Embed(WindDoc(), await new Bbs2023Cryptosuite().CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, WindMandatory()));
        var expected = new Bbs2023Cryptosuite().DeriveProof(secured, ["/credentialSubject/sails/0"], Convert.FromHexString("113377aa"));
        var buffer = Encoding.UTF8.GetBytes(secured.GetRawText());
        var document = JsonDocument.Parse(buffer.AsMemory());
        var at = buffer.AsSpan().IndexOf("Earth101"u8) + 7;
        var header = Convert.FromHexString("113377aa");
        var pointers = new CapturingIds("/credentialSubject/sails/0")
        {
            OnRead = () =>
            {
                header[0] = 0;
                buffer[at] = (byte)'2';
                document.Dispose();
            },
        };

        var reveal = new Bbs2023Cryptosuite().DeriveProof(document.RootElement, pointers, header);

        var derived = Bbs2023ProofValue.ParseDerivedProof(reveal.GetProperty("proof").GetProperty("proofValue").GetString()!);
        derived.PresentationHeader.Should().Equal(Convert.FromHexString("113377aa"));
        JsonElement.DeepEquals(WithoutProof(reveal), WithoutProof(expected)).Should().BeTrue();
        VerifyReveal(new Bbs2023Cryptosuite(), reveal, PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, info.PublicKey)).Verified.Should().BeTrue();
    }

    [BbsFact]
    public async Task DeriveProof_ADisposedBaseDocument_IsAProofGenerationException()
    {
        // As at every create entry point (PR #62 review: DeriveProof let the raw ObjectDisposedException out).
        var (sk, hmacKey) = KeyMaterial();
        var secured = Embed(WindDoc(), await new Bbs2023Cryptosuite().CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, WindMandatory()));
        JsonElement disposed;
        using (var source = JsonDocument.Parse(secured.GetRawText()))
        {
            disposed = source.RootElement;
        }

        FluentActions.Invoking(() => new Bbs2023Cryptosuite().DeriveProof(disposed, ["/credentialSubject/sails/0"], Convert.FromHexString("113377aa")))
            .Should().Throw<ProofGenerationException>().WithMessage("The secured base document has been disposed.")
            .WithInnerException<ObjectDisposedException>();
    }

    [BbsTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ADocumentDisposedWhileItIsCopied_IsAProofGenerationException_BeforeTheStoreIsCalled(bool keyStore)
    {
        // A dispose racing the copy could leave a copy of another document's bytes, which would be signed. The source
        // is read again after the copy (PR #62 review).
        var (store, info) = await StoreWithVectorKeyAsync();
        var memory = new DisposingMemory(WindDoc().GetRawText());
        memory.DisposeOnNextRead();

        var thrown = await Issue(keyStore, BaseOptions(), store, info, document: memory.Document.RootElement)
            .Should().ThrowAsync<ProofGenerationException>().WithMessage("The document to secure has been disposed.");

        thrown.WithInnerException<ObjectDisposedException>();
        store.Calls.Should().BeEmpty();
    }

    [BbsFact]
    public async Task DeriveProof_ABaseDocumentDisposedWhileItIsCopied_IsAProofGenerationException()
    {
        var (sk, hmacKey) = KeyMaterial();
        var secured = Embed(WindDoc(), await new Bbs2023Cryptosuite().CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, WindMandatory()));
        var memory = new DisposingMemory(secured.GetRawText());
        memory.DisposeOnNextRead();

        FluentActions.Invoking(() => new Bbs2023Cryptosuite().DeriveProof(
                memory.Document.RootElement, ["/credentialSubject/sails/0"], Convert.FromHexString("113377aa")))
            .Should().Throw<ProofGenerationException>().WithMessage("The secured base document has been disposed.")
            .WithInnerException<ObjectDisposedException>();
    }

    // A canonicalizer of the caller's: the RDFC one, after running during on every call.
    private sealed class HookedCanonicalizer(Action during) : IRdfCanonicalizer
    {
        private readonly RdfcDocumentCanonicalizer _inner = new();

        public byte[] CanonicalizeJsonLd(JsonElement document, RdfCanonicalizationHashAlgorithm hashAlgorithm = RdfCanonicalizationHashAlgorithm.Sha256)
        {
            during();
            return _inner.CanonicalizeJsonLd(document, hashAlgorithm);
        }

        public string CanonicalizeNQuads(string nQuads, RdfCanonicalizationHashAlgorithm hashAlgorithm = RdfCanonicalizationHashAlgorithm.Sha256)
        {
            during();
            return _inner.CanonicalizeNQuads(nQuads, hashAlgorithm);
        }

        public IReadOnlyDictionary<string, string> CanonicalizeNQuadsToMap(string nQuads, RdfCanonicalizationHashAlgorithm hashAlgorithm = RdfCanonicalizationHashAlgorithm.Sha256)
        {
            during();
            return _inner.CanonicalizeNQuadsToMap(nQuads, hashAlgorithm);
        }
    }

    [BbsFact]
    public async Task TheReturnedProof_OutlivesTheCallersJsonDocuments()
    {
        // An extension value and the options' fallback @context, read from documents the caller disposes
        // after the call: the issued proof must not depend on them (PR #60 review).
        var (sk, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();
        var suite = new Bbs2023Cryptosuite();

        // No @context in the document, so the proof configuration takes the options' context.
        var document = Parse("""
            {
              "@id": "urn:example:credential",
              "https://example.org/vocab#name": "Alice",
              "https://example.org/vocab#color": "purple"
            }
            """);
        using var noteDocument = JsonDocument.Parse("\"kept\"");
        using var contextDocument = JsonDocument.Parse("\"https://www.w3.org/ns/credentials/v2\"");
        var options = BaseOptions() with
        {
            Context = contextDocument.RootElement,
            // An absolute IRI, so the proof configuration needs no context definition for it.
            AdditionalProperties = new Dictionary<string, JsonElement> { ["https://example.org/vocab#note"] = noteDocument.RootElement },
        };

        var raw = await suite.CreateBaseProofAsync(document, options, sk, hmacKey, []);
        var stored = await suite.CreateBaseProofAsync(
            document, options, store, Alias, info.InstanceId!.Value, hmacKey, []);
        var rawJson = JsonSerializer.Serialize(raw, DataProofsJsonOptions.Default);
        var storedJson = JsonSerializer.Serialize(stored, DataProofsJsonOptions.Default);
        storedJson.Should().Be(rawJson).And.Contain("credentials/v2").And.Contain("vocab#note\":\"kept\"");

        noteDocument.Dispose();
        contextDocument.Dispose();

        JsonSerializer.Serialize(raw, DataProofsJsonOptions.Default).Should().Be(rawJson);
        JsonSerializer.Serialize(stored, DataProofsJsonOptions.Default).Should().Be(storedJson);
    }

    [BbsFact]
    public async Task TheStoreSeesTheNonMandatoryStatements_ButNotTheMandatoryOnesNorTheHmacKey()
    {
        // What the XML docs say a remote key service learns: BBS signs the messages, not a hash of them.
        var (_, hmacKey) = KeyMaterial();
        var (store, info) = await StoreWithVectorKeyAsync();

        await new Bbs2023Cryptosuite().CreateBaseProofAsync(
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

        await suite.Invoking(s => s.CreateBaseProofAsync(WindDoc(), BaseOptions(), null!, Alias, id, hmacKey, WindMandatory()))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("keyStore");
        await suite.Invoking(s => s.CreateBaseProofAsync(WindDoc(), BaseOptions(), store, null!, id, hmacKey, WindMandatory()))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("alias");
        await suite.Invoking(s => s.CreateBaseProofAsync(WindDoc(), BaseOptions(), store, "", id, hmacKey, WindMandatory()))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("alias");
        await suite.Invoking(s => s.CreateBaseProofAsync(WindDoc(), BaseOptions(), store, Alias, default, hmacKey, WindMandatory()))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("instanceId");
        await suite.Invoking(s => s.CreateBaseProofAsync(WindDoc(), null!, store, Alias, id, hmacKey, WindMandatory()))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("proofOptions");
        await suite.Invoking(s => s.CreateBaseProofAsync(WindDoc(), BaseOptions(), store, Alias, id, hmacKey, null!))
            .Should().ThrowAsync<ArgumentNullException>().WithParameterName("mandatoryPointers");

        store.Calls.Should().BeEmpty();
    }

    [Fact]
    [Trait("Category", "BbsAbsent")]
    public void TheKeyStorePath_TakesNoPrivateKeyBytes()
    {
        // The issue's "no API on that path accepts private-key bytes": the only byte parameter is the
        // HMAC key, which the holder receives inside the base proof.
        // Two overloads share the name, so the key-store one is picked by its parameter types.
        var overloads = typeof(Bbs2023Cryptosuite).GetMethods()
            .Where(m => m.Name == nameof(Bbs2023Cryptosuite.CreateBaseProofAsync)).ToList();
        overloads.Should().HaveCount(2);
        var method = overloads.Single(m => m.GetParameters().Any(p => p.ParameterType == typeof(ICapableKeyStore)));
        var parameters = method.GetParameters();

        parameters.Select(p => p.ParameterType).Should().Contain(typeof(ICapableKeyStore));
        parameters.Where(p => IsBytes(p.ParameterType)).Select(p => p.Name).Should().Equal("hmacKey");

        static bool IsBytes(Type type)
            => type == typeof(byte[]) || type == typeof(ReadOnlyMemory<byte>) || type == typeof(Memory<byte>)
                || type == typeof(IEnumerable<byte>) || type == typeof(IReadOnlyList<byte>);
    }
}
