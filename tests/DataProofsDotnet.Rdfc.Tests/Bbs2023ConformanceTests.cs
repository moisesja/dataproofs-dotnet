using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using DataProofsDotnet.Rdfc.Internal;
using DataProofsDotnet.Rdfc.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// bbs-2023 conformance against the W3C <c>vc-di-bbs</c> test vectors and the reference
/// implementation's algorithms (PR #42). Before this, the suite signed every N-Quad as a BBS
/// message, used absolute indexes, exposed skolem IRIs in the reveal document and keyed the derived
/// label map by skolem labels: its proofs verified only here. Now the W3C derived-proof vector
/// verifies, the deterministic intermediates (BBS header, label map, indexes, reveal document) equal
/// the vectors', and a reveal made here verifies on the reference verifier (checked out of band with
/// <c>@digitalbazaar/bbs-2023-cryptosuite</c>; see the PR).
/// </summary>
public sealed class Bbs2023ConformanceTests
{
    private const string Vectors = "TestVectors";
    private const string V2 = "https://www.w3.org/ns/credentials/v2";

    private static JsonElement Vector(string name) => Fx.Json("w3c", "vc-di-bbs", Vectors, name);

    private static (byte[] Sk, byte[] HmacKey) KeyMaterial()
    {
        var keyMaterial = Vector("BBSKeyMaterial.json");
        return (
            Convert.FromHexString(keyMaterial.GetProperty("privateKeyHex").GetString()!),
            Convert.FromHexString(keyMaterial.GetProperty("hmacKeyString").GetString()!));
    }

    /// <summary>The vector's proof options (addProofConfig.json without its @context, which the suite adds).</summary>
    private static DataIntegrityProof VectorOptions()
    {
        var config = Vector("addProofConfig.json");
        return new DataIntegrityProof
        {
            Type = config.GetProperty("type").GetString()!,
            Cryptosuite = config.GetProperty("cryptosuite").GetString()!,
            Created = config.GetProperty("created").GetString()!,
            VerificationMethod = config.GetProperty("verificationMethod").GetString()!,
            ProofPurpose = config.GetProperty("proofPurpose").GetString()!,
        };
    }

    private static string[] Pointers(string name) => JsonSerializer.Deserialize<string[]>(Fx.Text("w3c", "vc-di-bbs", Vectors, name))!;

    private static PublicKeyMaterial VectorPublicKey(string verificationMethod)
    {
        var start = "did:key:".Length;
        return PublicKeyMaterial.FromMultikey(verificationMethod[start..verificationMethod.IndexOf('#')]);
    }

    private static (DataIntegrityProof Proof, JsonElement Unsecured) Split(JsonElement secured)
        => (secured.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!,
            Fx.Mutate(secured, document => document.Remove("proof")));

    private static async Task<JsonElement> SecuredWindDocAsync(Bbs2023Cryptosuite suite, byte[] sk, byte[] hmacKey)
    {
        var baseProof = await suite.CreateBaseProofAsync(Vector("windDoc.json"), VectorOptions(), sk, hmacKey, Pointers("windMandatory.json"));
        return Fx.Mutate(Vector("windDoc.json"), document => document["proof"] = JsonSerializer.SerializeToNode(baseProof, DataProofsJsonOptions.Default));
    }

    // ------------------------------------------------------------------ the W3C vectors

    [BbsFact]
    public void DerivedRevealVector_Verifies_DirectlyAndThroughThePipeline()
    {
        // The headline: a reveal document and derived proof the reference implementation produced.
        var reveal = Vector("derivedRevealDocument.json");
        var (proof, unsecured) = Split(reveal);
        var publicKey = VectorPublicKey(proof.VerificationMethod!);
        var suite = new Bbs2023Cryptosuite();
        var pipeline = new DataIntegrityProofPipeline(CryptosuiteRegistry.CreateDefault().AddBbs2023());

        suite.VerifyProof(unsecured, proof, publicKey).Verified.Should().BeTrue();
        pipeline.Verify(reveal, publicKey).Verified.Should().BeTrue();

        // And the mandatory binding holds on the vector too: a mandatory value changed in the reveal fails.
        var tampered = Fx.Mutate(unsecured, document => document["issuer"] = "https://evil.example/");
        suite.VerifyProof(tampered, proof, publicKey).Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task BaseProof_BindsTheVectorsProofHashAndMandatoryHash()
    {
        // bbsHeader = proofHash ‖ mandatoryHash is deterministic for the vector's options and HMAC key,
        // and it pins the proof configuration, the canonical N-Quads, the HMAC labels and the mandatory partition.
        var (sk, hmacKey) = KeyMaterial();
        var hashes = Vector("addHashData.json");
        var expectedHeader = Convert.FromHexString(hashes.GetProperty("proofHash").GetString()! + hashes.GetProperty("mandatoryHash").GetString()!);

        var baseProof = await new Bbs2023Cryptosuite().CreateBaseProofAsync(
            Vector("windDoc.json"), VectorOptions(), sk, hmacKey, Pointers("windMandatory.json"));
        var components = Bbs2023ProofValue.ParseBaseProof(baseProof.ProofValue!);

        components.BbsHeader.Should().Equal(expectedHeader);
        components.MandatoryPointers.Should().Equal(Pointers("windMandatory.json"));
        components.HmacKey.Should().Equal(hmacKey);
    }

    [BbsFact]
    public async Task DerivedProof_MatchesTheVectorsDisclosureData()
    {
        // The label map (keyed by the reveal's canonical labels), the relative index sets and the
        // reveal document are deterministic; only the BBS proof bytes are randomized.
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await SecuredWindDocAsync(suite, sk, hmacKey);
        var expected = Vector("derivedDisclosureData.json");
        var adjusted = Vector("derivedAdjIndexes.json");

        var reveal = suite.DeriveProof(secured, Pointers("windSelective.json"), Convert.FromHexString("113377aa"));
        var components = Bbs2023ProofValue.ParseDerivedProof(reveal.GetProperty("proof").GetProperty("proofValue").GetString()!);

        var expectedLabelMap = expected.GetProperty("labelMap").GetProperty("value").EnumerateArray()
            .ToDictionary(pair => pair[0].GetString()!, pair => pair[1].GetString()!);
        components.LabelMap.Should().BeEquivalentTo(expectedLabelMap);
        components.MandatoryIndexes.Should().Equal(adjusted.GetProperty("adjMandatoryIndexes").Deserialize<int[]>()!);
        components.SelectiveIndexes.Should().Equal(adjusted.GetProperty("adjSelectiveIndexes").Deserialize<int[]>()!);
        components.PresentationHeader.Should().Equal(Convert.FromHexString("113377aa"));

        var (proof, unsecured) = Split(reveal);
        JsonNode.DeepEquals(JsonNode.Parse(unsecured.GetRawText()), JsonNode.Parse(Vector("derivedUnsignedReveal.json").GetRawText()))
            .Should().BeTrue("the reveal document is the selection of the document as written");
        reveal.GetRawText().Should().NotContain("urn:bnid", "a verifier sees blank nodes, not skolem ids");
        proof.VerificationMethod.Should().Be(VectorOptions().VerificationMethod);
    }

    // ------------------------------------------------------------------ refusals

    /// <summary>The wind credential with a list-valued property on the subject.</summary>
    private static JsonElement WindDocWithList()
        => Fx.Mutate(Vector("windDoc.json"), document =>
        {
            ((JsonArray)document["@context"]!).Add(new JsonObject { ["steps"] = new JsonObject { ["@id"] = "https://e.example/vocab#steps", ["@container"] = "@list" } });
            document["credentialSubject"]!["steps"] = new JsonArray("a", "b");
        });

    [BbsFact]
    public async Task ListDocument_IsRefusedAtCreation()
    {
        // The reference implementation cannot sign a document holding an @list either (its skolemizer
        // makes the list object invalid). Here the list's blank nodes have no stable label, so the
        // document is refused up front instead of failing at verification (#43).
        var (sk, hmacKey) = KeyMaterial();

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(WindDocWithList(), VectorOptions(), sk, hmacKey, Pointers("windMandatory.json"));

        (await act.Should().ThrowAsync<ProofGenerationException>())
            .WithInnerException<JsonLdDataLossException>().WithMessage("*blank node that bbs-2023 skolemization cannot name, such as a @list's*");
    }

    [BbsFact]
    public async Task ListDocument_IsRefusedAtDerivation_BeforeTheSignatureIsRead()
    {
        // A base proof from a list-free document attached to a list document: the holder's boundary
        // refuses the document before the base proof's signature matters.
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await SecuredWindDocAsync(suite, sk, hmacKey);
        var withList = Fx.Mutate(WindDocWithList(), document => document["proof"] = JsonNode.Parse(secured.GetProperty("proof").GetRawText()));

        var act = () => suite.DeriveProof(withList, ["/credentialSubject/sails/0"], Convert.FromHexString("113377aa"));

        act.Should().Throw<ProofGenerationException>()
            .WithInnerException<JsonLdDataLossException>().WithMessage("*blank node that bbs-2023 skolemization cannot name*");
    }

    [BbsFact]
    public async Task LanguageMap_IsRefusedAsSkolemizationThatWouldChangeTheDocument()
    {
        // The compact skolemizer adds an @id to the map, which reads as a language key; the document as
        // written canonicalizes, so the refusal names skolemization, not the language tag (#43 review).
        var (sk, hmacKey) = KeyMaterial();
        var document = Fx.Mutate(Vector("windDoc.json"), vc =>
        {
            ((JsonArray)vc["@context"]!).Add(new JsonObject { ["label"] = new JsonObject { ["@id"] = "https://schema.org/name", ["@container"] = "@language" } });
            vc["credentialSubject"]!["label"] = new JsonObject { ["en"] = "x", ["@none"] = "y" };
        });

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(document, VectorOptions(), sk, hmacKey, Pointers("windMandatory.json"));

        (await act.Should().ThrowAsync<ProofGenerationException>())
            .WithInnerException<JsonLdDataLossException>().WithMessage("*skolemization would change it*");
    }

    [BbsFact]
    public async Task MandatoryOnlyDisclosure_IsRefused()
    {
        // The spec allows a disclosure of mandatory statements alone (no BBS message disclosed); the
        // BBS provider needs at least one revealed index (NetCrypto 1.7.1), so it is refused with a
        // message that says what to do. The same holds when the selection repeats mandatory pointers.
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await SecuredWindDocAsync(suite, sk, hmacKey);

        foreach (var selective in new[] { Array.Empty<string>(), new[] { "/credentialSubject/sails/1" } })
        {
            var act = () => suite.DeriveProof(secured, selective, Convert.FromHexString("113377aa"));
            act.Should().Throw<ProofGenerationException>().WithMessage("A mandatory-only disclosure is not supported*");
        }
    }

    [BbsFact]
    public async Task AllMandatoryDocument_IsRefused()
    {
        // Every statement mandatory leaves no BBS message, which the provider cannot sign.
        var (sk, hmacKey) = KeyMaterial();
        var document = JsonDocument.Parse("{\"@context\":[\"" + V2 + "\"],\"id\":\"urn:uuid:all-mandatory\",\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:issuer\"}").RootElement.Clone();

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(document, VectorOptions(), sk, hmacKey, ["/issuer", "/type"]);

        (await act.Should().ThrowAsync<ProofGenerationException>()).WithMessage("bbs-2023 needs at least one non-mandatory statement*");
    }

    [BbsFact]
    public async Task UnmappedBlankNodeInTheReveal_IsAVerificationFailure()
    {
        // A holder adds a blank node the derived proof's label map does not cover: the verifier cannot
        // relabel it to a signed message and fails closed with a clear reason.
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await SecuredWindDocAsync(suite, sk, hmacKey);
        var reveal = suite.DeriveProof(secured, Pointers("windSelective.json"), Convert.FromHexString("113377aa"));
        var (proof, unsecured) = Split(reveal);
        var publicKey = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk).PublicKey);
        var extra = Fx.Mutate(unsecured, document => document["credentialSubject"]!["sponsor"] = new JsonObject { ["sailName"] = "x" });

        var result = suite.VerifyProof(extra, proof, publicKey);

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Message.Should().Contain("label map does not cover");
    }
}
