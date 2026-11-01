using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// The legacy RDFC variant binds what the 2022/2019 suites bind: a proof verifies only if the proof
/// options the library reads are what the issuer signed (see the Rdfc package's tests of the same
/// name). This variant takes its proof <c>@context</c> from the document, so that is the way in.
/// </summary>
public class ProofOptionsBindingTests
{
    private const string Sec = "https://w3id.org/security#";
    private const string XsdDateTime = "http://www.w3.org/2001/XMLSchema#dateTime";
    private const string Expiry = "2027-01-01T00:00:00Z";
    private const string CredentialsV1 = "https://www.w3.org/2018/credentials/v1";
    private const string CredentialsV2 = "https://www.w3.org/ns/credentials/v2";
    private const string Ed25519Context = "https://w3id.org/security/suites/ed25519-2020/v1";

    private static readonly DateTimeOffset BeforeExpiry = DateTimeOffset.Parse("2026-11-01T00:00:00Z");
    private static readonly DateTimeOffset AfterExpiry = DateTimeOffset.Parse("2028-01-01T00:00:00Z");

    private const string Renamed = "{\"renamed\":{\"@id\":\"" + Sec + "expiration\",\"@type\":\"" + XsdDateTime + "\"}}";

    private static JsonElement Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    private static JsonElement Credential(string context) => Parse(
        "{\"@context\":" + context + ",\"id\":\"urn:uuid:46464646-0000-4000-8000-000000000042\","
        + "\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:issuer\","
        + "\"credentialSubject\":{\"id\":\"did:example:alice\"}}");

    // The suite, its key, the proof type, and contexts that define that proof type.
    private static (DataIntegrityProofPipeline Pipeline, KeyPairSigner Signer, PublicKeyMaterial PublicKey, string Type, string[] Contexts) Setup(string type)
    {
        var registry = CryptosuiteRegistry.CreateDefault();
        KeyPair key;
        string[] contexts;
        if (type == Ed25519Signature2020Cryptosuite.ProofType)
        {
            registry.Register(new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Rdfc));
            key = Fx.SeedKey(0x21, KeyType.Ed25519);
            contexts = [CredentialsV2, Ed25519Context];
        }
        else
        {
            registry.Register(new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Rdfc));
            key = Fx.SeedKey(0x22, KeyType.P256);
            contexts = [CredentialsV1];
        }

        return (new DataIntegrityProofPipeline(registry), Fx.Signer(key), PublicKeyMaterial.FromRaw(key.KeyType, key.PublicKey), type, contexts);
    }

    private static DataIntegrityProof Options(string type, string? expires = null) => new()
    {
        Type = type,
        Cryptosuite = type,
        Created = "2026-10-30T00:00:00Z",
        VerificationMethod = "did:example:issuer#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
        Expires = expires,
    };

    private static string ContextArray(string[] contexts, params string[] inlineContexts)
        => "[" + string.Join(",", contexts.Select(context => "\"" + context + "\"").Concat(inlineContexts)) + "]";

    private static ProofVerificationOptions At(DateTimeOffset time) => new() { VerificationTime = time };

    [Theory]
    [InlineData(Ed25519Signature2020Cryptosuite.ProofType)]
    [InlineData(EcdsaSecp256r1Signature2019Cryptosuite.ProofType)]
    public async Task ExpiredProofStaysExpiredWhenTheDocumentContextRenamesExpires(string type)
    {
        var (pipeline, signer, publicKey, _, contexts) = Setup(type);
        var secured = await pipeline.AddProofAsync(Credential(ContextArray(contexts)), Options(type, Expiry), signer);
        pipeline.Verify(secured, publicKey, At(BeforeExpiry)).Verified.Should().BeTrue();
        pipeline.Verify(secured, publicKey, At(AfterExpiry)).Verified.Should().BeFalse();

        var attacked = Fx.Mutate(secured, node =>
        {
            node["@context"] = JsonNode.Parse(ContextArray(contexts, Renamed));
            var proof = (JsonObject)node["proof"]!;
            proof.Remove("expires");
            proof["renamed"] = Expiry;
        });

        pipeline.Verify(attacked, publicKey, At(AfterExpiry)).Verified.Should().BeFalse();
    }

    [Fact]
    public async Task AChallengeTheIssuerNeverSignedIsRefusedUnderAnUnprotectedContext()
    {
        var (pipeline, signer, publicKey, type, _) = Setup(Ed25519Signature2020Cryptosuite.ProofType);
        const string terms =
            "\"id\":\"@id\",\"type\":\"@type\",\"Ed25519Signature2020\":\"" + Sec + "Ed25519Signature2020\","
            + "\"created\":{\"@id\":\"http://purl.org/dc/terms/created\",\"@type\":\"" + XsdDateTime + "\"},"
            + "\"verificationMethod\":{\"@id\":\"" + Sec + "verificationMethod\",\"@type\":\"@id\"},"
            + "\"proofPurpose\":{\"@id\":\"" + Sec + "proofPurpose\",\"@type\":\"@vocab\"},"
            + "\"assertionMethod\":{\"@id\":\"" + Sec + "assertionMethod\",\"@type\":\"@id\"},"
            + "\"claim\":\"https://example.org/claim\"";
        var document = Parse("{\"@context\":{" + terms + "},\"id\":\"urn:uuid:46464646-0000-4000-8000-000000000042\",\"claim\":\"value\"}");
        var secured = await pipeline.AddProofAsync(document, Options(type), signer);
        pipeline.Verify(secured, publicKey).Verified.Should().BeTrue();

        var attacked = Fx.Mutate(secured, node =>
        {
            node["@context"] = JsonNode.Parse("{" + terms + ",\"challenge\":\"@type\",\"abc\":\"" + Sec + "Ed25519Signature2020\"}");
            ((JsonObject)node["proof"]!)["challenge"] = "abc";
        });

        pipeline.Verify(attacked, publicKey, new ProofVerificationOptions { ExpectedChallenge = "abc" }).Verified.Should().BeFalse();
    }
}
