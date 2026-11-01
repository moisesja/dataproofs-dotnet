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
/// A proof verifies only if the proof options the library reads are what the issuer signed. The
/// pipeline reads JSON members, the signature covers the RDF of the proof configuration, and
/// <c>@context</c> is unsigned, so a holder with no key can spell the same RDF with different JSON.
/// Each attack here keeps the signature valid. Each first shows the untouched proof verifying, so a
/// suite that refused everything would not pass.
/// </summary>
public class ProofOptionsBindingTests
{
    private const string V2 = "https://www.w3.org/ns/credentials/v2";
    private const string Sec = "https://w3id.org/security#";
    private const string XsdDateTime = "http://www.w3.org/2001/XMLSchema#dateTime";
    private const string Expiry = "2027-01-01T00:00:00Z";

    private static readonly DateTimeOffset BeforeExpiry = DateTimeOffset.Parse("2026-11-01T00:00:00Z");
    private static readonly DateTimeOffset AfterExpiry = DateTimeOffset.Parse("2028-01-01T00:00:00Z");
    private static readonly byte[] PresentationHeader = [0x11, 0x33];
    private static readonly DataIntegrityProofPipeline Pipeline = new(RdfcCryptosuiteRegistration.CreateWithRdfcSuites());
    private static readonly Bbs2023Cryptosuite Bbs = new();

    // The proof terms, written inline so that no protected context limits what a term can mean.
    private const string ProofTerms =
        "\"id\":\"@id\",\"type\":\"@type\",\"DataIntegrityProof\":\"" + Sec + "DataIntegrityProof\","
        + "\"cryptosuite\":{\"@id\":\"" + Sec + "cryptosuite\",\"@type\":\"" + Sec + "cryptosuiteString\"},"
        + "\"created\":{\"@id\":\"http://purl.org/dc/terms/created\",\"@type\":\"" + XsdDateTime + "\"},"
        + "\"verificationMethod\":{\"@id\":\"" + Sec + "verificationMethod\",\"@type\":\"@id\"},"
        + "\"proofPurpose\":{\"@id\":\"" + Sec + "proofPurpose\",\"@type\":\"@vocab\"},"
        + "\"assertionMethod\":{\"@id\":\"" + Sec + "assertionMethod\",\"@type\":\"@id\"}";

    public static TheoryData<string> RdfcSuites() => new()
    {
        EddsaRdfc2022Cryptosuite.CryptosuiteName,
        EcdsaRdfc2019Cryptosuite.CryptosuiteName,
    };

    private static JsonElement Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }

    private static JsonNode InlineContext(string extraTerms) => JsonNode.Parse("{" + ProofTerms + extraTerms + "}")!;

    private static JsonElement Credential() => Parse(
        "{\"@context\":\"" + V2 + "\",\"id\":\"urn:uuid:46464646-0000-4000-8000-000000000042\","
        + "\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:issuer\","
        + "\"credentialSubject\":{\"id\":\"did:example:alice\",\"name\":\"Alice\",\"description\":\"d\"}}");

    private static (KeyPair Key, PublicKeyMaterial PublicKey) RdfcKey(string suite)
    {
        var type = suite == EddsaRdfc2022Cryptosuite.CryptosuiteName ? KeyType.Ed25519 : KeyType.P256;
        var key = Fx.KeyGen.FromPrivateKey(type, Enumerable.Repeat((byte)0x46, 32).ToArray());
        return (key, PublicKeyMaterial.FromRaw(type, key.PublicKey));
    }

    private static Task<JsonElement> SignRdfc(string suite, KeyPair key, string? expires = null, string? domain = null)
        => Pipeline.AddProofAsync(Credential(), new DataIntegrityProof
        {
            Cryptosuite = suite,
            Created = "2026-10-30T00:00:00Z",
            VerificationMethod = "did:example:issuer#key-1",
            ProofPurpose = ProofPurposes.AssertionMethod,
            Expires = expires,
            Domain = domain,
        }, Fx.Signer(key));

    private static (byte[] PrivateKey, byte[] HmacKey, PublicKeyMaterial PublicKey) BbsKeys()
    {
        var material = Fx.Json("w3c", "vc-di-bbs", "TestVectors", "BBSKeyMaterial.json");
        var privateKey = Convert.FromHexString(material.GetProperty("privateKeyHex").GetString()!);
        var hmacKey = Convert.FromHexString(material.GetProperty("hmacKeyString").GetString()!);
        var publicKey = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, privateKey).PublicKey);
        return (privateKey, hmacKey, publicKey);
    }

    private static DataIntegrityProof BbsOptions(string? expires = null, string? domain = null, JsonElement? context = null) => new()
    {
        Cryptosuite = Bbs2023Cryptosuite.CryptosuiteName,
        Created = "2026-10-30T00:00:00Z",
        VerificationMethod = "did:example:issuer#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
        Expires = expires,
        Domain = domain,
        Context = context,
    };

    private static async Task<JsonElement> DeriveBbs(
        JsonElement document, DataIntegrityProof options, string[] mandatory, string[] selective)
    {
        var (privateKey, hmacKey, _) = BbsKeys();
        var proof = await Bbs.CreateBaseProofAsync(document, options, privateKey, hmacKey, mandatory);
        var secured = Fx.Mutate(document, node => node["proof"] = JsonSerializer.SerializeToNode(proof, DataProofsJsonOptions.Default));
        return Bbs.DeriveProof(secured, selective, PresentationHeader);
    }

    private static Task<JsonElement> DeriveBbs(string? expires = null, string? domain = null)
        => DeriveBbs(Credential(), BbsOptions(expires, domain), ["/issuer"], ["/credentialSubject/name"]);

    private static JsonElement OnProof(JsonElement secured, Action<JsonObject> attack)
        => Fx.Mutate(secured, node => attack((JsonObject)node["proof"]!));

    // expires, renamed under a term for the same predicate, so that the pipeline sees no expiry.
    private static void RenameExpires(JsonObject proof)
    {
        proof.Remove("expires");
        proof["renamed"] = Expiry;
        proof["@context"] = InlineContext(",\"renamed\":{\"@id\":\"" + Sec + "expiration\",\"@type\":\"" + XsdDateTime + "\"}");
    }

    // A challenge the issuer never signed: the member spells the proof's own type, already signed.
    private static void InjectChallenge(JsonObject proof)
    {
        proof["challenge"] = "abc";
        proof["@context"] = InlineContext(",\"challenge\":\"@type\",\"abc\":\"" + Sec + "DataIntegrityProof\"");
    }

    // The signed domain moves to another term; the member named domain then spells the proof's type.
    private static void SwapDomain(JsonObject proof)
    {
        proof.Remove("domain");
        proof["signedDomain"] = "a.example";
        proof["domain"] = "b.example";
        proof["@context"] = InlineContext(
            ",\"signedDomain\":\"" + Sec + "domain\",\"domain\":\"@type\",\"b.example\":\"" + Sec + "DataIntegrityProof\"");
    }

    // The name authentication now means the assertionMethod IRI that was signed.
    private static void SwapPurpose(JsonObject proof)
    {
        proof["proofPurpose"] = "authentication";
        proof["@context"] = InlineContext(",\"authentication\":{\"@id\":\"" + Sec + "assertionMethod\",\"@type\":\"@id\"}");
    }

    // No proof @context at all: one term appended to the document's, which the suites then borrow.
    private static JsonElement RenameExpiresThroughTheDocumentContext(JsonElement secured) => Fx.Mutate(secured, node =>
    {
        node["@context"] = JsonNode.Parse(
            "[\"" + V2 + "\",{\"renamed\":{\"@id\":\"" + Sec + "expiration\",\"@type\":\"" + XsdDateTime + "\"}}]");
        var proof = (JsonObject)node["proof"]!;
        proof.Remove("@context");
        proof.Remove("expires");
        proof["renamed"] = Expiry;
    });

    private static ProofVerificationOptions At(DateTimeOffset time) => new() { VerificationTime = time };

    [Theory, MemberData(nameof(RdfcSuites))]
    public async Task Rdfc_ExpiredProofStaysExpiredWhenExpiresIsRenamed(string suite)
    {
        var (key, publicKey) = RdfcKey(suite);
        var secured = await SignRdfc(suite, key, Expiry);
        Pipeline.Verify(secured, publicKey, At(BeforeExpiry)).Verified.Should().BeTrue();
        Pipeline.Verify(secured, publicKey, At(AfterExpiry)).Verified.Should().BeFalse();

        Pipeline.Verify(OnProof(secured, RenameExpires), publicKey, At(AfterExpiry)).Verified.Should().BeFalse();
    }

    [Theory, MemberData(nameof(RdfcSuites))]
    public async Task Rdfc_ExpiredProofStaysExpiredWhenTheDocumentContextRenamesExpires(string suite)
    {
        var (key, publicKey) = RdfcKey(suite);
        var secured = await SignRdfc(suite, key, Expiry);
        Pipeline.Verify(secured, publicKey, At(BeforeExpiry)).Verified.Should().BeTrue();

        Pipeline.Verify(RenameExpiresThroughTheDocumentContext(secured), publicKey, At(AfterExpiry)).Verified.Should().BeFalse();
    }

    [Theory, MemberData(nameof(RdfcSuites))]
    public async Task Rdfc_AChallengeTheIssuerNeverSignedIsRefused(string suite)
    {
        var (key, publicKey) = RdfcKey(suite);
        var secured = await SignRdfc(suite, key);
        Pipeline.Verify(secured, publicKey).Verified.Should().BeTrue();

        Pipeline.Verify(OnProof(secured, InjectChallenge), publicKey, new ProofVerificationOptions { ExpectedChallenge = "abc" })
            .Verified.Should().BeFalse();
    }

    [Theory, MemberData(nameof(RdfcSuites))]
    public async Task Rdfc_ADomainTheIssuerNeverSignedIsRefused(string suite)
    {
        var (key, publicKey) = RdfcKey(suite);
        var secured = await SignRdfc(suite, key, domain: "a.example");
        Pipeline.Verify(secured, publicKey, new ProofVerificationOptions { ExpectedDomain = "a.example" }).Verified.Should().BeTrue();

        Pipeline.Verify(OnProof(secured, SwapDomain), publicKey, new ProofVerificationOptions { ExpectedDomain = "b.example" })
            .Verified.Should().BeFalse();
    }

    [Theory, MemberData(nameof(RdfcSuites))]
    public async Task Rdfc_APurposeTheIssuerNeverSignedIsRefused(string suite)
    {
        var (key, publicKey) = RdfcKey(suite);
        var secured = await SignRdfc(suite, key);
        Pipeline.Verify(secured, publicKey, new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod })
            .Verified.Should().BeTrue();

        Pipeline.Verify(OnProof(secured, SwapPurpose), publicKey, new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.Authentication })
            .Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task Bbs_ExpiredProofStaysExpiredWhenExpiresIsRenamed()
    {
        var (_, _, publicKey) = BbsKeys();
        var reveal = await DeriveBbs(Expiry);
        Pipeline.Verify(reveal, publicKey, At(BeforeExpiry)).Verified.Should().BeTrue();
        Pipeline.Verify(reveal, publicKey, At(AfterExpiry)).Verified.Should().BeFalse();

        Pipeline.Verify(OnProof(reveal, RenameExpires), publicKey, At(AfterExpiry)).Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task Bbs_ExpiredProofStaysExpiredWhenTheDocumentContextRenamesExpires()
    {
        var (_, _, publicKey) = BbsKeys();
        var reveal = await DeriveBbs(Expiry);
        Pipeline.Verify(reveal, publicKey, At(BeforeExpiry)).Verified.Should().BeTrue();

        Pipeline.Verify(RenameExpiresThroughTheDocumentContext(reveal), publicKey, At(AfterExpiry)).Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task Bbs_ExpiredProofStaysExpiredOnADocumentWithNoContext()
    {
        var (_, _, publicKey) = BbsKeys();
        var document = Parse("{\"https://x.example/a\":\"1\",\"https://x.example/b\":\"2\",\"https://x.example/c\":\"3\"}");
        var reveal = await DeriveBbs(
            document, BbsOptions(Expiry, context: Parse("\"" + V2 + "\"")), ["/https:~1~1x.example~1a"], ["/https:~1~1x.example~1b"]);
        Pipeline.Verify(reveal, publicKey, At(BeforeExpiry)).Verified.Should().BeTrue();

        Pipeline.Verify(OnProof(reveal, RenameExpires), publicKey, At(AfterExpiry)).Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task Bbs_AChallengeTheIssuerNeverSignedIsRefused()
    {
        var (_, _, publicKey) = BbsKeys();
        var reveal = await DeriveBbs();
        Pipeline.Verify(reveal, publicKey).Verified.Should().BeTrue();

        Pipeline.Verify(OnProof(reveal, InjectChallenge), publicKey, new ProofVerificationOptions { ExpectedChallenge = "abc" })
            .Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task Bbs_ADomainTheIssuerNeverSignedIsRefused()
    {
        var (_, _, publicKey) = BbsKeys();
        var reveal = await DeriveBbs(domain: "a.example");
        Pipeline.Verify(reveal, publicKey, new ProofVerificationOptions { ExpectedDomain = "a.example" }).Verified.Should().BeTrue();

        Pipeline.Verify(OnProof(reveal, SwapDomain), publicKey, new ProofVerificationOptions { ExpectedDomain = "b.example" })
            .Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task Bbs_APurposeTheIssuerNeverSignedIsRefused()
    {
        var (_, _, publicKey) = BbsKeys();
        var reveal = await DeriveBbs();
        Pipeline.Verify(reveal, publicKey, new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod })
            .Verified.Should().BeTrue();

        Pipeline.Verify(OnProof(reveal, SwapPurpose), publicKey, new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.Authentication })
            .Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task KnownContextsStillRefusesTheContextOnItsOwn()
    {
        var (_, _, publicKey) = BbsKeys();
        var reveal = await DeriveBbs(Expiry);

        var result = Pipeline.Verify(
            OnProof(reveal, RenameExpires), publicKey, new ProofVerificationOptions { VerificationTime = AfterExpiry, KnownContexts = [V2] });

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle(problem => problem.Message!.Contains("@context"));
    }
}
