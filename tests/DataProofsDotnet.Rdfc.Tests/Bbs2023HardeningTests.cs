using System.Formats.Cbor;
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
/// bbs-2023 hardening from the adversarial review of the conformance rework (PR #42): pointers that
/// fail open, a derivation that never checked the base signature, malformed proof values that leaked
/// raw exceptions, explicit blank-node identifiers refused with the wrong reason, and a derived proof
/// that carried a <c>@context</c> the reference omits.
/// </summary>
public sealed class Bbs2023HardeningTests
{
    private const string Vectors = "TestVectors";
    private const string V2 = "https://www.w3.org/ns/credentials/v2";
    private const string PointerMismatch = "A JSON pointer does not match the document.";
    private const string UnusableSignature = "The base proof's BBS signature could not be used to derive a proof.";
    private const string AlteredHeader = "The base proof's BBS header does not match the document and proof configuration: a mandatory value or the proof was altered after signing.";
    private const string MalformedBase = "The base proofValue is not a valid bbs-2023 base proof.";
    private const string HmacKeyLength = "The bbs-2023 HMAC key must be 32 bytes.";
    private const string MalformedDerived = "The proofValue is not a valid bbs-2023 derived proof.";

    private static readonly byte[] Header = Convert.FromHexString("113377aa");

    private static JsonElement Vector(string name) => Fx.Json("w3c", "vc-di-bbs", Vectors, name);

    private static (byte[] Sk, byte[] HmacKey) KeyMaterial()
    {
        var keyMaterial = Vector("BBSKeyMaterial.json");
        return (
            Convert.FromHexString(keyMaterial.GetProperty("privateKeyHex").GetString()!),
            Convert.FromHexString(keyMaterial.GetProperty("hmacKeyString").GetString()!));
    }

    private static PublicKeyMaterial PublicKey(byte[] sk)
        => PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk).PublicKey);

    private static DataIntegrityProof Options() => new()
    {
        Type = DataIntegrityProof.DataIntegrityProofType,
        Cryptosuite = Bbs2023Cryptosuite.CryptosuiteName,
        Created = "2026-10-30T00:00:00Z",
        VerificationMethod = "did:example:issuer#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    private static string[] WindMandatory() => JsonSerializer.Deserialize<string[]>(Fx.Text("w3c", "vc-di-bbs", Vectors, "windMandatory.json"))!;

    private static async Task<JsonElement> SecuredAsync(Bbs2023Cryptosuite suite, JsonElement document, string[] mandatory, byte[] sk, byte[] hmacKey)
    {
        var baseProof = await suite.CreateBaseProofAsync(document, Options(), sk, hmacKey, mandatory);
        return Fx.Mutate(document, d => d["proof"] = JsonSerializer.SerializeToNode(baseProof, DataProofsJsonOptions.Default));
    }

    private static (DataIntegrityProof Proof, JsonElement Unsecured) Split(JsonElement secured)
        => (secured.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!,
            Fx.Mutate(secured, document => document.Remove("proof")));

    // ------------------------------------------------------------------ pointers

    [BbsFact]
    public async Task MandatoryPointer_ThatMatchesNothing_IsRefusedAtCreation()
    {
        // It used to be skipped, leaving nothing mandatory: an issuer's "mandatory" claim silently unenforced.
        var (sk, hmacKey) = KeyMaterial();

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(Vector("windDoc.json"), Options(), sk, hmacKey, ["/issuer", "/nope"]);

        (await act.Should().ThrowAsync<ProofGenerationException>()).WithMessage(PointerMismatch);
    }

    [BbsFact]
    public async Task MandatoryPointer_Invalid_IsRefusedAtCreation()
    {
        // Creation leaked ArgumentException / ArgumentNullException; the documented exception is ProofGenerationException.
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();

        foreach (var pointers in new[] { new[] { "nope" }, new string[] { null! } })
        {
            var act = () => suite.CreateBaseProofAsync(Vector("windDoc.json"), Options(), sk, hmacKey, pointers);
            (await act.Should().ThrowAsync<ProofGenerationException>()).WithMessage("A mandatory pointer is invalid.");
        }
    }

    [BbsFact]
    public async Task EmptyPointer_SelectsTheWholeDocument()
    {
        // RFC 6901: "" is the whole document, so everything is mandatory and nothing is left to sign.
        var (sk, hmacKey) = KeyMaterial();

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(Vector("windDoc.json"), Options(), sk, hmacKey, [""]);

        (await act.Should().ThrowAsync<ProofGenerationException>()).WithMessage("bbs-2023 needs at least one non-mandatory statement*");
    }

    [BbsFact]
    public async Task SelectivePointer_ThatMatchesNothing_IsRefusedAtDerivation()
    {
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await SecuredAsync(suite, Vector("windDoc.json"), WindMandatory(), sk, hmacKey);

        var act = () => suite.DeriveProof(secured, ["/credentialSubject/nope"], Header);

        act.Should().Throw<ProofGenerationException>().WithMessage(PointerMismatch);
    }

    // ------------------------------------------------------------------ the base proof at derivation

    [BbsTheory]
    [InlineData("a selectively disclosable value")]
    [InlineData("a mandatory value")]
    [InlineData("the proof's created date")]
    public async Task BaseDocumentAlteredAfterSigning_IsRefusedAtDerivation(string what)
    {
        // BBS proof generation checks nothing, so a holder used to derive a proof over an altered
        // document and only learn at verification that it could never verify. The recomputed header
        // catches a mandatory value, the proof configuration and, through the reshuffled blank-node
        // labels, most other changes; the signature check catches the rest. Either names the base proof.
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await SecuredAsync(suite, Vector("windDoc.json"), WindMandatory(), sk, hmacKey);
        var altered = Fx.Mutate(secured, document =>
        {
            switch (what)
            {
                case "a mandatory value":
                    document["issuer"] = "https://evil.example/";
                    break;
                case "the proof's created date":
                    document["proof"]!["created"] = "2027-01-01T00:00:00Z";
                    break;
                default:
                    document["credentialSubject"]!["sails"]![0]!["size"] = 5.6;
                    break;
            }
        });

        var act = () => suite.DeriveProof(altered, ["/credentialSubject/sails/0"], Header);

        act.Should().Throw<ProofGenerationException>().Which.Message.Should().BeOneOf(UnusableSignature, AlteredHeader);
    }

    [BbsTheory]
    [InlineData(10, 32)]
    [InlineData(64, 0)]
    public async Task BaseProof_WithAShortHeaderOrHmacKey_IsMalformed(int headerLength, int hmacKeyLength)
    {
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await SecuredAsync(suite, Vector("windDoc.json"), WindMandatory(), sk, hmacKey);
        var honest = Bbs2023ProofValue.ParseBaseProof(secured.GetProperty("proof").GetProperty("proofValue").GetString()!);
        var malformed = Bbs2023ProofValue.SerializeBaseProof(
            honest.BbsSignature, honest.BbsHeader.AsSpan(0, headerLength), honest.PublicKey, hmacKey.AsSpan(0, hmacKeyLength), honest.MandatoryPointers);
        var tampered = Fx.Mutate(secured, document => document["proof"]!["proofValue"] = malformed);

        var act = () => suite.DeriveProof(tampered, ["/credentialSubject/sails/0"], Header);

        act.Should().Throw<ProofGenerationException>().WithMessage(MalformedBase);
    }

    // ------------------------------------------------------------------ the HMAC key

    [Theory]
    [InlineData(0)]
    [InlineData(16)]
    [InlineData(31)]
    [InlineData(33)]
    [InlineData(64)]
    public async Task HmacKey_OfAnotherLength_IsRefusedAtIssuance(int length)
    {
        // Not a BbsTheory: the refusal comes before anything reaches the BBS provider. The parser would
        // otherwise refuse the returned proof only when the holder derives from it.
        var (sk, _) = KeyMaterial();

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(Vector("windDoc.json"), Options(), sk, new byte[length], WindMandatory());

        await act.Should().ThrowAsync<ProofGenerationException>().WithMessage(HmacKeyLength);
    }

    [BbsFact]
    public async Task HmacKey_Of32Bytes_IssuesDerivesAndVerifies()
    {
        var (sk, _) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await SecuredAsync(suite, Vector("windDoc.json"), ["/issuer"], sk, new byte[32]);

        var (proof, unsecured) = Split(suite.DeriveProof(secured, ["/credentialSubject/sails/0"], Header));

        suite.VerifyProof(unsecured, proof, PublicKey(sk)).Verified.Should().BeTrue();
    }

    // ------------------------------------------------------------------ blank node identifiers

    [BbsFact]
    public async Task ExplicitBlankNodeIdentifiers_AreKeptAndVerify()
    {
        // The document names its subject _:cs and refers to one friend node twice. The skolemizer keeps
        // the identifiers (as the reference does), so the shared node stays one node.
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var document = JsonDocument.Parse("{\"@context\":[\"" + V2 + "\",{\"@vocab\":\"https://e.example/vocab#\"}],"
            + "\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:issuer\","
            + "\"credentialSubject\":{\"id\":\"_:cs\",\"name\":\"Ann\",\"friend\":{\"id\":\"_:f\",\"name\":\"Bob\"},\"rival\":{\"id\":\"_:f\"}}}").RootElement.Clone();
        var secured = await SecuredAsync(suite, document, ["/issuer"], sk, hmacKey);

        var reveal = suite.DeriveProof(secured, ["/credentialSubject/friend/name"], Header);
        var (proof, unsecured) = Split(reveal);

        reveal.GetRawText().Should().NotContain("urn:bnid");
        suite.VerifyProof(unsecured, proof, PublicKey(sk)).Verified.Should().BeTrue();
        suite.VerifyProof(Fx.Mutate(unsecured, d => d["credentialSubject"]!["friend"]!["name"] = "Mallory"), proof, PublicKey(sk))
            .Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task BlankNodeIdentifierAsAPlainValue_IsRefusedWithThatReason()
    {
        // Compact JSON cannot tell "_:b0" under an @id-coerced term from a string, so the blank node
        // survives skolemization unnamed; the refusal names that case.
        var (sk, hmacKey) = KeyMaterial();
        var document = JsonDocument.Parse("{\"@context\":[\"" + V2 + "\",{\"knows\":{\"@id\":\"https://e.example/vocab#knows\",\"@type\":\"@id\"}}],"
            + "\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:issuer\",\"credentialSubject\":{\"id\":\"did:example:alice\",\"knows\":\"_:b0\"}}").RootElement.Clone();

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(document, Options(), sk, hmacKey, ["/issuer"]);

        (await act.Should().ThrowAsync<ProofGenerationException>())
            .WithInnerException<JsonLdDataLossException>().WithMessage("*blank node identifier used as a plain value*");
    }

    [BbsFact]
    public async Task NestedProperties_AreRefusedAsSkolemizationThatWouldChangeTheDocument()
    {
        // The skolemizer adds an @id inside a @nest object, which is invalid JSON-LD; the document as
        // written canonicalizes, so the refusal names skolemization rather than "could not be canonicalized".
        var (sk, hmacKey) = KeyMaterial();
        var document = JsonDocument.Parse("{\"@context\":[\"" + V2 + "\",{\"@vocab\":\"https://e.example/vocab#\",\"details\":\"@nest\"}],"
            + "\"type\":\"VerifiableCredential\",\"issuer\":\"did:example:issuer\",\"credentialSubject\":{\"id\":\"did:example:alice\",\"details\":{\"shoeSize\":42}}}").RootElement.Clone();

        var act = () => new Bbs2023Cryptosuite().CreateBaseProofAsync(document, Options(), sk, hmacKey, ["/issuer"]);

        (await act.Should().ThrowAsync<ProofGenerationException>())
            .WithInnerException<JsonLdDataLossException>().WithMessage("*skolemization would change it*");
    }

    // ------------------------------------------------------------------ the derived proof

    [BbsFact]
    public async Task DerivedProof_CarriesNoContext_AndVerificationBorrowsTheDocuments()
    {
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await SecuredAsync(suite, Vector("windDoc.json"), WindMandatory(), sk, hmacKey);

        var reveal = suite.DeriveProof(secured, ["/credentialSubject/sails/0"], Header);
        var (proof, unsecured) = Split(reveal);

        reveal.GetProperty("proof").TryGetProperty("@context", out _).Should().BeFalse("the reference's derived proof carries none");
        proof.Context.Should().BeNull();
        suite.VerifyProof(unsecured, proof, PublicKey(sk)).Verified.Should().BeTrue();
    }

    [BbsFact]
    public async Task DerivedProof_MalformedComponents_AreNotAValidDerivedProof()
    {
        // These used to surface as "Verification failed unexpectedly (OverflowException)" and the
        // like; a proofValue the parser cannot read is a malformed derived proof.
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await SecuredAsync(suite, Vector("windDoc.json"), WindMandatory(), sk, hmacKey);
        var reveal = suite.DeriveProof(secured, ["/credentialSubject/sails/0"], Header);
        var (proof, unsecured) = Split(reveal);
        var honest = Bbs2023ProofValue.ParseDerivedProof(proof.ProofValue!);

        var truncated = Bbs2023ProofValue.SerializeDerivedProof(
            honest.BbsProof.AsSpan(0, 10), honest.LabelMap, honest.MandatoryIndexes, honest.SelectiveIndexes, honest.PresentationHeader);
        var oversized = Crafted(writer =>
        {
            writer.WriteStartArray(5);
            writer.WriteByteString(honest.BbsProof);
            writer.WriteStartMap(0);
            writer.WriteEndMap();
            writer.WriteStartArray(1);
            writer.WriteUInt64(5_000_000_000);
            writer.WriteEndArray();
            writer.WriteStartArray(0);
            writer.WriteEndArray();
            writer.WriteByteString(honest.PresentationHeader);
            writer.WriteEndArray();
        });
        var textual = Crafted(writer =>
        {
            writer.WriteStartArray(5);
            writer.WriteByteString(honest.BbsProof);
            writer.WriteStartMap(1);
            writer.WriteTextString("c14n0");
            writer.WriteTextString("b0");
            writer.WriteEndMap();
            writer.WriteStartArray(0);
            writer.WriteEndArray();
            writer.WriteStartArray(0);
            writer.WriteEndArray();
            writer.WriteByteString(honest.PresentationHeader);
            writer.WriteEndArray();
        });

        foreach (var proofValue in new[] { truncated, oversized, textual })
        {
            var result = suite.VerifyProof(unsecured, proof with { ProofValue = proofValue }, PublicKey(sk));
            result.Verified.Should().BeFalse();
            result.Problems.Should().ContainSingle().Which.Message.Should().Be(MalformedDerived);
        }
    }

    [BbsFact]
    public async Task DerivedProof_DuplicateSelectiveIndex_FailsWithThatReason()
    {
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await SecuredAsync(suite, Vector("windDoc.json"), WindMandatory(), sk, hmacKey);
        var reveal = suite.DeriveProof(secured, ["/credentialSubject/sails/0"], Header);
        var (proof, unsecured) = Split(reveal);
        var honest = Bbs2023ProofValue.ParseDerivedProof(proof.ProofValue!);
        honest.SelectiveIndexes.Count.Should().BeGreaterThan(1);
        var duplicated = honest.SelectiveIndexes.Take(honest.SelectiveIndexes.Count - 1).Append(honest.SelectiveIndexes[0]).ToList();
        var repacked = Bbs2023ProofValue.SerializeDerivedProof(
            honest.BbsProof, honest.LabelMap, honest.MandatoryIndexes, duplicated, honest.PresentationHeader);

        var result = suite.VerifyProof(unsecured, proof with { ProofValue = repacked }, PublicKey(sk));

        result.Verified.Should().BeFalse();
        result.Problems.Should().ContainSingle().Which.Message.Should().Contain("selective indexes are not distinct");
    }

    private static string Crafted(Action<CborWriter> write)
    {
        var writer = new CborWriter();
        write(writer);
        var cbor = writer.Encode();
        var bytes = new byte[3 + cbor.Length];
        bytes[0] = 0xd9;
        bytes[1] = 0x5d;
        bytes[2] = 0x03;
        cbor.CopyTo(bytes, 3);
        return NetCid.Multibase.Encode(bytes, NetCid.MultibaseEncoding.Base64Url);
    }
}
