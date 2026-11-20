using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.SdJwt.Vc;
using DataProofsDotnet.Jose.Signing;
using FluentAssertions;
using NetCrypto;
using Xunit;
using static DataProofsDotnet.Jose.Tests.X509.TestCertificates;
using Base64Url = DataProofsDotnet.Jose.Base64Url;

namespace DataProofsDotnet.Jose.Tests.X509;

/// <summary>
/// Issue #46 on SD-JWT and SD-JWT VC: the Issuer's chain rides in the issuer JWT's protected header, and the Inline
/// X.509 Certificates mechanism of draft-ietf-oauth-sd-jwt-vc-27 §2.5 verifies with the end-entity key, then the
/// caller's hook, then the Disclosures, Key Binding and profile rules. Failures are coded results, never throws.
/// </summary>
public sealed class SdJwtX5cTests
{
    private const string Vct = "https://credentials.example.com/identity_credential";
    private const string Audience = "https://verifier.example.org";
    private const string Nonce = "n-0S6_WzA2Mj";

    private static JsonObject Claims() => new()
    {
        ["vct"] = Vct,
        ["given_name"] = "Erika",
        ["family_name"] = "Mustermann",
    };

    private static DisclosureFrame Frame() => new DisclosureFrame().Disclose("given_name").Disclose("family_name");

    private static async Task<string> IssueVc(JwsSigner signer, SdJwtIssuerOptions? options = null)
        => (await SdJwtVcIssuer.IssueAsync(Claims(), Frame(), signer, options)).Issuance;

    /// <summary>An SD-JWT VC issuer JWT over any protected header, signed by <paramref name="signer"/>, with no Disclosures.</summary>
    private static async Task<string> IssueWithHeader(JsonObject header, JwsSigner signer)
    {
        var payload = new JsonObject { ["vct"] = Vct, ["_sd_alg"] = "sha-256" };
        var protectedB64u = Base64Url.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadB64u = Base64Url.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var signature = await signer.SignAsync(Encoding.ASCII.GetBytes(protectedB64u + "." + payloadB64u), CancellationToken.None);
        return protectedB64u + "." + payloadB64u + "." + Base64Url.Encode(signature) + "~";
    }

    private static void ShouldFail(SdJwtVcVerificationResult result, string code)
    {
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith(code + ":");
        result.IssuerCertificateChain.Should().BeNull();
        result.DisclosedPayload.Should().BeNull();
    }

    private static void ShouldFail(SdJwtVerificationResult result, string code)
    {
        result.IsValid.Should().BeFalse();
        result.Errors.Should().ContainSingle().Which.Should().StartWith(code + ":");
        result.IssuerCertificateChain.Should().BeNull();
    }

    // ------------------------------------------------------------------ round trips

    [Fact]
    public async Task An_SD_JWT_VC_issued_with_a_chain_verifies_against_the_callers_anchor()
    {
        var pki = CreatePki(KeyType.P256);
        var issuance = await IssueVc(pki.SignerWithChain());

        var header = JsonNode.Parse(Base64Url.Decode(issuance.Split('.')[0]))!.AsObject();
        header["typ"]!.GetValue<string>().Should().Be("dc+sd-jwt");
        header["x5c"]!.AsArray().Should().HaveCount(2);

        var result = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(issuance, chain => ValidateWithAnchors(chain, pki.Root));

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.Vct.Should().Be(Vct);
        result.DisclosedPayload!["given_name"]!.GetValue<string>().Should().Be("Erika");
        result.IssuerCertificateChain!.EndEntityCertificate.ToArray().Should().Equal(pki.Leaf.Certificate);
        result.TypeMetadata.Should().BeNull();
        result.ProcessedTypeMetadata.Should().BeNull();
    }

    [Fact]
    public async Task Key_Binding_works_under_the_X509_mechanism()
    {
        var pki = CreatePki(KeyType.P256);
        var holder = CreateLeaf(KeyType.P256);
        var issued = await SdJwtVcIssuer.IssueAsync(Claims(), Frame(), pki.SignerWithChain(),
            new SdJwtIssuerOptions { HolderConfirmationKey = holder.PublicJwk });
        var presentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
            issued.Issuance, [issued.Disclosures[0].Encoded], holder.Signer, Audience, Nonce);
        var options = new SdJwtVerificationOptions { RequireKeyBinding = true, ExpectedAudience = Audience, ExpectedNonce = Nonce };

        var result = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(presentation, chain => ValidateWithAnchors(chain, pki.Root), options);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.KeyBindingVerified.Should().BeTrue();
        result.DisclosedPayload!.ContainsKey("family_name").Should().BeFalse();
    }

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.Secp256k1)]
    public async Task Every_v1_key_type_round_trips_through_the_generic_SD_JWT_verifier(KeyType keyType)
    {
        var leaf = CreateLeaf(keyType);
        var signer = new JwsSigner(leaf.Signer.Signer) { CertificateChain = X509CertificateChain.Create([leaf.Certificate]) };
        var issued = await SdJwtIssuer.IssueAsync(Claims(), Frame(), signer, typ: "example+sd-jwt");

        var calls = new List<X509CertificateChain>();
        var result = SdJwtVerifier.VerifyWithCertificateChain(issued.Issuance, chain =>
        {
            calls.Add(chain);
            return chain.EndEntityCertificate.Span.SequenceEqual(leaf.Certificate);
        });

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.SignatureAlgorithm.Should().Be(signer.Algorithm);
        calls.Should().ContainSingle().Which.Should().BeSameAs(result.IssuerCertificateChain);
    }

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.Secp256k1)]
    public async Task Every_v1_key_type_round_trips_through_the_SD_JWT_VC_verifier(KeyType keyType)
    {
        var leaf = CreateLeaf(keyType);
        var signer = new JwsSigner(leaf.Signer.Signer) { CertificateChain = X509CertificateChain.Create([leaf.Certificate]) };
        var issuance = await IssueVc(signer);

        var calls = new List<X509CertificateChain>();
        var result = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(issuance, chain =>
        {
            calls.Add(chain);
            return chain.EndEntityCertificate.Span.SequenceEqual(leaf.Certificate);
        });

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.Vct.Should().Be(Vct);
        calls.Should().ContainSingle().Which.Should().BeSameAs(result.IssuerCertificateChain);
    }

    [Fact]
    public async Task The_kid_methods_accept_a_malformed_x5c_as_they_always_did()
    {
        // Before issue #46 an x5c of any shape was an ignored header member; the kid paths still never read it.
        var leaf = CreateLeaf(KeyType.Ed25519);
        foreach (var x5c in new JsonNode?[] { 42, "garbage", new JsonArray(), new JsonArray((JsonNode)1, (JsonNode)2), null })
        {
            var issuance = await IssueWithHeader(
                new JsonObject { ["alg"] = "EdDSA", ["typ"] = "dc+sd-jwt", ["kid"] = "k1", ["x5c"] = x5c?.DeepClone() }, leaf.Signer);
            var document = Encoding.UTF8.GetBytes(new JsonObject { ["vct"] = Vct }.ToJsonString());
            var typeMetadata = new TypeMetadataProcessingOptions(
                new LocalCacheTypeMetadataDocumentResolver(new Dictionary<string, byte[]> { [Vct] = document }));

            SdJwtVerifier.Verify(issuance, _ => leaf.PublicJwk).IsValid.Should().BeTrue();
            (await SdJwtVcVerifier.VerifyAsync(issuance, _ => leaf.PublicJwk)).IsValid.Should().BeTrue();
            var processed = await SdJwtVcVerifier.VerifyWithTypeMetadataAsync(issuance, _ => leaf.PublicJwk, typeMetadata);
            processed.IsValid.Should().BeTrue(string.Join("; ", processed.Errors));
            processed.IssuerCertificateChain.Should().BeNull();
        }
    }

    [Fact]
    public async Task Type_Metadata_is_processed_under_the_X509_mechanism_when_asked()
    {
        var pki = CreatePki(KeyType.P256);
        var issuance = await IssueVc(pki.SignerWithChain());
        var document = Encoding.UTF8.GetBytes(new JsonObject
        {
            ["vct"] = Vct,
            ["name"] = "Identity",
            ["claims"] = new JsonArray((JsonNode)new JsonObject { ["path"] = new JsonArray((JsonNode)"given_name"), ["sd"] = "always" }),
        }.ToJsonString());
        var typeMetadata = new TypeMetadataProcessingOptions(
            new LocalCacheTypeMetadataDocumentResolver(new Dictionary<string, byte[]> { [Vct] = document }));

        var result = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(
            issuance, chain => ValidateWithAnchors(chain, pki.Root), typeMetadata: typeMetadata);

        result.IsValid.Should().BeTrue(string.Join("; ", result.Errors));
        result.ProcessedTypeMetadata.Should().NotBeNull();
        result.IssuerCertificateChain.Should().NotBeNull();

        var violating = Encoding.UTF8.GetBytes(new JsonObject
        {
            ["vct"] = Vct,
            ["claims"] = new JsonArray((JsonNode)new JsonObject { ["path"] = new JsonArray((JsonNode)"given_name"), ["sd"] = "never" }),
        }.ToJsonString());
        var refused = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(issuance, chain => ValidateWithAnchors(chain, pki.Root),
            typeMetadata: new TypeMetadataProcessingOptions(new LocalCacheTypeMetadataDocumentResolver(new Dictionary<string, byte[]> { [Vct] = violating })));
        ShouldFail(refused, "VC_CLAIM_SD_VIOLATION");
    }

    [Fact]
    public async Task The_kid_methods_never_read_x5c()
    {
        var pki = CreatePki(KeyType.P256);
        var issuance = await IssueVc(pki.SignerWithChain("issuer-key-1"));

        var vc = await SdJwtVcVerifier.VerifyAsync(issuance, kid => kid == "issuer-key-1" ? pki.Leaf.PublicJwk : null);
        var sd = SdJwtVerifier.Verify(issuance, _ => pki.Leaf.PublicJwk);

        vc.IsValid.Should().BeTrue();
        vc.IssuerCertificateChain.Should().BeNull();
        sd.IsValid.Should().BeTrue();
        sd.IssuerCertificateChain.Should().BeNull();
    }

    // ------------------------------------------------------------------ the trust decision

    [Fact]
    public async Task A_chain_the_hook_refuses_is_X5C_UNTRUSTED()
    {
        var pki = CreatePki(KeyType.P256, "Issuer");
        var other = CreatePki(KeyType.P256, "Other");
        var issuance = await IssueVc(pki.SignerWithChain());

        ShouldFail(await SdJwtVcVerifier.VerifyWithCertificateChainAsync(issuance, chain => ValidateWithAnchors(chain, other.Root)), "X5C_UNTRUSTED");
        ShouldFail(SdJwtVerifier.VerifyWithCertificateChain(issuance, _ => false), "X5C_UNTRUSTED");
    }

    [Fact]
    public async Task A_root_carried_in_x5c_is_not_an_anchor_under_the_recommended_hook()
    {
        var pki = CreatePki(KeyType.P256, "Issuer");
        var signer = new JwsSigner(pki.Leaf.Signer.Signer)
        {
            CertificateChain = X509CertificateChain.Create([pki.Leaf.Certificate, pki.Intermediate.RawData, pki.Root.RawData]),
        };
        var issuance = await IssueVc(signer);

        ShouldFail(await SdJwtVcVerifier.VerifyWithCertificateChainAsync(issuance, chain => ValidateWithAnchors(chain)), "X5C_UNTRUSTED");
    }

    [Fact]
    public async Task Type_Metadata_is_not_retrieved_for_an_untrusted_chain()
    {
        var pki = CreatePki(KeyType.P256);
        var issuance = await IssueVc(pki.SignerWithChain());
        var resolver = new CountingResolver();

        var result = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(
            issuance, _ => false, typeMetadata: new TypeMetadataProcessingOptions(resolver));

        ShouldFail(result, "X5C_UNTRUSTED");
        resolver.Calls.Should().Be(0);
    }

    [Fact]
    public async Task The_hook_is_not_called_when_the_signature_does_not_verify()
    {
        var a = CreateLeaf(KeyType.P256);
        var b = CreateLeaf(KeyType.P256);
        var forged = await IssueWithHeader(new JsonObject
        {
            ["alg"] = "ES256",
            ["typ"] = "dc+sd-jwt",
            ["x5c"] = new JsonArray((JsonNode)Convert.ToBase64String(a.Certificate)),
        }, b.Signer);
        var calls = 0;

        ShouldFail(await SdJwtVcVerifier.VerifyWithCertificateChainAsync(forged, _ => { calls++; return true; }), "ISSUER_SIGNATURE_INVALID");
        ShouldFail(SdJwtVerifier.VerifyWithCertificateChain(forged, _ => { calls++; return true; }), "ISSUER_SIGNATURE_INVALID");
        calls.Should().Be(0);
    }

    [Fact]
    public async Task A_hook_exception_propagates()
    {
        var leaf = CreateLeaf(KeyType.Ed25519);
        var signer = new JwsSigner(leaf.Signer.Signer) { CertificateChain = X509CertificateChain.Create([leaf.Certificate]) };
        var issuance = await IssueVc(signer);

        var act = () => SdJwtVcVerifier.VerifyWithCertificateChainAsync(issuance, _ => throw new TimeoutException("OCSP"));

        await act.Should().ThrowAsync<TimeoutException>();
    }

    [Fact]
    public async Task A_kid_beside_x5c_selects_nothing()
    {
        // The kid names some other key; under the X.509 mechanism only x5c[0] is used, and it verifies.
        var leaf = CreateLeaf(KeyType.Ed25519);
        var signer = new JwsSigner(leaf.Signer.Signer, "did:example:someone-else#key-1")
        {
            CertificateChain = X509CertificateChain.Create([leaf.Certificate]),
        };
        var issuance = await IssueVc(signer);

        var result = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(issuance, _ => true);

        result.IsValid.Should().BeTrue();
        result.IssuerCertificateChain.Should().NotBeNull();
    }

    // ------------------------------------------------------------------ the codes

    [Fact]
    public async Task An_issuer_JWT_without_x5c_is_X5C_MISSING()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var issuance = await IssueVc(new JwsSigner(leaf.Signer.Signer, "k1"));

        ShouldFail(await SdJwtVcVerifier.VerifyWithCertificateChainAsync(issuance, _ => true), "X5C_MISSING");
        ShouldFail(SdJwtVerifier.VerifyWithCertificateChain(issuance, _ => true), "X5C_MISSING");
    }

    [Theory]
    [InlineData("\"MIIB\"")]
    [InlineData("[]")]
    [InlineData("[7]")]
    [InlineData("[\"bm90IGEgY2VydA==\"]")]
    [InlineData("null")]
    public async Task A_malformed_x5c_is_X5C_MALFORMED(string x5c)
    {
        var leaf = CreateLeaf(KeyType.P256);
        var issuance = await IssueWithHeader(new JsonObject { ["alg"] = "ES256", ["typ"] = "dc+sd-jwt", ["x5c"] = JsonNode.Parse(x5c) }, leaf.Signer);

        ShouldFail(await SdJwtVcVerifier.VerifyWithCertificateChainAsync(issuance, _ => true), "X5C_MALFORMED");
        ShouldFail(SdJwtVerifier.VerifyWithCertificateChain(issuance, _ => true), "X5C_MALFORMED");
    }

    [Fact]
    public async Task An_RSA_end_entity_is_X5C_UNSUPPORTED_KEY()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var issuance = await IssueWithHeader(new JsonObject
        {
            ["alg"] = "RS256",
            ["typ"] = "dc+sd-jwt",
            ["x5c"] = new JsonArray((JsonNode)Convert.ToBase64String(RsaCertificate("RSA issuer"))),
        }, leaf.Signer);

        ShouldFail(await SdJwtVcVerifier.VerifyWithCertificateChainAsync(issuance, _ => true), "X5C_UNSUPPORTED_KEY");
        ShouldFail(SdJwtVerifier.VerifyWithCertificateChain(issuance, _ => true), "X5C_UNSUPPORTED_KEY");
    }

    [Fact]
    public async Task A_wrong_typ_is_refused_before_the_chain_is_read()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var issuance = await IssueWithHeader(new JsonObject { ["alg"] = "ES256", ["typ"] = "vc+sd-jwt", ["x5c"] = 7 }, leaf.Signer);

        ShouldFail(await SdJwtVcVerifier.VerifyWithCertificateChainAsync(issuance, _ => true), "VC_MEDIA_TYPE_INVALID");
    }

    [Fact]
    public async Task Null_arguments_are_argument_errors()
    {
        var verifyVc = () => SdJwtVcVerifier.VerifyWithCertificateChainAsync("x~", null!);
        var verifySd = () => SdJwtVerifier.VerifyWithCertificateChain("x~", null!);
        var verifyEmpty = () => SdJwtVerifier.VerifyWithCertificateChain("", _ => true);

        await verifyVc.Should().ThrowAsync<ArgumentNullException>();
        verifySd.Should().Throw<ArgumentNullException>();
        verifyEmpty.Should().Throw<ArgumentException>();
    }

    private sealed class CountingResolver : ITypeMetadataDocumentResolver
    {
        public int Calls { get; private set; }

        public Task<byte[]?> ResolveDocumentAsync(string reference, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult<byte[]?>(null);
        }
    }
}
