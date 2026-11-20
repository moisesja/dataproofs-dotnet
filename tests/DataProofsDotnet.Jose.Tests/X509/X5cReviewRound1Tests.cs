using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.SdJwt.Vc;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.SdJwt;
using FluentAssertions;
using NetCrypto;
using Xunit;
using static DataProofsDotnet.Jose.Tests.X509.TestCertificates;
using Base64Url = DataProofsDotnet.Jose.Base64Url;

namespace DataProofsDotnet.Jose.Tests.X509;

/// <summary>
/// PR #56 review round 1. [P2] A trusted end-entity certificate whose Key Usage does not permit digital signatures
/// (RFC 5280 §4.2.1.3) verified a JWS, an SD-JWT and an SD-JWT VC; the library now refuses it with
/// <c>X5C_KEY_USAGE</c> before using the key, whatever the hook does. [P3] Name and other nested encodings were skipped
/// unread; every TLV of the certificate, down to attribute values, algorithm parameters and extension values, is now
/// read under DER rules. Each test here fails on 188471f.
/// </summary>
public sealed class X5cReviewRound1Tests
{
    private const string Vct = "https://credentials.example.com/identity_credential";
    private static readonly JoseCryptoProvider Crypto = new();
    private static readonly byte[] Payload = """{"iss":"https://issuer.example"}"""u8.ToArray();

    // ------------------------------------------------------------------ helpers

    private static async Task<string> CompactWith(JsonObject header, JwsSigner signer, byte[] payload)
    {
        var protectedB64u = Base64Url.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadB64u = Base64Url.Encode(payload);
        var signature = await signer.SignAsync(Encoding.ASCII.GetBytes(protectedB64u + "." + payloadB64u), CancellationToken.None);
        return protectedB64u + "." + payloadB64u + "." + Base64Url.Encode(signature);
    }

    private static JsonArray X5c(params byte[][] certificates)
        => new(certificates.Select(c => (JsonNode?)JsonValue.Create(Convert.ToBase64String(c))).ToArray());

    /// <summary>A compact JWS, an SD-JWT and an SD-JWT VC carrying <paramref name="x5c"/>, honestly signed by <paramref name="signer"/>.</summary>
    private static async Task<(string Jws, string SdJwt, string SdJwtVc)> Tokens(JwsSigner signer, JsonArray x5c)
    {
        var jws = await CompactWith(new JsonObject { ["alg"] = signer.Algorithm, ["x5c"] = x5c.DeepClone() }, signer, Payload);
        var sdPayload = Encoding.UTF8.GetBytes(new JsonObject { ["vct"] = Vct, ["_sd_alg"] = "sha-256" }.ToJsonString());
        var sdJwt = await CompactWith(new JsonObject { ["alg"] = signer.Algorithm, ["typ"] = "example+sd-jwt", ["x5c"] = x5c.DeepClone() }, signer, sdPayload) + "~";
        var vc = await CompactWith(new JsonObject { ["alg"] = signer.Algorithm, ["typ"] = "dc+sd-jwt", ["x5c"] = x5c.DeepClone() }, signer, sdPayload) + "~";
        return (jws, sdJwt, vc);
    }

    private static async Task ShouldFailOnAllThree(JwsSigner signer, JsonArray x5c, string code, Func<X509CertificateChain, bool> hook)
    {
        var (jws, sdJwt, vc) = await Tokens(signer, x5c);
        var hookCalls = 0;
        bool Counting(X509CertificateChain chain) { hookCalls++; return hook(chain); }

        var jwsAct = () => JwsParser.ParseCompactWithCertificateChain(jws, Counting, Crypto);
        jwsAct.Should().Throw<JoseException>().Which.Message.Should().StartWith(code + ": ");

        var sd = SdJwtVerifier.VerifyWithCertificateChain(sdJwt, Counting);
        sd.IsValid.Should().BeFalse();
        sd.Errors.Should().ContainSingle().Which.Should().StartWith(code + ": ");

        var vcResult = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(vc, Counting);
        vcResult.IsValid.Should().BeFalse();
        vcResult.Errors.Should().ContainSingle().Which.Should().StartWith(code + ": ");

        hookCalls.Should().Be(0, "the library refuses before the trust hook runs");
    }

    private static async Task ShouldVerifyOnAllThree(JwsSigner signer, JsonArray x5c, Func<X509CertificateChain, bool> hook)
    {
        var (jws, sdJwt, vc) = await Tokens(signer, x5c);
        JwsParser.ParseCompactWithCertificateChain(jws, hook, Crypto).CertificateChain.Should().NotBeNull();
        var sd = SdJwtVerifier.VerifyWithCertificateChain(sdJwt, hook);
        sd.IsValid.Should().BeTrue(string.Join("; ", sd.Errors));
        var vcResult = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(vc, hook);
        vcResult.IsValid.Should().BeTrue(string.Join("; ", vcResult.Errors));
    }

    /// <summary>A keyUsage extension with the given encoded bits (named bits, DER), optionally twice.</summary>
    private static Action<AsnWriter> KeyUsageExtension(byte[] bits, int unusedBits, bool twice = false, bool critical = true)
        => w =>
        {
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true)))
            using (w.PushSequence())
            {
                for (var i = 0; i < (twice ? 2 : 1); i++)
                {
                    using (w.PushSequence())
                    {
                        w.WriteObjectIdentifier("2.5.29.15");
                        if (critical)
                            w.WriteBoolean(true);
                        var value = new AsnWriter(AsnEncodingRules.DER);
                        value.WriteBitString(bits, unusedBits);
                        w.WriteOctetString(value.Encode());
                    }
                }
            }
        };

    private static Leaf AssembledLeaf(KeyType keyType, Action<AsnWriter> extensions)
    {
        var key = new DefaultKeyGenerator().Generate(keyType);
        var certificate = Assemble(Spki(key), withExtensions: false, tbsTail: extensions);
        return new Leaf(key, new JwsSigner(new KeyPairSigner(key, new DefaultCryptoProvider())), certificate);
    }

    private static void ShouldBeMalformed(params byte[][] certificates)
    {
        var act = () => X509CertificateChain.Create(certificates.Select(c => new ReadOnlyMemory<byte>(c)).ToArray());
        act.Should().Throw<MalformedJoseException>().Which.Message.Should().StartWith("X5C_MALFORMED: ");
    }

    // ------------------------------------------------------------------ [P2] Key Usage

    [Fact]
    public async Task A_trusted_key_agreement_only_end_entity_is_refused_on_all_three_APIs()
    {
        // The reviewer's reproduction: an otherwise valid leaf, CA-signed, chaining to the verifier's anchor, whose only
        // (critical) Key Usage is keyAgreement. The platform's path validation accepts it: Key Usage is the purpose of
        // the key, which only the party using it can check.
        var pki = CreatePki(KeyType.P256, "KeyAgreement", leafKeyUsage: X509KeyUsageFlags.KeyAgreement);
        var x5c = X5c(pki.Leaf.Certificate, pki.Intermediate.RawData);
        var platformAccepts = ValidateWithAnchors(
            X509CertificateChain.Create([pki.Leaf.Certificate, pki.Intermediate.RawData]), pki.Root);
        platformAccepts.Should().BeTrue("the chain itself is valid; only the key's purpose is wrong");

        await ShouldFailOnAllThree(pki.Leaf.Signer, x5c, "X5C_KEY_USAGE", chain => ValidateWithAnchors(chain, pki.Root));
    }

    [Fact]
    public void A_signer_refuses_a_chain_whose_end_entity_may_not_sign()
    {
        var pki = CreatePki(KeyType.P256, "KeyAgreementSigner", leafKeyUsage: X509KeyUsageFlags.KeyAgreement);
        var chain = X509CertificateChain.Create([pki.Leaf.Certificate, pki.Intermediate.RawData]);

        var act = () => new JwsSigner(pki.Leaf.Signer.Signer) { CertificateChain = chain };

        act.Should().Throw<ArgumentException>().Which.Message.Should().StartWith("X5C_KEY_USAGE: ");
    }

    public static TheoryData<string, byte[], int> RefusedKeyUsages() => new()
    {
        { "keyAgreement", [0x08], 3 },                    // bit 4
        { "keyEncipherment", [0x20], 5 },                 // bit 2
        { "contentCommitment (nonRepudiation) only", [0x40], 6 }, // bit 1
        { "keyCertSign and cRLSign (a CA key)", [0x06], 1 }, // bits 5 and 6
        { "no bit at all", [], 0 },
    };

    [Theory]
    [MemberData(nameof(RefusedKeyUsages))]
    public async Task An_end_entity_Key_Usage_without_digitalSignature_is_X5C_KEY_USAGE(string usage, byte[] bits, int unusedBits)
    {
        _ = usage;
        var leaf = AssembledLeaf(KeyType.Ed25519, KeyUsageExtension(bits, unusedBits));

        await ShouldFailOnAllThree(leaf.Signer, X5c(leaf.Certificate), "X5C_KEY_USAGE", _ => true);
    }

    [Fact]
    public async Task A_non_critical_Key_Usage_restricts_the_key_too()
    {
        var leaf = AssembledLeaf(KeyType.Ed25519, KeyUsageExtension([0x08], 3, critical: false));

        await ShouldFailOnAllThree(leaf.Signer, X5c(leaf.Certificate), "X5C_KEY_USAGE", _ => true);
    }

    [Theory]
    [InlineData(new byte[] { 0x80 }, 7)]       // digitalSignature
    [InlineData(new byte[] { 0x88 }, 3)]       // digitalSignature + keyAgreement
    [InlineData(new byte[] { 0xC0 }, 6)]       // digitalSignature + contentCommitment
    public async Task An_end_entity_Key_Usage_with_digitalSignature_verifies(byte[] bits, int unusedBits)
    {
        var leaf = AssembledLeaf(KeyType.Ed25519, KeyUsageExtension(bits, unusedBits));

        await ShouldVerifyOnAllThree(leaf.Signer, X5c(leaf.Certificate), _ => true);
    }

    [Fact]
    public async Task An_end_entity_without_Key_Usage_verifies()
    {
        // RFC 5280 §4.2.1.3 makes the extension optional; without it the key's purpose is unrestricted.
        var leaf = AssembledLeaf(KeyType.Ed25519, _ => { });

        await ShouldVerifyOnAllThree(leaf.Signer, X5c(leaf.Certificate), _ => true);
    }

    [Fact]
    public void A_repeated_extension_or_a_Key_Usage_that_is_not_a_BIT_STRING_is_malformed()
    {
        // RFC 5280 §4.2: "A certificate MUST NOT include more than one instance of a particular extension."
        var key = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
        ShouldBeMalformed(Assemble(Spki(key), withExtensions: false, tbsTail: KeyUsageExtension([0x80], 7, twice: true)));
        ShouldBeMalformed(Assemble(Spki(key), withExtensions: false, tbsTail: w =>
        {
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true)))
            using (w.PushSequence())
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("2.5.29.15");
                w.WriteOctetString([0x04, 0x01, 0x80]); // an OCTET STRING where the BIT STRING belongs
            }
        }));
    }

    [Fact]
    public void Key_Usage_restricts_only_the_end_entity()
    {
        // A CA certificate's keyCertSign-only usage is path validation's business; the chain is built.
        var leaf = CreateLeaf(KeyType.P256);
        var ca = Assemble(Spki(new DefaultKeyGenerator().Generate(KeyType.P256)), "CA", withExtensions: false,
            tbsTail: KeyUsageExtension([0x06], 1));

        X509CertificateChain.Create([leaf.Certificate, ca]).Certificates.Should().HaveCount(2);
    }

    // ------------------------------------------------------------------ [P3] every TLV, strictly

    public static TheoryData<string, byte[]> MalformedNames() => new()
    {
        { "a SEQUENCE holding a truncated SET (the reviewer's 30 02 31 01)", [0x30, 0x02, 0x31, 0x01] },
        { "an empty RelativeDistinguishedName", [0x30, 0x02, 0x31, 0x00] },
        { "a SEQUENCE in place of an RDN's SET", [0x30, 0x04, 0x30, 0x02, 0x05, 0x00] },
        { "an attribute without a value", [0x30, 0x09, 0x31, 0x07, 0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x03] },
        { "an attribute type that is not an OID", [0x30, 0x0A, 0x31, 0x08, 0x30, 0x06, 0x02, 0x01, 0x01, 0x0C, 0x01, 0x41] },
        { "an attribute with a third field", [0x30, 0x0E, 0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x01, 0x41, 0x05, 0x00] },
        { "an attribute value with a truncated inner TLV", [0x30, 0x0D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x30, 0x02, 0x31, 0x01] },
        { "an attribute value that is a constructed UTF8String", [0x30, 0x0E, 0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x2C, 0x03, 0x0C, 0x01, 0x41] },
        { "an attribute value INTEGER with a redundant leading zero", [0x30, 0x0D, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x02, 0x02, 0x00, 0x01] },
        { "a multi-valued RDN out of DER order", [0x30, 0x1A, 0x31, 0x18, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x03, 0x5A, 0x5A, 0x5A, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x03, 0x41, 0x41, 0x41] },
    };

    [Theory]
    [MemberData(nameof(MalformedNames))]
    public void A_malformed_issuer_or_subject_Name_is_malformed(string shape, byte[] name)
    {
        _ = shape;
        var key = new DefaultKeyGenerator().Generate(KeyType.P256);

        ShouldBeMalformed(Assemble(Spki(key), rawIssuer: name));
        ShouldBeMalformed(Assemble(Spki(key), rawSubject: name));
        // In a CA position too: every certificate in x5c is read the same way.
        ShouldBeMalformed(CreateLeaf(KeyType.P256).Certificate, Assemble(Spki(key), "CA", rawSubject: name));
    }

    [Fact]
    public async Task The_reviewers_malformed_Name_never_reaches_signing_or_the_hook()
    {
        var key = new DefaultKeyGenerator().Generate(KeyType.P256);
        var certificate = Assemble(Spki(key), rawIssuer: [0x30, 0x02, 0x31, 0x01]);
        var signer = new JwsSigner(new KeyPairSigner(key, new DefaultCryptoProvider()));

        await ShouldFailOnAllThree(signer, X5c(certificate), "X5C_MALFORMED", _ => true);
    }

    [Fact]
    public void Empty_names_and_multi_valued_RDNs_in_DER_order_are_read()
    {
        var key = new DefaultKeyGenerator().Generate(KeyType.P256);
        byte[] empty = [0x30, 0x00];
        byte[] multiValued = [0x30, 0x1A, 0x31, 0x18,
            0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x03, 0x41, 0x41, 0x41,
            0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x03, 0x5A, 0x5A, 0x5A];

        X509CertificateChain.Create([Assemble(Spki(key), rawSubject: empty)]).Should().NotBeNull();
        X509CertificateChain.Create([Assemble(Spki(key), rawSubject: multiValued)]).Should().NotBeNull();
    }

    public static TheoryData<string, byte[]> MalformedAlgorithmIdentifiers() => new()
    {
        { "parameters with a truncated inner TLV", [0x30, 0x0E, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30, 0x02, 0x31, 0x01] },
        { "a BOOLEAN parameter that is not 00 or FF", [0x30, 0x0D, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x01, 0x01, 0x01] },
        { "a NULL parameter with content", [0x30, 0x0D, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x05, 0x01, 0x00] },
        { "a primitive SEQUENCE parameter", [0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x10, 0x00] },
    };

    [Theory]
    [MemberData(nameof(MalformedAlgorithmIdentifiers))]
    public void A_malformed_algorithm_parameter_is_malformed(string shape, byte[] algorithmIdentifier)
    {
        _ = shape;
        var key = new DefaultKeyGenerator().Generate(KeyType.P256);
        ShouldBeMalformed(Assemble(Spki(key), rawSignatureAlgorithm: algorithmIdentifier));

        // The same parameters on a CA's public key algorithm.
        var reader = new AsnReader(algorithmIdentifier, AsnEncodingRules.DER).ReadSequence();
        reader.ReadObjectIdentifier();
        var parameters = reader.ReadEncodedValue().ToArray();
        var caSpki = Spki("1.2.840.113549.1.1.1", null, [0x30, 0x03, 0x02, 0x01, 0x03], rawParameters: parameters);
        ShouldBeMalformed(CreateLeaf(KeyType.P256).Certificate, Assemble(caSpki, "CA"));
    }

    public static TheoryData<string, byte[]> MalformedExtensionValues() => new()
    {
        { "not one TLV (trailing bytes)", [0x30, 0x00, 0x05, 0x00] },
        { "a truncated TLV", [0x30, 0x03, 0x01, 0x01] },
        { "empty", [] },
        { "a BOOLEAN that is not 00 or FF", [0x30, 0x03, 0x01, 0x01, 0x01] },
        { "nested deeper than 32 levels", X509CertificateChainTests.DeepNest(40) },
    };

    [Theory]
    [MemberData(nameof(MalformedExtensionValues))]
    public void An_extension_value_that_is_not_one_DER_TLV_is_malformed(string shape, byte[] value)
    {
        _ = shape;
        var key = new DefaultKeyGenerator().Generate(KeyType.P256);
        ShouldBeMalformed(Assemble(Spki(key), withExtensions: false, tbsTail: w =>
        {
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true)))
            using (w.PushSequence())
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("2.5.29.19"); // basicConstraints
                w.WriteOctetString(value);
            }
        }));
    }

    [Fact]
    public void The_RFC_7515_Appendix_B_chain_is_well_formed_and_its_RSA_end_entity_unsupported()
    {
        // A real-world chain (Go Daddy / ValiCert, RSA, extensions of every common kind): the structural reading does
        // not refuse it; only the end-entity's RSA key is outside the v1 algorithms.
        using var fixture = SdJwtFixtureSupport.Load("rfc7515", "appendix-b-x5c.json");
        var certificates = fixture.RootElement.GetProperty("x5c").EnumerateArray()
            .Select(e => new ReadOnlyMemory<byte>(Convert.FromBase64String(e.GetString()!))).ToArray();
        certificates.Should().HaveCount(3);

        var act = () => X509CertificateChain.Create(certificates);

        act.Should().Throw<NotSupportedException>().Which.Message.Should().StartWith("X5C_UNSUPPORTED_KEY: ");
    }
}
