using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using DataProofsDotnet.Jose.Signing;
using FluentAssertions;
using NetCrypto;
using Xunit;
using static DataProofsDotnet.Jose.Tests.X509.TestCertificates;
using Base64Url = DataProofsDotnet.Jose.Base64Url;

namespace DataProofsDotnet.Jose.Tests.X509;

/// <summary>
/// PR #56 review round 2. [P3] A schema-unknown SET was checked for SET OF order, so a valid DER SET in tag order (the
/// reviewer's private extension) was refused: the reader now applies to values without a known schema only the DER
/// rules that hold whatever the schema, and certificates carrying real-world extensions, validated by the platform,
/// parse. [P2] The malformed-x5c fixtures depended on random ECDSA signature lengths; assembled certificates are now
/// deterministic. Each test here fails on 50a2d09.
/// </summary>
public sealed class X5cReviewRound2Tests
{
    private static readonly JoseCryptoProvider Crypto = new();
    private static readonly byte[] Payload = """{"iss":"https://issuer.example"}"""u8.ToArray();

    /// <summary>The reviewer's value: SET { a [0] EXPLICIT INTEGER 1, b [1] IMPLICIT INTEGER 2 }, valid DER in tag order.</summary>
    private static readonly byte[] TagOrderedSet = [0x31, 0x08, 0xA0, 0x03, 0x02, 0x01, 0x01, 0x81, 0x01, 0x02];

    /// <summary>
    /// A platform-made end-entity certificate with digitalSignature Key Usage and the given extra extensions. With
    /// <paramref name="authorityKeyIdentifier"/>, the intermediate carries a subjectKeyIdentifier and the leaf an
    /// authorityKeyIdentifier naming it (key id, issuer and serial), as real issuers emit them: OpenSSL matches the AKI
    /// against the issuer when it builds the path, so an AKI naming another CA would leave the leaf without an issuer.
    /// </summary>
    private static (Pki Pki, byte[] Certificate) PlatformLeaf(string name, params X509Extension[] extensions)
        => PlatformLeaf(name, authorityKeyIdentifier: false, extensions);

    private static (Pki Pki, byte[] Certificate) PlatformLeaf(string name, bool authorityKeyIdentifier, params X509Extension[] extensions)
    {
        var pki = CreatePki(KeyType.P256, name);
        // Re-issue the end-entity for the same NetCrypto key with the extra extensions, under the same intermediate.
        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var intermediateRequest = new CertificateRequest($"CN={name} Intermediate", intermediateKey, HashAlgorithmName.SHA256);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        if (authorityKeyIdentifier)
            intermediateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(intermediateRequest.PublicKey, critical: false));
        var now = DateTimeOffset.UtcNow;
        using var intermediate = intermediateRequest.Create(pki.Root, now.AddDays(-1), now.AddYears(1), [0x11]);
        var jwk = pki.Leaf.PublicJwk;
        using var leafPublic = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = Base64Url.Decode(jwk.X!), Y = Base64Url.Decode(jwk.Y!) },
        });
        var request = new CertificateRequest($"CN={name} Issuer", leafPublic, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        foreach (var extension in extensions)
            request.CertificateExtensions.Add(extension);
        if (authorityKeyIdentifier)
        {
            request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
                intermediate, includeKeyIdentifier: true, includeIssuerAndSerial: true));
        }
        using var leaf = request.Create(intermediate.SubjectName, X509SignatureGenerator.CreateForECDsa(intermediateKey),
            now.AddDays(-1), now.AddMonths(6), [0x12]);
        return (pki with { Intermediate = X509CertificateLoader.LoadCertificate(intermediate.RawData) }, leaf.RawData);
    }

    /// <summary>The platform validates the chain to the anchor, the library reads it, and a JWS under it verifies.</summary>
    private static async Task ShouldBeAcceptedEndToEnd(Pki pki, byte[] leafCertificate)
    {
        var chain = X509CertificateChain.Create([leafCertificate, pki.Intermediate.RawData]);
        ValidateWithAnchors(chain, pki.Root).Should().BeTrue($"the platform accepts the chain ({PlatformStatus(chain, pki.Root)})");

        var signer = new JwsSigner(pki.Leaf.Signer.Signer) { CertificateChain = chain };
        var compact = await JwsBuilder.BuildCompactAsync(Payload, signer);
        JwsParser.ParseCompactWithCertificateChain(compact, c => ValidateWithAnchors(c, pki.Root), Crypto)
            .PayloadBytes.Should().Equal(Payload);
    }

    /// <summary>What the platform chain engine reports, for an assertion message.</summary>
    private static string PlatformStatus(X509CertificateChain chain, X509Certificate2 anchor)
    {
        using var platformChain = new X509Chain();
        platformChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        platformChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        platformChain.ChainPolicy.DisableCertificateDownloads = true;
        platformChain.ChainPolicy.CustomTrustStore.Add(anchor);
        foreach (var certificate in chain.Certificates.Skip(1))
            platformChain.ChainPolicy.ExtraStore.Add(X509CertificateLoader.LoadCertificate(certificate.Span));
        using var endEntity = X509CertificateLoader.LoadCertificate(chain.EndEntityCertificate.Span);
        platformChain.Build(endEntity);
        return string.Join("; ", platformChain.ChainStatus.Select(s => $"{s.Status}: {s.StatusInformation.Trim()}"));
    }

    private static byte[] Der(Action<AsnWriter> write)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        write(writer);
        return writer.Encode();
    }

    // ------------------------------------------------------------------ [P3] the reviewer's SET, and its neighbours

    [Fact]
    public async Task A_valid_DER_SET_in_tag_order_in_a_private_extension_is_accepted()
    {
        var (pki, leaf) = PlatformLeaf("TagOrderedSet", new X509Extension("1.2.3.4", TagOrderedSet, critical: false));

        await ShouldBeAcceptedEndToEnd(pki, leaf);
    }

    public static TheoryData<string, byte[]> SchemaUnknownValuesThatAreValidDer() => new()
    {
        // SET OF INTEGER in octet order, and a SET whose untagged-CHOICE component sorts by its least alternative's
        // tag (X.680 §8.6), so the encoded tags descend: neither order can be judged without the schema.
        { "a SET in neither encoded-tag nor octet order", [0x31, 0x06, 0x85, 0x01, 0x01, 0x83, 0x01, 0x02] },
        { "a SET OF INTEGER", [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02] },
        // EXTERNAL (UNIVERSAL 8) is always constructed: { direct-reference OID, octet-aligned [1] IMPLICIT OCTET STRING }.
        { "an EXTERNAL", [0x28, 0x0A, 0x06, 0x03, 0x2A, 0x03, 0x04, 0x81, 0x03, 0x01, 0x02, 0x03] },
        { "a BMPString and a UniversalString", [0x30, 0x0C, 0x1E, 0x02, 0x00, 0x41, 0x1C, 0x04, 0x00, 0x00, 0x00, 0x42, 0x14, 0x00] },
        { "a BIT STRING with trailing zero bits", [0x03, 0x02, 0x00, 0x00] },
        { "an application-class constructed value", [0x61, 0x03, 0x02, 0x01, 0x05] },
    };

    [Theory]
    [MemberData(nameof(SchemaUnknownValuesThatAreValidDer))]
    public async Task A_valid_DER_value_with_no_known_schema_is_accepted(string shape, byte[] value)
    {
        _ = shape;
        var (pki, leaf) = PlatformLeaf("Open", new X509Extension("1.2.3.4", value, critical: false));

        await ShouldBeAcceptedEndToEnd(pki, leaf);
    }

    public static TheoryData<string, byte[]> SchemaUnknownValuesThatNoSchemaAllows() => new()
    {
        { "a primitive SET", [0x11, 0x00] },
        { "a primitive EXTERNAL", [0x08, 0x00] },
        { "a constructed OCTET STRING", [0x24, 0x03, 0x04, 0x01, 0x00] },
        { "a constructed INTEGER", [0x22, 0x03, 0x02, 0x01, 0x00] },
        { "a BOOLEAN that is not 00 or FF", [0x01, 0x01, 0x01] },
        { "a non-minimal INTEGER", [0x02, 0x02, 0x00, 0x01] },
        { "a NULL with content", [0x05, 0x01, 0x00] },
        { "a BIT STRING with unused bits set", [0x03, 0x02, 0x01, 0x01] },
        { "an OID with a padded subidentifier", [0x06, 0x03, 0x2A, 0x80, 0x01] },
        { "a UTCTime without seconds", [0x17, 0x0B, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x5A] },
        { "an end-of-contents octet pair", [0x00, 0x00] },
        { "a long-form length that fits the short form", [0x04, 0x81, 0x01, 0x00] },
    };

    [Theory]
    [MemberData(nameof(SchemaUnknownValuesThatNoSchemaAllows))]
    public void A_value_no_DER_schema_allows_is_still_malformed(string shape, byte[] value)
    {
        _ = shape;
        var key = new DefaultKeyGenerator().Generate(KeyType.P256);
        var certificate = Assemble(Spki(key), withExtensions: false, tbsTail: w =>
        {
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true)))
            using (w.PushSequence())
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("1.2.3.4");
                w.WriteOctetString(value);
            }
        });

        var act = () => X509CertificateChain.Create([certificate]);

        act.Should().Throw<MalformedJoseException>().Which.Message.Should().StartWith("X5C_MALFORMED: ");
    }

    [Fact]
    public void An_RDN_SET_OF_out_of_DER_order_is_still_malformed()
    {
        // The Name's schema is known (RFC 5280: RDN ::= SET OF AttributeTypeAndValue), so its order is checked.
        var key = new DefaultKeyGenerator().Generate(KeyType.P256);
        byte[] unsorted = [0x30, 0x1A, 0x31, 0x18,
            0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x03, 0x5A, 0x5A, 0x5A,
            0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x03, 0x41, 0x41, 0x41];

        var act = () => X509CertificateChain.Create([Assemble(Spki(key), rawSubject: unsorted)]);

        act.Should().Throw<MalformedJoseException>().Which.Message.Should().StartWith("X5C_MALFORMED: ");
    }

    // ------------------------------------------------------------------ real-world extensions, platform-validated

    /// <summary>certificatePolicies: the EV policy with a CPS URI and a UserNotice, and an ETSI qualified policy.</summary>
    private static X509Extension CertificatePolicies() => new("2.5.29.32", Der(w =>
    {
        using (w.PushSequence())
        {
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("2.23.140.1.1"); // CA/B Forum EV
                using (w.PushSequence())
                {
                    using (w.PushSequence())
                    {
                        w.WriteObjectIdentifier("1.3.6.1.5.5.7.2.1"); // id-qt-cps
                        w.WriteCharacterString(UniversalTagNumber.IA5String, "https://ca.example/cps");
                    }
                    using (w.PushSequence())
                    {
                        w.WriteObjectIdentifier("1.3.6.1.5.5.7.2.2"); // id-qt-unotice
                        using (w.PushSequence())
                        {
                            using (w.PushSequence())
                            {
                                w.WriteCharacterString(UniversalTagNumber.UTF8String, "Example CA");
                                using (w.PushSequence())
                                {
                                    w.WriteInteger(1);
                                    w.WriteInteger(2);
                                }
                            }
                            w.WriteCharacterString(UniversalTagNumber.UTF8String, "Example EV policy");
                        }
                    }
                }
            }
            using (w.PushSequence())
                w.WriteObjectIdentifier("0.4.0.194112.1.1"); // ETSI QCP-l (qualified seal)
        }
    }), critical: false);

    /// <summary>qcStatements as an eIDAS qualified seal carries them (ETSI EN 319 412-5, RFC 3739).</summary>
    private static X509Extension QcStatements() => new("1.3.6.1.5.5.7.1.3", Der(w =>
    {
        using (w.PushSequence())
        {
            using (w.PushSequence())
                w.WriteObjectIdentifier("0.4.0.1862.1.1"); // QcCompliance
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("0.4.0.1862.1.6"); // QcType
                using (w.PushSequence())
                    w.WriteObjectIdentifier("0.4.0.1862.1.6.2"); // eseal
            }
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("0.4.0.1862.1.5"); // QcPDS
                using (w.PushSequence())
                using (w.PushSequence())
                {
                    w.WriteCharacterString(UniversalTagNumber.IA5String, "https://ca.example/pds-en.pdf");
                    w.WriteCharacterString(UniversalTagNumber.PrintableString, "en");
                }
            }
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("1.3.6.1.5.5.7.11.2"); // id-qcs-pkixQCSyntax-v2
                using (w.PushSequence())
                    w.WriteObjectIdentifier("0.4.0.194121.1.2"); // semantics: legal person
            }
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("0.4.0.1862.1.2"); // QcEuLimitValue
                using (w.PushSequence())
                {
                    w.WriteCharacterString(UniversalTagNumber.PrintableString, "EUR");
                    w.WriteInteger(1000);
                    w.WriteInteger(0);
                }
            }
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("0.4.0.1862.1.3"); // QcRetentionPeriod
                w.WriteInteger(15);
            }
        }
    }), critical: false);

    /// <summary>A Certificate Transparency SCT list (RFC 6962 §3.3): an OCTET STRING holding TLS-encoded bytes.</summary>
    private static X509Extension SignedCertificateTimestamps()
    {
        var sct = new List<byte> { 0x00 };                 // v1
        sct.AddRange(Enumerable.Range(0, 32).Select(i => (byte)i)); // log id
        sct.AddRange([0x00, 0x00, 0x01, 0x8B, 0x2C, 0x3D, 0x4E, 0x5F]); // timestamp
        sct.AddRange([0x00, 0x00]);                        // no extensions
        sct.AddRange([0x04, 0x03, 0x00, 0x04, 0x30, 0x02, 0x05, 0x00]); // sha256/ecdsa, a 4-byte "signature"
        var list = new List<byte> { 0x00, (byte)(sct.Count + 2), 0x00, (byte)sct.Count };
        list.AddRange(sct);
        return new X509Extension("1.3.6.1.4.1.11129.2.4.2", Der(w => w.WriteOctetString(list.ToArray())), critical: false);
    }

    private static X509Extension AuthorityInformationAccess() => new X509AuthorityInformationAccessExtension(
        ["http://ocsp.ca.example"], ["http://ca.example/issuing-ca.cer"], critical: false);

    private static X509Extension CrlDistributionPoints() => new("2.5.29.31", Der(w =>
    {
        using (w.PushSequence())
        using (w.PushSequence())
        using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
        using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
            w.WriteCharacterString(UniversalTagNumber.IA5String, "http://crl.ca.example/issuing.crl", new Asn1Tag(TagClass.ContextSpecific, 6));
    }), critical: false);

    private static X509Extension SubjectAlternativeNames()
    {
        var builder = new SubjectAlternativeNameBuilder();
        builder.AddDnsName("issuer.example");
        builder.AddEmailAddress("pki@issuer.example");
        builder.AddUri(new Uri("https://issuer.example/"));
        builder.AddIpAddress(IPAddress.Parse("192.0.2.1"));
        builder.AddIpAddress(IPAddress.Parse("2001:db8::1"));
        builder.AddUserPrincipalName("issuer@issuer.example");
        return builder.Build(critical: false);
    }

    [Fact]
    public async Task Certificates_with_real_world_extensions_are_accepted()
    {
        var (pki, leaf) = PlatformLeaf("RealWorld", authorityKeyIdentifier: true,
            CertificatePolicies(),
            QcStatements(),
            SignedCertificateTimestamps(),
            AuthorityInformationAccess(),
            CrlDistributionPoints(),
            SubjectAlternativeNames(),
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2")], critical: false),
            new X509SubjectKeyIdentifierExtension(Enumerable.Range(1, 20).Select(i => (byte)i).ToArray(), critical: false));

        await ShouldBeAcceptedEndToEnd(pki, leaf);
    }

    [Fact]
    public void Names_with_every_common_string_type_are_accepted()
    {
        // PrintableString C, UTF8String O, a BMPString OU, a TeletexString L, an IA5String email, a two-valued RDN.
        var subject = new X500DistinguishedName(Der(w =>
        {
            using (w.PushSequence())
            {
                Rdn(w, ("2.5.4.6", UniversalTagNumber.PrintableString, "DE"));
                Rdn(w, ("2.5.4.10", UniversalTagNumber.UTF8String, "Bundesdruckerei Ünïcødé"));
                Rdn(w, ("2.5.4.11", UniversalTagNumber.BMPString, "Qualified Seals"));
                Rdn(w, ("2.5.4.7", UniversalTagNumber.T61String, "Berlin"));
                Rdn(w, ("1.2.840.113549.1.9.1", UniversalTagNumber.IA5String, "pki@issuer.example"));
                Rdn(w, ("2.5.4.3", UniversalTagNumber.UTF8String, "Issuer"), ("2.5.4.97", UniversalTagNumber.UTF8String, "VATDE-123456789"));
            }
        }));
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = new CertificateRequest(subject, key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        X509CertificateChain.Create([certificate.RawData]).Certificates.Should().ContainSingle();

        static void Rdn(AsnWriter w, params (string Oid, UniversalTagNumber Type, string Value)[] attributes)
        {
            // DER SET OF order: write each attribute, sort the encodings, then the SET.
            var encodings = attributes.Select(a => Der(x =>
            {
                using (x.PushSequence())
                {
                    x.WriteObjectIdentifier(a.Oid);
                    x.WriteCharacterString(a.Type, a.Value);
                }
            })).OrderBy(e => Convert.ToHexString(e), StringComparer.Ordinal).ToList();
            using (w.PushSetOf())
            {
                foreach (var e in encodings)
                    w.WriteEncodedValue(e);
            }
        }
    }

    // ------------------------------------------------------------------ [P2] deterministic test certificates

    [Theory]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.Secp256k1)]
    public void Assembled_certificates_have_a_length_that_depends_only_on_their_inputs(KeyType keyType)
    {
        // The malformed-x5c fixtures pick certificates by length; with a randomized ECDSA signature the length varied
        // by up to two bytes, so a fixture could find no certificate of the length it needed (review round 2).
        var lengths = Enumerable.Range(0, 64).Select(_ => CreateLeaf(keyType).Certificate.Length).Distinct().ToList();

        lengths.Should().ContainSingle();
    }

    [Fact]
    public void The_malformed_x5c_fixtures_build_and_their_padded_certificate_has_padding()
    {
        var data = JwsX5cTests.MalformedX5cValues();

        data.Should().NotBeEmpty();
        JwsX5cTests.PaddedCertificate().Length.Should().NotBe(0).And.Match(n => n % 3 != 0);
    }
}
