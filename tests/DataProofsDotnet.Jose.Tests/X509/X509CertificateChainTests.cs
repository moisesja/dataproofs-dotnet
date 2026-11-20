using System.Diagnostics;
using System.Formats.Asn1;
using FluentAssertions;
using NetCrypto;
using Xunit;
using static DataProofsDotnet.Jose.Tests.X509.TestCertificates;

namespace DataProofsDotnet.Jose.Tests.X509;

/// <summary>
/// Issue #46: what <see cref="X509CertificateChain"/> accepts as a chain. Well-formed means 1 to
/// <see cref="X509CertificateChain.MaxCertificates"/> distinct DER certificates with nothing after each, and an
/// end-entity key the package verifies with; everything else is <c>X5C_MALFORMED</c> or <c>X5C_UNSUPPORTED_KEY</c>.
/// </summary>
public sealed class X509CertificateChainTests
{
    private static X509CertificateChain Create(params byte[][] certificates)
        => X509CertificateChain.Create(certificates.Select(c => new ReadOnlyMemory<byte>(c)).ToArray());

    private static void ShouldBeMalformed(Func<X509CertificateChain> create)
        => create.Should().Throw<MalformedJoseException>().Which.Message.Should().StartWith("X5C_MALFORMED: ");

    private static void ShouldBeUnsupported(Func<X509CertificateChain> create)
        => create.Should().Throw<NotSupportedException>().Which.Message.Should().StartWith("X5C_UNSUPPORTED_KEY: ");

    // ------------------------------------------------------------------ accepted

    [Theory]
    [InlineData(KeyType.Ed25519, false)]
    [InlineData(KeyType.P256, false)]
    [InlineData(KeyType.P256, true)]
    [InlineData(KeyType.P384, false)]
    [InlineData(KeyType.P384, true)]
    [InlineData(KeyType.Secp256k1, false)]
    [InlineData(KeyType.Secp256k1, true)]
    public void The_end_entity_key_is_read_from_the_first_certificate(KeyType keyType, bool compressed)
    {
        var leaf = CreateLeaf(keyType, compressed);

        var chain = Create(leaf.Certificate, RsaCertificate());

        var key = chain.EndEntityPublicKey;
        key.Kty.Should().Be(leaf.PublicJwk.Kty);
        key.Crv.Should().Be(leaf.PublicJwk.Crv);
        key.X.Should().Be(leaf.PublicJwk.X);
        key.Y.Should().Be(leaf.PublicJwk.Y);
        key.D.Should().BeNull();
        key.Kid.Should().BeNull();
    }

    [Fact]
    public void A_platform_made_chain_is_read_as_is()
    {
        var pki = CreatePki(KeyType.P256);

        var chain = Create(pki.Leaf.Certificate, pki.Intermediate.RawData, pki.Root.RawData);

        chain.Certificates.Should().HaveCount(3);
        chain.EndEntityCertificate.ToArray().Should().Equal(pki.Leaf.Certificate);
        chain.Certificates[1].ToArray().Should().Equal(pki.Intermediate.RawData);
        chain.Certificates[2].ToArray().Should().Equal(pki.Root.RawData);
        chain.EndEntityPublicKey.X.Should().Be(pki.Leaf.PublicJwk.X);
    }

    [Fact]
    public void Later_certificates_may_hold_any_key_type()
    {
        // Only the end-entity key is used; a CA's RSA (or P-521) key is the caller's path validation's business.
        var leaf = CreateLeaf(KeyType.P256);
        var p521 = Assemble(Spki(EcPublicKeyOid, P521Oid, [0x04, .. new byte[132]]), "P-521 CA");

        var chain = Create(leaf.Certificate, RsaCertificate(), p521);

        chain.Certificates.Should().HaveCount(3);
    }

    [Fact]
    public void The_chain_owns_copies_of_its_bytes_and_hands_out_fresh_keys()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var input = (byte[])leaf.Certificate.Clone();
        var chain = Create(input);

        input.AsSpan().Fill(0);
        var first = chain.EndEntityPublicKey;
        first.X = "tampered";

        chain.EndEntityCertificate.ToArray().Should().Equal(leaf.Certificate);
        chain.EndEntityPublicKey.X.Should().Be(leaf.PublicJwk.X);
        chain.EndEntityPublicKey.Should().NotBeSameAs(chain.EndEntityPublicKey);
    }

    [Fact]
    public void Exactly_MaxCertificates_certificates_are_accepted()
    {
        var leaf = CreateLeaf(KeyType.Ed25519);
        var cas = Enumerable.Range(0, X509CertificateChain.MaxCertificates - 1).Select(i => CaCertificate(i));

        var chain = Create([leaf.Certificate, .. cas]);

        chain.Certificates.Should().HaveCount(X509CertificateChain.MaxCertificates);
        X509CertificateChain.MaxCertificates.Should().Be(10);
    }

    [Fact]
    public void An_explicit_v1_version_and_a_certificate_without_version_or_extensions_are_read()
    {
        var key = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
        Create(Assemble(Spki(key), version: 0, withExtensions: false)).Should().NotBeNull();
        Create(Assemble(Spki(key), version: null, withExtensions: false)).Should().NotBeNull();
    }

    [Fact]
    public void An_explicit_critical_FALSE_is_tolerated_and_an_extension_without_a_value_is_not()
    {
        // X.690 §11.5 would omit a DEFAULT FALSE; certificate parsers generally tolerate it, and so does this one.
        var key = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
        Create(Assemble(Spki(key), withExtensions: false, tbsTail: w => Extensions(w, critical: false, withValue: true))).Should().NotBeNull();
        ShouldBeMalformed(() => Create(Assemble(Spki(key), withExtensions: false, tbsTail: w => Extensions(w, critical: null, withValue: false))));

        static void Extensions(AsnWriter w, bool? critical, bool withValue)
        {
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true)))
            using (w.PushSequence())
            using (w.PushSequence())
            {
                w.WriteObjectIdentifier("2.5.29.15");
                if (critical is { } c)
                    w.WriteBoolean(c);
                if (withValue)
                    w.WriteOctetString([0x03, 0x02, 0x07, 0x80]);
            }
        }
    }

    // ------------------------------------------------------------------ count, duplicates, null

    [Fact]
    public void No_certificate_is_malformed()
        => ShouldBeMalformed(() => Create());

    [Fact]
    public void More_than_MaxCertificates_is_malformed()
    {
        var leaf = CreateLeaf(KeyType.Ed25519);
        var cas = Enumerable.Range(0, X509CertificateChain.MaxCertificates).Select(CaCertificate);

        ShouldBeMalformed(() => Create([leaf.Certificate, .. cas]));
    }

    [Fact]
    public void A_repeated_certificate_is_malformed()
    {
        var leaf = CreateLeaf(KeyType.P256);
        var ca = RsaCertificate();

        ShouldBeMalformed(() => Create(leaf.Certificate, leaf.Certificate));
        ShouldBeMalformed(() => Create(leaf.Certificate, ca, ca));
    }

    [Fact]
    public void A_null_list_is_an_argument_error()
        => ((Func<X509CertificateChain>)(() => X509CertificateChain.Create(null!))).Should().Throw<ArgumentNullException>();

    // ------------------------------------------------------------------ DER structure

    public static TheoryData<string, byte[]> MalformedDer()
    {
        var key = new DefaultKeyGenerator().Generate(KeyType.P256);
        var spki = Spki(key);
        var good = Assemble(spki);

        // BER, not DER: the same certificate with its outer length in long form and with an indefinite length.
        var content = good.AsSpan(good[1] == 0x82 ? 4 : 3).ToArray();
        byte[] longForm = [0x30, 0x83, 0x00, (byte)(content.Length >> 8), (byte)content.Length, .. content];
        byte[] indefinite = [0x30, 0x80, .. content, 0x00, 0x00];

        var nested = DeepNest(10_000);

        return new TheoryData<string, byte[]>
        {
            { "empty", [] },
            { "one byte", [0x30] },
            { "not a SEQUENCE", [0x04, 0x02, 0x01, 0x02] },
            { "truncated", good[..^1] },
            { "a trailing byte", [.. good, 0x00] },
            { "two certificates in one entry", [.. good, .. good] },
            { "long-form outer length (BER)", longForm },
            { "indefinite outer length (BER)", indefinite },
            { "a deep nest of SEQUENCEs", nested },
            { "a SubjectPublicKeyInfo, not a certificate", spki },
            { "a fourth Certificate field", Wrap(w => { WriteFields(w, good); w.WriteNull(); }) },
            { "only two Certificate fields", Wrap(w => { var r = Fields(good); w.WriteEncodedValue(r[0]); w.WriteEncodedValue(r[1]); }) },
            { "version 3 (v4)", Assemble(spki, version: 3) },
            { "a field after the extensions", Assemble(spki, tbsTail: w => w.WriteNull()) },
            { "an empty extensions SEQUENCE", Assemble(spki, withExtensions: false, tbsTail: w =>
                {
                    using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true)))
                    using (w.PushSequence()) { }
                }) },
            { "fields out of RFC 5280 order", Sign(TbsWithSwappedNames(spki)) },
        };
    }

    [Theory]
    [MemberData(nameof(MalformedDer))]
    public void An_entry_that_is_not_one_DER_certificate_is_malformed(string shape, byte[] der)
    {
        _ = shape;
        var leaf = CreateLeaf(KeyType.P256);

        var stopwatch = Stopwatch.StartNew();
        ShouldBeMalformed(() => Create(der));
        ShouldBeMalformed(() => Create(leaf.Certificate, der));
        stopwatch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(2));
    }

    // ------------------------------------------------------------------ end-entity key

    public static TheoryData<string, byte[]> MalformedKeys()
    {
        // A fixed key, so the off-curve row is off the curve on every run (flipping a random y's low bit is only
        // overwhelmingly likely to leave the curve).
        var p256 = new DefaultKeyGenerator().FromPrivateKey(KeyType.P256, Enumerable.Repeat((byte)0x47, 32).ToArray());
        var jwk = JwkConversion.ToPublicJwk(p256.KeyType, p256.PublicKey);
        var x = Base64Url.Decode(jwk.X!);
        var y = Base64Url.Decode(jwk.Y!);
        var offCurveY = (byte[])y.Clone();
        offCurveY[^1] ^= 0x01;
        var ed = new DefaultKeyGenerator().Generate(KeyType.Ed25519).PublicKey.ToArray();
        var nullParameters = new byte[] { 0x05, 0x00 };

        return new TheoryData<string, byte[]>
        {
            { "EC key without parameters", Spki(EcPublicKeyOid, null, [0x04, .. x, .. y]) },
            { "EC key with NULL parameters", Spki(EcPublicKeyOid, null, [0x04, .. x, .. y], rawParameters: nullParameters) },
            { "EC key with specified-curve parameters", Spki(EcPublicKeyOid, null, [0x04, .. x, .. y], rawParameters: [0x30, 0x03, 0x02, 0x01, 0x01]) },
            { "EC key with unused bits", Spki(EcPublicKeyOid, P256Oid, [0x04, .. x, .. y[..^1], (byte)(y[^1] & 0xFE)], unusedBits: 1) },
            { "EC point one byte short", Spki(EcPublicKeyOid, P256Oid, [0x04, .. x, .. y[..^1]]) },
            { "EC point of the wrong curve size", Spki(EcPublicKeyOid, P384Oid, [0x04, .. x, .. y]) },
            { "EC hybrid point form", Spki(EcPublicKeyOid, P256Oid, [0x06, .. x, .. y]) },
            { "EC point at infinity", Spki(EcPublicKeyOid, P256Oid, [0x00]) },
            { "EC point off the curve", Spki(EcPublicKeyOid, P256Oid, [0x04, .. x, .. offCurveY]) },
            { "EC compressed x with no point", Spki(EcPublicKeyOid, P256Oid, [0x02, .. Enumerable.Repeat((byte)0xFF, 32)]) },
            { "Ed25519 key with parameters", Spki(Ed25519Oid, P256Oid, ed) },
            { "Ed25519 key of 31 bytes", Spki(Ed25519Oid, null, ed[..^1]) },
            { "Ed25519 key with unused bits", Spki(Ed25519Oid, null, [.. ed[..^1], (byte)(ed[^1] & 0xFC)], unusedBits: 2) },
        };
    }

    [Theory]
    [MemberData(nameof(MalformedKeys))]
    public void An_end_entity_key_that_is_not_a_valid_encoding_is_malformed(string shape, byte[] spki)
    {
        _ = shape;
        ShouldBeMalformed(() => Create(Assemble(spki)));
    }

    public static TheoryData<string, byte[]> UnsupportedKeys()
    {
        using var rsa = RSA.Create(2048);
        return new TheoryData<string, byte[]>
        {
            { "RSA", rsa.ExportSubjectPublicKeyInfo() },
            { "P-521", Spki(EcPublicKeyOid, P521Oid, [0x04, .. new byte[132]]) },
            { "brainpoolP256r1", Spki(EcPublicKeyOid, "1.3.36.3.3.2.8.1.1.7", [0x04, .. new byte[64]]) },
            { "Ed448", Spki("1.3.101.113", null, new byte[57]) },
            { "X25519", Spki("1.3.101.110", null, new byte[32]) },
            { "id-ecDH", Spki("1.3.132.1.12", P256Oid, [0x04, .. new byte[64]]) },
        };
    }

    [Theory]
    [MemberData(nameof(UnsupportedKeys))]
    public void An_end_entity_key_no_supported_algorithm_uses_is_unsupported(string shape, byte[] spki)
    {
        _ = shape;
        ShouldBeUnsupported(() => Create(Assemble(spki)));
    }

    // ------------------------------------------------------------------ helpers

    private static byte[] CaCertificate(int i)
        => Assemble(Spki(new DefaultKeyGenerator().Generate(KeyType.Ed25519)), $"CA {i}");

    /// <summary><paramref name="depth"/> DER SEQUENCEs, each holding the next, around a NULL; written outside in.</summary>
    internal static byte[] DeepNest(int depth)
    {
        var lengths = new int[depth + 1];
        lengths[0] = 2; // 05 00
        for (var k = 1; k <= depth; k++)
            lengths[k] = lengths[k - 1] + 1 + LengthOctets(lengths[k - 1]);
        var bytes = new byte[lengths[depth]];
        var at = 0;
        for (var k = depth; k >= 1; k--)
        {
            bytes[at++] = 0x30;
            var length = lengths[k - 1];
            var octets = LengthOctets(length);
            if (octets == 1)
            {
                bytes[at++] = (byte)length;
            }
            else
            {
                bytes[at++] = (byte)(0x80 | (octets - 1));
                for (var i = octets - 2; i >= 0; i--)
                    bytes[at++] = (byte)(length >> (8 * i));
            }
        }
        bytes[at++] = 0x05;
        bytes[at] = 0x00;
        return bytes;

        static int LengthOctets(int length) => length < 0x80 ? 1 : length < 0x100 ? 2 : length < 0x10000 ? 3 : 4;
    }

    private static byte[] Wrap(Action<AsnWriter> fields)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
            fields(writer);
        return writer.Encode();
    }

    private static List<byte[]> Fields(byte[] certificate)
    {
        var reader = new AsnReader(certificate, AsnEncodingRules.DER).ReadSequence();
        var fields = new List<byte[]>();
        while (reader.HasData)
            fields.Add(reader.ReadEncodedValue().ToArray());
        return fields;
    }

    private static void WriteFields(AsnWriter writer, byte[] certificate)
    {
        foreach (var field in Fields(certificate))
            writer.WriteEncodedValue(field);
    }

    /// <summary>A TBSCertificate whose validity and subject trade places.</summary>
    private static byte[] TbsWithSwappedNames(byte[] spki)
    {
        var tbsFields = Fields(Fields(Assemble(spki))[0]);
        // [0] version, [1] serial, [2] signature, [3] issuer, [4] validity, [5] subject, [6] spki, [7] extensions
        (tbsFields[4], tbsFields[5]) = (tbsFields[5], tbsFields[4]);
        return Wrap(w => tbsFields.ForEach(f => w.WriteEncodedValue(f)));
    }
}
