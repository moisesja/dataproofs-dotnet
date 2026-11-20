using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;
using Base64Url = DataProofsDotnet.Jose.Base64Url;

namespace DataProofsDotnet.Jose.Tests.X509;

/// <summary>
/// Certificates for the issue #46 tests. Two kinds: real chains made by the platform's <see cref="CertificateRequest"/>
/// (P-256 / P-384 end-entity keys, validated by <see cref="X509Chain"/> in the hooks, as a consumer would), and
/// certificates assembled here field by field with <see cref="AsnWriter"/>, for the key types the platform cannot
/// certify (Ed25519, secp256k1) and for every malformed shape. The library under test never validates a chain, so the
/// signature on an assembled certificate is a real ECDSA signature by <see cref="AssemblyCa"/> but is never checked.
/// </summary>
internal static class TestCertificates
{
    private static readonly IKeyGenerator Generator = new DefaultKeyGenerator();
    private static readonly NetCrypto.ICryptoProvider NetCryptoProvider = new DefaultCryptoProvider();
    private static int _serial = 1000;

    public const string EcPublicKeyOid = "1.2.840.10045.2.1";
    public const string Ed25519Oid = "1.3.101.112";
    public const string P256Oid = "1.2.840.10045.3.1.7";
    public const string P384Oid = "1.3.132.0.34";
    public const string P521Oid = "1.3.132.0.35";
    public const string Secp256k1Oid = "1.3.132.0.10";

    /// <summary>
    /// The Ed25519 key that signs every assembled certificate, from a fixed seed. Ed25519 signatures are deterministic
    /// and always 64 bytes, so an assembled certificate's bytes, and so its length, depend only on its inputs (PR #56
    /// review round 2: a randomized ECDSA signature made the length vary, and a fixture that needed a length could fail).
    /// </summary>
    private static readonly KeyPairSigner AssemblyCa =
        new(Generator.FromPrivateKey(KeyType.Ed25519, Enumerable.Repeat((byte)0x46, 32).ToArray()), NetCryptoProvider);

    /// <summary>The fixed validity of assembled certificates: no clock reaches into their bytes.</summary>
    private static readonly DateTimeOffset AssembledNotBefore = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset AssembledNotAfter = new(2036, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>A NetCrypto key pair, the JWS signer over it, and the end-entity certificate holding its public key.</summary>
    public sealed record Leaf(KeyPair Key, JwsSigner Signer, byte[] Certificate)
    {
        public Jwk PublicJwk => JwkConversion.ToPublicJwk(Key.KeyType, Key.PublicKey);
    }

    /// <summary>A platform-made PKI: a self-signed root, an intermediate, and an end-entity certificate for a NetCrypto key.</summary>
    public sealed record Pki(X509Certificate2 Root, X509Certificate2 Intermediate, Leaf Leaf)
    {
        /// <summary>The <c>x5c</c> a conformant issuer sends: end-entity, then intermediate; the root is the verifier's anchor.</summary>
        public X509CertificateChain Chain => X509CertificateChain.Create([Leaf.Certificate, Intermediate.RawData]);

        public JwsSigner SignerWithChain(string? kid = null)
            => new(new KeyPairSigner(Leaf.Key, NetCryptoProvider), kid) { CertificateChain = Chain };
    }

    // ------------------------------------------------------------------------------------------ platform-made chains

    /// <summary>Root → intermediate → end-entity, the end-entity certifying a fresh NetCrypto key of <paramref name="keyType"/>.</summary>
    public static Pki CreatePki(KeyType keyType = KeyType.P256, string name = "Example", DateTimeOffset? leafNotAfter = null,
        X509KeyUsageFlags? leafKeyUsage = X509KeyUsageFlags.DigitalSignature)
    {
        var now = DateTimeOffset.UtcNow;
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest($"CN={name} Root", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var root = rootRequest.CreateSelfSigned(now.AddDays(-2), now.AddYears(5));

        using var intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var intermediateRequest = new CertificateRequest($"CN={name} Intermediate", intermediateKey, HashAlgorithmName.SHA256);
        intermediateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        intermediateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var intermediateWithKey = intermediateRequest.Create(root, now.AddDays(-1), now.AddYears(2), NextSerial());
        var intermediate = X509CertificateLoader.LoadCertificate(intermediateWithKey.RawData);

        var key = Generator.Generate(keyType);
        using var leafPublic = PlatformPublicKey(key);
        var leafRequest = new CertificateRequest($"CN={name} Issuer", leafPublic, keyType == KeyType.P384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        if (leafKeyUsage is { } usage)
            leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(usage, true));
        using var leaf = leafRequest.Create(
            intermediate.SubjectName, X509SignatureGenerator.CreateForECDsa(intermediateKey),
            now.AddDays(-1), leafNotAfter ?? now.AddYears(1), NextSerial());

        return new Pki(root, intermediate, new Leaf(key, new JwsSigner(new KeyPairSigner(key, NetCryptoProvider)), leaf.RawData));
    }

    /// <summary>
    /// The recommended hook: RFC 5280 path validation by the platform, the caller's anchors in the custom trust store,
    /// every <c>x5c</c> certificate only in the extra store (a certificate in <c>x5c</c> is never an anchor). The
    /// end-entity Key Usage is not checked here: X509Chain does not check it, and the library refuses a certificate
    /// without digitalSignature before any hook runs (X5C_KEY_USAGE, PR #56 review round 1).
    /// </summary>
    public static bool ValidateWithAnchors(X509CertificateChain chain, params X509Certificate2[] anchors)
    {
        using var platformChain = new X509Chain();
        platformChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        platformChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        platformChain.ChainPolicy.DisableCertificateDownloads = true;
        foreach (var anchor in anchors)
            platformChain.ChainPolicy.CustomTrustStore.Add(anchor);
        foreach (var certificate in chain.Certificates.Skip(1))
            platformChain.ChainPolicy.ExtraStore.Add(X509CertificateLoader.LoadCertificate(certificate.Span));
        using var endEntity = X509CertificateLoader.LoadCertificate(chain.EndEntityCertificate.Span);
        return platformChain.Build(endEntity);
    }

    private static ECDsa PlatformPublicKey(KeyPair key)
    {
        var jwk = JwkConversion.ToPublicJwk(key.KeyType, key.PublicKey);
        var curve = key.KeyType == KeyType.P384 ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP256;
        return ECDsa.Create(new ECParameters
        {
            Curve = curve,
            Q = new ECPoint { X = Base64Url.Decode(jwk.X!), Y = Base64Url.Decode(jwk.Y!) },
        });
    }

    private static byte[] NextSerial()
    {
        var serial = Interlocked.Increment(ref _serial);
        return [0x01, (byte)(serial >> 16), (byte)(serial >> 8), (byte)serial];
    }

    // ------------------------------------------------------------------------------------------ assembled certificates

    /// <summary>An end-entity certificate, assembled here, for a fresh NetCrypto key of any v1 JWS type.</summary>
    public static Leaf CreateLeaf(KeyType keyType, bool compressedPoint = false)
    {
        var key = Generator.Generate(keyType);
        var certificate = Assemble(Spki(key, compressedPoint), subject: $"Leaf {keyType}");
        return new Leaf(key, new JwsSigner(new KeyPairSigner(key, NetCryptoProvider)), certificate);
    }

    /// <summary>The <c>subjectPublicKeyInfo</c> for a NetCrypto key.</summary>
    public static byte[] Spki(KeyPair key, bool compressedPoint = false)
    {
        if (key.KeyType == KeyType.Ed25519)
            return Spki(Ed25519Oid, parametersOid: null, key.PublicKey.ToArray());

        var jwk = JwkConversion.ToPublicJwk(key.KeyType, key.PublicKey);
        var x = Base64Url.Decode(jwk.X!);
        var y = Base64Url.Decode(jwk.Y!);
        byte[] point = compressedPoint
            ? [(byte)(0x02 | (y[^1] & 1)), .. x]
            : [0x04, .. x, .. y];
        var curve = key.KeyType switch
        {
            KeyType.P256 => P256Oid,
            KeyType.P384 => P384Oid,
            KeyType.Secp256k1 => Secp256k1Oid,
            _ => throw new ArgumentOutOfRangeException(nameof(key)),
        };
        return Spki(EcPublicKeyOid, curve, point);
    }

    /// <summary>A <c>subjectPublicKeyInfo</c> with any algorithm, parameters and key bits.</summary>
    public static byte[] Spki(string algorithmOid, string? parametersOid, byte[] key, int unusedBits = 0, byte[]? rawParameters = null)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(algorithmOid);
                if (parametersOid is not null)
                    writer.WriteObjectIdentifier(parametersOid);
                if (rawParameters is not null)
                    writer.WriteEncodedValue(rawParameters);
            }
            writer.WriteBitString(key, unusedBits);
        }
        return writer.Encode();
    }

    /// <summary>
    /// A v3 certificate for <paramref name="spki"/>, signed (Ed25519) by <see cref="AssemblyCa"/>, with a fixed validity
    /// and an 8-byte serial, so its length depends only on the arguments.
    /// <paramref name="tbsTail"/> writes extra TBS fields after the subjectPublicKeyInfo; <paramref name="version"/>
    /// null omits the version field.
    /// </summary>
    public static byte[] Assemble(byte[] spki, string subject = "Leaf", string issuer = "Assembly CA", int? version = 2,
        Action<AsnWriter>? tbsTail = null, bool withExtensions = true, byte[]? rawIssuer = null, byte[]? rawSubject = null,
        byte[]? rawSignatureAlgorithm = null)
    {
        var tbs = new AsnWriter(AsnEncodingRules.DER);
        using (tbs.PushSequence())
        {
            if (version is { } v)
            {
                using (tbs.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                    tbs.WriteInteger(v);
            }
            // A distinct serial per certificate (so two assembled certificates never repeat), always 8 bytes long.
            var serial = new byte[8];
            serial[0] = 0x01;
            BinaryPrimitives.WriteInt32BigEndian(serial.AsSpan(4), Interlocked.Increment(ref _serial));
            tbs.WriteIntegerUnsigned(serial);
            if (rawSignatureAlgorithm is not null) tbs.WriteEncodedValue(rawSignatureAlgorithm); else WriteEd25519(tbs);
            if (rawIssuer is not null) tbs.WriteEncodedValue(rawIssuer); else WriteName(tbs, issuer);
            using (tbs.PushSequence())
            {
                tbs.WriteUtcTime(AssembledNotBefore);
                tbs.WriteUtcTime(AssembledNotAfter);
            }
            if (rawSubject is not null) tbs.WriteEncodedValue(rawSubject); else WriteName(tbs, subject);
            tbs.WriteEncodedValue(spki);
            if (withExtensions)
            {
                using (tbs.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true)))
                using (tbs.PushSequence())
                using (tbs.PushSequence())
                {
                    tbs.WriteObjectIdentifier("2.5.29.15"); // keyUsage
                    tbs.WriteBoolean(true);
                    var keyUsage = new AsnWriter(AsnEncodingRules.DER);
                    keyUsage.WriteBitString([0x80], unusedBitCount: 7); // digitalSignature
                    tbs.WriteOctetString(keyUsage.Encode());
                }
            }
            tbsTail?.Invoke(tbs);
        }
        return Sign(tbs.Encode());
    }

    /// <summary>Wrap TBS bytes into a Certificate signed (deterministically) by <see cref="AssemblyCa"/>.</summary>
    public static byte[] Sign(byte[] tbs)
    {
        var certificate = new AsnWriter(AsnEncodingRules.DER);
        using (certificate.PushSequence())
        {
            certificate.WriteEncodedValue(tbs);
            WriteEd25519(certificate);
            certificate.WriteBitString(AssemblyCa.SignAsync(tbs).GetAwaiter().GetResult());
        }
        return certificate.Encode();
    }

    /// <summary>A distinct CA certificate with an RSA key: valid anywhere in <c>x5c</c> but first.</summary>
    public static byte[] RsaCertificate(string subject = "RSA CA")
    {
        using var rsa = RSA.Create(2048);
        return Assemble(rsa.ExportSubjectPublicKeyInfo(), subject);
    }

    private static void WriteEd25519(AsnWriter writer)
    {
        using (writer.PushSequence())
            writer.WriteObjectIdentifier(Ed25519Oid);
    }

    private static void WriteName(AsnWriter writer, string commonName)
    {
        using (writer.PushSequence())
        using (writer.PushSetOf())
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("2.5.4.3");
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, commonName);
        }
    }
}
