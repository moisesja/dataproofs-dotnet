using System.Collections.ObjectModel;
using System.Formats.Asn1;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetCrypto;

namespace DataProofsDotnet.Jose;

/// <summary>
/// An X.509 certificate chain as the JOSE <c>x5c</c> header parameter carries it (RFC 7515 §4.1.6): DER
/// certificates, the end-entity certificate first, each later one meant to certify the one before it. Used to put
/// a chain on a <see cref="Signing.JwsSigner"/> (<see cref="Signing.JwsSigner.CertificateChain"/>) and handed to the
/// caller's validation hook by <see cref="Signing.JwsParser.ParseCompactWithCertificateChain"/>,
/// <see cref="SdJwt.SdJwtVerifier.VerifyWithCertificateChain"/> and
/// <see cref="SdJwt.Vc.SdJwtVcVerifier.VerifyWithCertificateChainAsync"/>. Immutable and thread-safe.
/// </summary>
/// <remarks>
/// <para>
/// <b>Parsed, not validated.</b> Building this type checks that each entry is one well-formed DER certificate
/// with nothing after it and that the end-entity key is one this package verifies with. It does <b>not</b> perform
/// RFC 5280 path validation: it checks no certificate signature, validity period, basic constraints, key usage,
/// name chaining or order, revocation, policy, name constraint or critical extension, and it knows no trust anchor.
/// RFC 7515 §4.1.6 requires the recipient to validate the chain, and draft-ietf-oauth-sd-jwt-vc-27 §2.5 requires
/// it to be validated "against a trust anchor permitted for the Issuer according to policy (a certificate in the
/// x5c header parameter is not a trust anchor merely because it is included there)". That is the caller's hook.
/// </para>
/// <para>
/// A well-formed chain holds 1 to <see cref="MaxCertificates"/> certificates, no two identical. The end-entity
/// certificate's key must be Ed25519, P-256, P-384 or secp256k1 (the JWS algorithms of PRD FR-13); later
/// certificates may hold any key type, since only the caller's path validation reads them. Certificates are parsed
/// with <see cref="System.Formats.Asn1"/>, which performs no cryptography (PRD §2.2).
/// </para>
/// </remarks>
public sealed class X509CertificateChain
{
    /// <summary>
    /// The most certificates a chain may hold: 10. A longer <c>x5c</c> is <c>X5C_MALFORMED</c>. It bounds the work a
    /// caller's path builder is given; real chains hold two to five.
    /// </summary>
    public const int MaxCertificates = 10;

    internal const string MissingCode = "X5C_MISSING";
    internal const string MalformedCode = "X5C_MALFORMED";
    internal const string UnsupportedKeyCode = "X5C_UNSUPPORTED_KEY";
    internal const string UntrustedCode = "X5C_UNTRUSTED";

    private const string HeaderParameter = "x5c";
    private const string EcPublicKeyOid = "1.2.840.10045.2.1"; // id-ecPublicKey (RFC 5480 §2.1.1)
    private const string Ed25519Oid = "1.3.101.112";            // id-Ed25519 (RFC 8410 §3)
    private const string P256Oid = "1.2.840.10045.3.1.7";       // secp256r1 / prime256v1 (RFC 5480 §2.1.1.1)
    private const string P384Oid = "1.3.132.0.34";              // secp384r1 (RFC 5480 §2.1.1.1)
    private const string Secp256k1Oid = "1.3.132.0.10";         // secp256k1 (SEC 2 §2.4.1)

    private static readonly Asn1Tag VersionTag = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag IssuerUniqueIdTag = new(TagClass.ContextSpecific, 1);
    private static readonly Asn1Tag SubjectUniqueIdTag = new(TagClass.ContextSpecific, 2);
    private static readonly Asn1Tag ExtensionsTag = new(TagClass.ContextSpecific, 3, isConstructed: true);

    private readonly KeyType _endEntityKeyType;
    private readonly byte[] _endEntityPublicKey;

    private X509CertificateChain(IReadOnlyList<ReadOnlyMemory<byte>> certificates, KeyType endEntityKeyType, byte[] endEntityPublicKey)
    {
        Certificates = certificates;
        _endEntityKeyType = endEntityKeyType;
        _endEntityPublicKey = endEntityPublicKey;
    }

    /// <summary>The DER certificates, in <c>x5c</c> order: the end-entity certificate first. Copies owned by this instance.</summary>
    public IReadOnlyList<ReadOnlyMemory<byte>> Certificates { get; }

    /// <summary>The end-entity certificate (<see cref="Certificates"/>[0]): the one whose key signed the JWS.</summary>
    public ReadOnlyMemory<byte> EndEntityCertificate => Certificates[0];

    /// <summary>
    /// The end-entity certificate's public key as a public-only <see cref="Jwk"/> (no <c>kid</c>). A new instance is
    /// returned on each access, so changing one changes nothing here, nor the key a verifier uses.
    /// </summary>
    public Jwk EndEntityPublicKey => JwkConversion.ToPublicJwk(_endEntityKeyType, _endEntityPublicKey);

    /// <summary>The end-entity key's NetCrypto type and compressed or raw public key bytes (verified on-curve).</summary>
    internal (KeyType KeyType, byte[] PublicKey) EndEntityKey => (_endEntityKeyType, _endEntityPublicKey);

    /// <summary>
    /// Build a chain from DER certificates, the end-entity certificate first. The bytes are copied.
    /// </summary>
    /// <param name="certificates">The DER certificates, end-entity first (for example <c>X509Certificate2.RawData</c>).</param>
    /// <exception cref="ArgumentNullException">When <paramref name="certificates"/> is null.</exception>
    /// <exception cref="MalformedJoseException">
    /// <c>X5C_MALFORMED</c>: no certificate, more than <see cref="MaxCertificates"/>, an entry that is not exactly
    /// one DER certificate, two identical entries, or an end-entity key that is not a valid encoding.
    /// </exception>
    /// <exception cref="NotSupportedException">
    /// <c>X5C_UNSUPPORTED_KEY</c>: the end-entity key is well formed but not Ed25519, P-256, P-384 or secp256k1.
    /// </exception>
    public static X509CertificateChain Create(IReadOnlyList<ReadOnlyMemory<byte>> certificates)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        var outcome = Parse(certificates.Select(c => c.ToArray()).ToList());
        return outcome.Chain ?? throw outcome.ToCreateException();
    }

    /// <summary>The <c>x5c</c> value as the protected header carries it: standard, padded base64 of each DER certificate.</summary>
    internal IReadOnlyList<string> ToHeaderValue()
        => Certificates.Select(c => Convert.ToBase64String(c.Span)).ToArray();

    /// <summary>Read <c>x5c</c> from a protected header's extension members (the JWS parser's header model).</summary>
    internal static ParseOutcome FromHeader(IDictionary<string, JsonElement>? members)
    {
        if (members is null || !members.TryGetValue(HeaderParameter, out var value))
            return ParseOutcome.Missing();
        if (value.ValueKind != JsonValueKind.Array)
            return ParseOutcome.Malformed("the 'x5c' header parameter is not a JSON array.");

        var count = value.GetArrayLength();
        if (CountProblem(count) is { } countProblem)
            return ParseOutcome.Malformed(countProblem);

        var encoded = new List<string>(count);
        var index = 0;
        foreach (var element in value.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.String)
                return ParseOutcome.Malformed($"'x5c' entry {index} is not a JSON string.");
            encoded.Add(element.GetString()!);
            index++;
        }
        return FromBase64(encoded);
    }

    /// <summary>Read <c>x5c</c> from a protected header parsed as a <see cref="JsonObject"/> (the SD-JWT decoder).</summary>
    internal static ParseOutcome FromHeader(JsonObject header)
    {
        // TryGetPropertyValue, not the indexer: the indexer returns null for both an absent member and "x5c": null.
        if (!header.TryGetPropertyValue(HeaderParameter, out var value))
            return ParseOutcome.Missing();
        if (value is not JsonArray array)
            return ParseOutcome.Malformed("the 'x5c' header parameter is not a JSON array.");
        if (CountProblem(array.Count) is { } countProblem)
            return ParseOutcome.Malformed(countProblem);

        var encoded = new List<string>(array.Count);
        for (var i = 0; i < array.Count; i++)
        {
            if (array[i] is not JsonValue element || element.GetValueKind() != JsonValueKind.String)
                return ParseOutcome.Malformed($"'x5c' entry {i} is not a JSON string.");
            encoded.Add(element.GetValue<string>());
        }
        return FromBase64(encoded);
    }

    private static string? CountProblem(int count) => count switch
    {
        0 => "the 'x5c' array is empty; it must hold the end-entity certificate first.",
        > MaxCertificates => $"the 'x5c' array holds {count} certificates; at most {MaxCertificates} are accepted.",
        _ => null,
    };

    private static ParseOutcome FromBase64(IReadOnlyList<string> encoded)
    {
        var der = new List<byte[]>(encoded.Count);
        for (var i = 0; i < encoded.Count; i++)
        {
            if (DecodeStrictBase64(encoded[i]) is not { } bytes)
                return ParseOutcome.Malformed(
                    $"'x5c' entry {i} is not canonical base64 (RFC 7515 §4.1.6 requires RFC 4648 §4 base64, padded, "
                    + "with no whitespace; base64url is not accepted).");
            der.Add(bytes);
        }
        return Parse(der);
    }

    /// <summary>
    /// RFC 4648 §4 base64, strictly: <see cref="Convert.TryFromBase64String"/> skips whitespace and ignores non-zero
    /// pad bits, so the decoded bytes are re-encoded and must give back the input exactly. That also refuses a
    /// missing or extra <c>=</c>, line breaks and the base64url alphabet (RFC 4648 §3.3, §3.5).
    /// </summary>
    private static byte[]? DecodeStrictBase64(string value)
    {
        if (value.Length == 0 || value.Length % 4 != 0)
            return null;
        var buffer = new byte[value.Length / 4 * 3];
        if (!Convert.TryFromBase64String(value, buffer, out var written))
            return null;
        var bytes = buffer.AsSpan(0, written).ToArray();
        return string.Equals(Convert.ToBase64String(bytes), value, StringComparison.Ordinal) ? bytes : null;
    }

    private static ParseOutcome Parse(IReadOnlyList<byte[]> der)
    {
        if (CountProblem(der.Count) is { } countProblem)
            return ParseOutcome.Malformed(countProblem);

        (string Oid, ReadOnlyMemory<byte>? Parameters, byte[] Key, int UnusedBits) endEntitySpki = default;
        for (var i = 0; i < der.Count; i++)
        {
            for (var j = 0; j < i; j++)
            {
                if (der[i].AsSpan().SequenceEqual(der[j]))
                    return ParseOutcome.Malformed($"'x5c' entry {i} repeats entry {j}.");
            }

            try
            {
                var spki = ReadCertificate(der[i]);
                if (i == 0)
                    endEntitySpki = spki;
            }
            catch (AsnContentException ex)
            {
                return ParseOutcome.Malformed($"'x5c' entry {i} is not one DER-encoded X.509 certificate: {ex.Message}");
            }
        }

        var (keyType, key, error) = ReadEndEntityKey(endEntitySpki);
        if (error is not null)
            return error;
        return ParseOutcome.Success(new X509CertificateChain(
            new ReadOnlyCollection<ReadOnlyMemory<byte>>(der.Select(b => new ReadOnlyMemory<byte>(b)).ToArray()),
            keyType,
            key!));
    }

    /// <summary>
    /// Read one <c>Certificate</c> (RFC 5280 §4.1) under DER rules and return its <c>subjectPublicKeyInfo</c>. The
    /// structure is walked to a fixed depth, so a deeply nested input costs no recursion; every field of
    /// <c>TBSCertificate</c> is checked for its tag and position, and nothing may follow the certificate.
    /// </summary>
    private static (string Oid, ReadOnlyMemory<byte>? Parameters, byte[] Key, int UnusedBits) ReadCertificate(byte[] der)
    {
        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var certificate = reader.ReadSequence();
        if (reader.HasData)
            throw new AsnContentException("bytes follow the certificate.");

        var tbs = certificate.ReadSequence();
        ReadAlgorithmIdentifier(certificate);   // signatureAlgorithm
        certificate.ReadBitString(out _);       // signatureValue
        if (certificate.HasData)
            throw new AsnContentException("the certificate has more than three fields.");

        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(VersionTag))
        {
            var explicitVersion = tbs.ReadSequence(VersionTag);
            // v1 (0), v2 (1) or v3 (2). DER would omit an explicit v1, as it would an explicit critical FALSE below;
            // both are tolerated, as certificate parsers generally do, since neither changes what the fields mean.
            if (!explicitVersion.TryReadInt32(out var version) || version is < 0 or > 2 || explicitVersion.HasData)
                throw new AsnContentException("the certificate version is not v1, v2 or v3.");
        }
        tbs.ReadIntegerBytes();                 // serialNumber
        ReadAlgorithmIdentifier(tbs);           // signature
        tbs.ReadSequence();                     // issuer
        var validity = tbs.ReadSequence();
        ReadTime(validity);                     // notBefore
        ReadTime(validity);                     // notAfter
        if (validity.HasData)
            throw new AsnContentException("the validity has more than two fields.");
        tbs.ReadSequence();                     // subject

        var spki = tbs.ReadSequence();
        var algorithm = spki.ReadSequence();
        var oid = algorithm.ReadObjectIdentifier();
        ReadOnlyMemory<byte>? parameters = algorithm.HasData ? algorithm.ReadEncodedValue() : null;
        if (algorithm.HasData)
            throw new AsnContentException("the public key algorithm has more than two fields.");
        var key = spki.ReadBitString(out var unusedBits);
        if (spki.HasData)
            throw new AsnContentException("the subjectPublicKeyInfo has more than two fields.");

        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(IssuerUniqueIdTag))
            tbs.ReadBitString(out _, IssuerUniqueIdTag);
        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(SubjectUniqueIdTag))
            tbs.ReadBitString(out _, SubjectUniqueIdTag);
        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(ExtensionsTag))
        {
            var explicitExtensions = tbs.ReadSequence(ExtensionsTag);
            var extensions = explicitExtensions.ReadSequence();
            if (explicitExtensions.HasData || !extensions.HasData)
                throw new AsnContentException("the extensions field is not one non-empty SEQUENCE.");
            while (extensions.HasData)
            {
                var extension = extensions.ReadSequence();
                extension.ReadObjectIdentifier();
                if (extension.HasData && extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                    extension.ReadBoolean();
                extension.ReadOctetString();
                if (extension.HasData)
                    throw new AsnContentException("an extension has more than three fields.");
            }
        }
        if (tbs.HasData)
            throw new AsnContentException("the TBSCertificate has unexpected trailing fields.");

        return (oid, parameters, key, unusedBits);
    }

    private static void ReadAlgorithmIdentifier(AsnReader reader)
    {
        var algorithm = reader.ReadSequence();
        algorithm.ReadObjectIdentifier();
        if (algorithm.HasData)
            algorithm.ReadEncodedValue();
        if (algorithm.HasData)
            throw new AsnContentException("an AlgorithmIdentifier has more than two fields.");
    }

    private static void ReadTime(AsnReader reader)
    {
        // RFC 5280 §4.1.2.5: Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }.
        if (reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime))
            reader.ReadUtcTime();
        else
            reader.ReadGeneralizedTime();
    }

    private static (KeyType KeyType, byte[]? Key, ParseOutcome? Error) ReadEndEntityKey(
        (string Oid, ReadOnlyMemory<byte>? Parameters, byte[] Key, int UnusedBits) spki)
    {
        KeyType keyType;
        switch (spki.Oid)
        {
            case Ed25519Oid:
                // RFC 8410 §3: "the parameters MUST be absent"; the key is the 32-byte encoding (RFC 8032 §5.1.5).
                if (spki.Parameters is not null || spki.UnusedBits != 0 || spki.Key.Length != 32)
                    return (default, null, ParseOutcome.Malformed("the end-entity Ed25519 key is not a 32-byte key without parameters (RFC 8410 §3)."));
                keyType = KeyType.Ed25519;
                break;

            case EcPublicKeyOid:
                // RFC 5480 §2.1.1: the parameters MUST be present, and only the namedCurve choice is permitted.
                if (spki.Parameters is not { } parameters)
                    return (default, null, ParseOutcome.Malformed("the end-entity EC key has no curve parameters (RFC 5480 §2.1.1)."));
                string curve;
                try
                {
                    var parameterReader = new AsnReader(parameters, AsnEncodingRules.DER);
                    curve = parameterReader.ReadObjectIdentifier();
                }
                catch (AsnContentException)
                {
                    return (default, null, ParseOutcome.Malformed("the end-entity EC key's parameters are not a named curve (RFC 5480 §2.1.1)."));
                }
                switch (curve)
                {
                    case P256Oid: keyType = KeyType.P256; break;
                    case P384Oid: keyType = KeyType.P384; break;
                    case Secp256k1Oid: keyType = KeyType.Secp256k1; break;
                    default:
                        return (default, null, ParseOutcome.UnsupportedKey($"the end-entity EC key is on curve {curve}, which no supported JWS algorithm uses."));
                }
                if (spki.UnusedBits != 0 || !IsSec1PointLength(spki.Key, keyType == KeyType.P384 ? 48 : 32))
                    return (default, null, ParseOutcome.Malformed("the end-entity EC key is not a SEC 1 point for its curve (RFC 5480 §2.2)."));
                break;

            default:
                return (default, null, ParseOutcome.UnsupportedKey(
                    $"the end-entity key algorithm {spki.Oid} is not supported; the key must be Ed25519, P-256, P-384 or secp256k1."));
        }

        try
        {
            // NetCrypto decodes the point and runs the invalid-curve defense (off-curve, out-of-range, identity),
            // and the round trip normalizes it to the encoding the verifiers use.
            var jwk = JwkConversion.ToPublicJwk(keyType, spki.Key);
            var (normalizedType, normalized) = JwkConversion.ExtractPublicKey(jwk);
            return (normalizedType, normalized, null);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or ArgumentException or MalformedJoseException)
        {
            return (default, null, ParseOutcome.Malformed("the end-entity key is not a valid point on its curve."));
        }
    }

    /// <summary>SEC 1 §2.3.3: an uncompressed point (<c>04 ‖ X ‖ Y</c>) or a compressed one (<c>02|03 ‖ X</c>).</summary>
    private static bool IsSec1PointLength(byte[] point, int coordinateLength)
        => point.Length switch
        {
            _ when point.Length == 1 + (2 * coordinateLength) => point[0] == 0x04,
            _ when point.Length == 1 + coordinateLength => point[0] is 0x02 or 0x03,
            _ => false,
        };

    /// <summary>The result of reading <c>x5c</c>: the chain, or a stable code and a message.</summary>
    internal sealed record ParseOutcome(X509CertificateChain? Chain, string? Code, string? Detail)
    {
        public static ParseOutcome Success(X509CertificateChain chain) => new(chain, null, null);

        public static ParseOutcome Missing()
            => new(null, MissingCode, "the protected header has no 'x5c' parameter (RFC 7515 §4.1.6); the X.509 mechanism needs one.");

        public static ParseOutcome Malformed(string detail) => new(null, MalformedCode, detail);

        public static ParseOutcome UnsupportedKey(string detail) => new(null, UnsupportedKeyCode, detail);

        /// <summary>The coded message: <c>CODE: detail</c>.</summary>
        public string Message => $"{Code}: {Detail}";

        public Exception ToCreateException() => Code == UnsupportedKeyCode
            ? new NotSupportedException(Message)
            : new MalformedJoseException(Message);
    }
}
