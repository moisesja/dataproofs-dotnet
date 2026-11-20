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
/// <b>Parsed, not validated.</b> Building this type reads each entry as exactly one DER certificate with nothing after
/// it. Where RFC 5280 gives the schema, it is read field by field under DER rules: each field of <c>TBSCertificate</c>
/// for its tag and position, each issuer and subject Name down to its attribute values (each RDN a non-empty SET OF in
/// DER order), each AlgorithmIdentifier, and each extension, whose <c>extnValue</c> must hold exactly one DER TLV; no
/// extension may appear twice (RFC 5280 §4.2). Where the schema is open (attribute values, algorithm parameters,
/// extension values), every nested TLV is read too, to a depth of 32, but only against the DER rules that hold whatever
/// the schema: minimal lengths and tags; primitive encodings for the universal types DER always encodes primitively and
/// constructed ones for SEQUENCE, SET, EXTERNAL, EMBEDDED PDV and CHARACTER STRING; and DER's content rules for
/// BOOLEAN, INTEGER, ENUMERATED, BIT STRING unused bits, NULL, OBJECT IDENTIFIER, UTCTime and GeneralizedTime. Without
/// the schema the order of a SET's elements, DEFAULT omission and a named bit list's trailing zeros cannot be judged,
/// so they are not. The bytes of strings, OCTET STRINGs and REALs are not interpreted (a character set is a type
/// constraint, not an encoding rule), and the contents of the signature and public-key BIT STRINGs are not TLVs and are
/// not read, except the end-entity key. Two DEFAULT values encoded explicitly where the schema is known, which DER
/// would omit (an explicit v1 version, an explicit critical <c>FALSE</c>), are tolerated, as certificate parsers
/// generally do; so are Key Usage trailing zero bits.
/// </para>
/// <para>
/// It does <b>not</b> perform RFC 5280 path validation: it checks no certificate signature, validity period, basic
/// constraints, name chaining or order, revocation, policy, name constraint, Extended Key Usage or critical extension,
/// and it knows no trust anchor. RFC 7515 §4.1.6 requires the recipient to validate the chain, and
/// draft-ietf-oauth-sd-jwt-vc-27 §2.5 requires it to be validated "against a trust anchor permitted for the Issuer
/// according to policy (a certificate in the x5c header parameter is not a trust anchor merely because it is included
/// there)". That is the caller's hook.
/// </para>
/// <para>
/// One restriction is checked where the key is used, because it limits that use: an end-entity certificate with a Key
/// Usage extension that does not assert <c>digitalSignature</c> (RFC 5280 §4.2.1.3; critical or not; a
/// <c>contentCommitment</c>-only key included) may not verify a JWS. The verifiers refuse it with <c>X5C_KEY_USAGE</c>
/// before using the key or calling the hook, and <see cref="Signing.JwsSigner.CertificateChain"/> refuses it.
/// <see cref="Create"/> does not: such a chain is well formed.
/// </para>
/// <para>
/// A well-formed chain holds 1 to <see cref="MaxCertificates"/> certificates, no two identical. The end-entity
/// certificate's key must be Ed25519, P-256, P-384 or secp256k1 (the JWS algorithms of PRD FR-13), and an EC key must
/// be a point on its curve (an Ed25519 key is checked for length only, as an Ed25519 JWK is); later
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
    internal const string KeyUsageCode = "X5C_KEY_USAGE";

    /// <summary>
    /// The deepest nesting accepted inside a value the certificate's schema leaves open (an attribute value, algorithm
    /// parameters, an extension value). Real certificates nest such values a few levels deep; 32 bounds the recursion.
    /// </summary>
    private const int MaxOpenValueDepth = 32;
    private const string KeyUsageOid = "2.5.29.15";             // id-ce-keyUsage (RFC 5280 §4.2.1.3)

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

    private X509CertificateChain(
        IReadOnlyList<ReadOnlyMemory<byte>> certificates, KeyType endEntityKeyType, byte[] endEntityPublicKey, bool endEntityMaySign)
    {
        Certificates = certificates;
        _endEntityKeyType = endEntityKeyType;
        _endEntityPublicKey = endEntityPublicKey;
        EndEntityMaySign = endEntityMaySign;
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

    /// <summary>The end-entity key's NetCrypto type and public key bytes: an EC point verified on its curve, or the raw Ed25519 key.</summary>
    internal (KeyType KeyType, byte[] PublicKey) EndEntityKey => (_endEntityKeyType, _endEntityPublicKey);

    /// <summary>
    /// Whether the end-entity key may verify a JWS signature: <c>true</c> when the certificate has no Key Usage extension
    /// or its Key Usage asserts <c>digitalSignature</c> (RFC 5280 §4.2.1.3). Checked before the key is used.
    /// </summary>
    internal bool EndEntityMaySign { get; }

    /// <summary>The coded message for an end-entity certificate whose Key Usage does not permit JWS signatures.</summary>
    internal const string KeyUsageMessage =
        KeyUsageCode + ": the end-entity certificate's Key Usage does not assert digitalSignature (RFC 5280 §4.2.1.3), "
        + "so its key may not verify a JWS signature.";

    /// <summary>
    /// Build a chain from DER certificates, the end-entity certificate first. The bytes are copied.
    /// </summary>
    /// <param name="certificates">The DER certificates, end-entity first (for example <c>X509Certificate2.RawData</c>).</param>
    /// <exception cref="ArgumentNullException">When <paramref name="certificates"/> is null.</exception>
    /// <exception cref="MalformedJoseException">
    /// <c>X5C_MALFORMED</c>: no certificate, more than <see cref="MaxCertificates"/>, an entry that is not exactly
    /// one DER certificate (see the remarks for what is read), an extension twice in one certificate, two identical
    /// entries, or an end-entity key that is not a valid encoding: an EC key not on its
    /// named curve, or an Ed25519 key that is not 32 bytes. Whether 32 Ed25519 bytes decode to a curve point is left to
    /// signature verification (RFC 8032 §5.1.7), as for an Ed25519 JWK: a JWS under such a key fails as a signature that
    /// does not verify, before any hook runs.
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
        var endEntityMaySign = true;
        for (var i = 0; i < der.Count; i++)
        {
            for (var j = 0; j < i; j++)
            {
                if (der[i].AsSpan().SequenceEqual(der[j]))
                    return ParseOutcome.Malformed($"'x5c' entry {i} repeats entry {j}.");
            }

            try
            {
                var (spki, keyUsage) = ReadCertificate(der[i]);
                if (i == 0)
                {
                    endEntitySpki = spki;
                    // RFC 5280 §4.2.1.3: when present, Key Usage lists what the key may be used for, critical or not.
                    // A JWS signature is verified with the end-entity key, so its certificate must assert
                    // digitalSignature (bit 0). Only the end-entity: a CA's usage is the caller's path validation.
                    endEntityMaySign = keyUsage is null || (keyUsage.Length > 0 && (keyUsage[0] & 0x80) != 0);
                }
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
            key!,
            endEntityMaySign));
    }

    /// <summary>
    /// Read one <c>Certificate</c> (RFC 5280 §4.1) under DER rules and return its <c>subjectPublicKeyInfo</c> and its Key
    /// Usage bits (<c>null</c> without the extension). Every TLV is read: each field of <c>TBSCertificate</c> for its tag
    /// and position, each Name down to its attribute values, each extension and the DER value inside it, and the values
    /// the schema leaves open (attribute values, algorithm parameters, extension values) with <see cref="ReadOpenValue"/>.
    /// The contents of the signature and public-key BIT STRINGs are not TLVs and are not read. Nothing may follow the
    /// certificate.
    /// </summary>
    private static ((string Oid, ReadOnlyMemory<byte>? Parameters, byte[] Key, int UnusedBits) Spki, byte[]? KeyUsage) ReadCertificate(byte[] der)
    {
        var reader = new AsnReader(der, AsnEncodingRules.DER);
        var certificate = reader.ReadSequence();
        if (reader.HasData)
            throw new AsnContentException("bytes follow the certificate.");
        byte[]? keyUsage = null;

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
        ReadName(tbs);                          // issuer
        var validity = tbs.ReadSequence();
        ReadTime(validity);                     // notBefore
        ReadTime(validity);                     // notAfter
        if (validity.HasData)
            throw new AsnContentException("the validity has more than two fields.");
        ReadName(tbs);                          // subject

        var spki = tbs.ReadSequence();
        var algorithm = spki.ReadSequence();
        var oid = algorithm.ReadObjectIdentifier();
        // Not a conditional expression: `cond ? memory : null` types as ReadOnlyMemory<byte> and turns the null into an
        // empty memory, so absent parameters would read as present.
        ReadOnlyMemory<byte>? parameters = null;
        if (algorithm.HasData)
        {
            ReadOpenValue(algorithm.Clone(), 0);
            parameters = algorithm.ReadEncodedValue();
        }
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
            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (extensions.HasData)
            {
                var extension = extensions.ReadSequence();
                var extensionId = extension.ReadObjectIdentifier();
                // RFC 5280 §4.2: "A certificate MUST NOT include more than one instance of a particular extension."
                if (!seen.Add(extensionId))
                    throw new AsnContentException($"the extension {extensionId} appears twice.");
                if (extension.HasData && extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
                    extension.ReadBoolean();
                var value = extension.ReadOctetString();
                if (extension.HasData)
                    throw new AsnContentException("an extension has more than three fields.");

                // extnValue "contains the DER encoding of an ASN.1 value" (RFC 5280 §4.1): exactly one TLV.
                var valueReader = new AsnReader(value, AsnEncodingRules.DER);
                if (extensionId == KeyUsageOid)
                {
                    // KeyUsage ::= BIT STRING, bit 0 digitalSignature.
                    keyUsage = valueReader.ReadBitString(out _);
                }
                else
                {
                    ReadOpenValue(valueReader, 0);
                }
                if (valueReader.HasData)
                    throw new AsnContentException($"the value of the extension {extensionId} is not one DER TLV.");
            }
        }
        if (tbs.HasData)
            throw new AsnContentException("the TBSCertificate has unexpected trailing fields.");

        return ((oid, parameters, key, unusedBits), keyUsage);
    }

    /// <summary>
    /// RFC 5280 §4.1.2.4: <c>Name ::= RDNSequence</c>, a SEQUENCE OF <c>RelativeDistinguishedName</c>, each a SET (in DER
    /// order) of one or more <c>AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }</c>. An empty RDNSequence is
    /// allowed (a subject named only in subjectAltName).
    /// </summary>
    private static void ReadName(AsnReader reader)
    {
        var rdnSequence = reader.ReadSequence();
        while (rdnSequence.HasData)
        {
            var rdn = rdnSequence.ReadSetOf();
            if (!rdn.HasData)
                throw new AsnContentException("a RelativeDistinguishedName is empty.");
            while (rdn.HasData)
            {
                var attribute = rdn.ReadSequence();
                attribute.ReadObjectIdentifier();
                ReadOpenValue(attribute, 0);
                if (attribute.HasData)
                    throw new AsnContentException("an AttributeTypeAndValue has more than two fields.");
            }
        }
    }

    /// <summary>
    /// Read one TLV whose type the certificate schema leaves open (an attribute value, algorithm parameters, an extension
    /// value), and everything inside it, checking only the DER rules that hold for every DER value whatever its schema
    /// (X.690). Without the schema the reader cannot tell SET from SET OF, a DEFAULT value from a present one, or a
    /// named bit list from a plain BIT STRING, so it checks no component order, DEFAULT omission or trailing-zero rule.
    /// It does check, at every level:
    /// <list type="bullet">
    /// <item>definite lengths in the fewest octets, and minimal tag octets (§10.1, §8.1.2);</item>
    /// <item>a constructed encoding's contents are complete TLVs (§8.1.3);</item>
    /// <item>the universal types DER always encodes primitively (BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL, OBJECT
    /// IDENTIFIER, ObjectDescriptor, REAL, ENUMERATED, RELATIVE-OID, the restricted character strings, UTCTime and
    /// GeneralizedTime) are primitive (§8.2–§8.20, §10.2), and those always constructed (SEQUENCE, SET, EXTERNAL,
    /// EMBEDDED PDV, CHARACTER STRING) are constructed (§8.9–§8.12, §8.18, §8.24); END-OF-CONTENTS never appears;</item>
    /// <item>BOOLEAN is one octet, 00 or FF (§11.1); INTEGER and ENUMERATED are minimal (§8.3.2); BIT STRING's unused
    /// bits are zero (§11.2.1); NULL is empty (§8.8.2); OBJECT IDENTIFIER subidentifiers are minimal (§8.19.2); UTCTime and
    /// GeneralizedTime have DER's form (§11.7, §11.8).</item>
    /// </list>
    /// The bytes of strings, OCTET STRINGs and REALs are not interpreted. Nesting deeper than
    /// <see cref="MaxOpenValueDepth"/> is refused: a resource bound, not a DER rule.
    /// </summary>
    private static void ReadOpenValue(AsnReader reader, int depth)
    {
        var tag = reader.PeekTag();
        var universal = tag.TagClass == TagClass.Universal ? (UniversalTagNumber?)tag.TagValue : null;

        if (universal is UniversalTagNumber.EndOfContents)
            throw new AsnContentException("an END-OF-CONTENTS, which DER never encodes.");

        if (tag.IsConstructed)
        {
            if (universal is { } type && IsAlwaysPrimitive(type))
                throw new AsnContentException($"a constructed encoding of universal type {tag.TagValue}, which DER encodes primitively.");
            if (depth >= MaxOpenValueDepth)
                throw new AsnContentException($"a value is nested more than {MaxOpenValueDepth} levels deep.");

            // Any constructed encoding's contents are complete TLVs; no schema needed to walk them, and no order is
            // checked (a schema-unknown SET may be a SET, ordered by tag, or a SET OF, ordered by octets).
            var encoded = reader.ReadEncodedValue();
            if (!AsnDecoder.TryReadEncodedValue(encoded.Span, AsnEncodingRules.DER, out _, out var contentOffset, out var contentLength, out _))
                throw new AsnContentException("a constructed value's header is not DER.");
            var inner = new AsnReader(encoded.Slice(contentOffset, contentLength), AsnEncodingRules.DER);
            while (inner.HasData)
                ReadOpenValue(inner, depth + 1);
            return;
        }

        switch (universal)
        {
            case UniversalTagNumber.Sequence:
            case UniversalTagNumber.Set:
            case UniversalTagNumber.External:
            case UniversalTagNumber.Embedded:
            case UniversalTagNumber.UnrestrictedCharacterString:
                throw new AsnContentException($"a primitive encoding of universal type {tag.TagValue}, which is always constructed.");
            case UniversalTagNumber.Boolean:
                reader.ReadBoolean();
                return;
            case UniversalTagNumber.Integer:
                reader.ReadIntegerBytes();
                return;
            case UniversalTagNumber.Enumerated:
                reader.ReadEnumeratedBytes();
                return;
            case UniversalTagNumber.BitString:
                reader.ReadBitString(out _);
                return;
            case UniversalTagNumber.Null:
                reader.ReadNull();
                return;
            case UniversalTagNumber.ObjectIdentifier:
                reader.ReadObjectIdentifier();
                return;
            case UniversalTagNumber.UtcTime:
                reader.ReadUtcTime();
                return;
            case UniversalTagNumber.GeneralizedTime:
                reader.ReadGeneralizedTime();
                return;
            default:
                reader.ReadEncodedValue();
                return;
        }
    }

    /// <summary>The universal types X.690 encodes primitively under DER, whatever the schema around them.</summary>
    private static bool IsAlwaysPrimitive(UniversalTagNumber type) => type switch
    {
        UniversalTagNumber.Boolean or UniversalTagNumber.Integer or UniversalTagNumber.BitString
            or UniversalTagNumber.OctetString or UniversalTagNumber.Null or UniversalTagNumber.ObjectIdentifier
            or UniversalTagNumber.ObjectDescriptor or UniversalTagNumber.Real or UniversalTagNumber.Enumerated
            or UniversalTagNumber.RelativeObjectIdentifier
            or UniversalTagNumber.UTF8String or UniversalTagNumber.NumericString or UniversalTagNumber.PrintableString
            or UniversalTagNumber.TeletexString or UniversalTagNumber.VideotexString or UniversalTagNumber.IA5String
            or UniversalTagNumber.UtcTime or UniversalTagNumber.GeneralizedTime or UniversalTagNumber.GraphicString
            or UniversalTagNumber.VisibleString or UniversalTagNumber.GeneralString or UniversalTagNumber.UniversalString
            or UniversalTagNumber.BMPString => true,
        _ => false,
    };

    private static void ReadAlgorithmIdentifier(AsnReader reader)
    {
        var algorithm = reader.ReadSequence();
        algorithm.ReadObjectIdentifier();
        if (algorithm.HasData)
            ReadOpenValue(algorithm, 0);
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
