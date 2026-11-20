namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// The integrity check of draft-ietf-oauth-sd-jwt-vc-27 §6 for documents an SD-JWT VC or its Type Metadata references:
/// <c>vct#integrity</c>, <c>extends#integrity</c> and the <c>uri#integrity</c> of a rendering resource. The value is a
/// W3C SRI "integrity metadata" string (SRI §3.5, the 2016 Recommendation -27 cites): whitespace-separated
/// <c>alg-base64digest</c> expressions, each optionally followed by <c>?options</c>, which are ignored. Hashing goes
/// through NetCrypto. Stateless and thread-safe.
/// </summary>
/// <remarks>
/// The rules applied, from -27 §6: the digest is computed over "the octets of the retrieved document"; with several
/// expressions, only those of "the strongest hash algorithm it supports" are used, and any of them may match; a value
/// that matches none of them, or names no supported algorithm, is a failure. SHA-256, SHA-384 and SHA-512 are supported
/// (<c>sha256</c>, <c>sha384</c>, <c>sha512</c>, compared case-insensitively as the ABNF grammar SRI uses reads them).
/// Other algorithms, such as <c>md5</c> or <c>sha1</c>, are ignored as SRI ignores them, so they can neither satisfy
/// nor weaken the check. A token that is not <c>alg-value</c> with an alphanumeric <c>alg</c>, or a supported expression
/// whose value is not standard base64 of the algorithm's digest length, makes the whole value refused. The SD-JWT VC verifier runs this check on <c>vct#integrity</c> and every
/// <c>extends#integrity</c> before it parses a document; a wallet runs <see cref="Matches"/> on a logo, background
/// image or SVG template it retrieved, since the library never retrieves those.
/// </remarks>
public static class TypeMetadataIntegrity
{
    /// <summary>The SRI name of SHA-256, the algorithm <see cref="Compute"/> uses by default.</summary>
    public const string Sha256 = "sha256";

    /// <summary>The SRI name of SHA-384.</summary>
    public const string Sha384 = "sha384";

    /// <summary>The SRI name of SHA-512.</summary>
    public const string Sha512 = "sha512";

    /// <summary>The outcome of checking an integrity metadata string against a document.</summary>
    internal enum Outcome
    {
        Match,
        Mismatch,
        Malformed,
        Unsupported,
    }

    /// <summary>
    /// Whether <paramref name="document"/>, the octets as retrieved, satisfies <paramref name="integrityMetadata"/>
    /// (-27 §6). <c>false</c> when the digest does not match, when the value is not a well-formed integrity metadata
    /// string, and when it names no supported algorithm: in each case -27 says the document "MUST be rejected and MUST
    /// NOT be processed further".
    /// </summary>
    /// <param name="integrityMetadata">The <c>…#integrity</c> value, for example <c>sha256-…</c>.</param>
    /// <param name="document">The octets of the retrieved document or resource.</param>
    public static bool Matches(string integrityMetadata, ReadOnlySpan<byte> document)
    {
        ArgumentNullException.ThrowIfNull(integrityMetadata);
        return Check(integrityMetadata, document) == Outcome.Match;
    }

    /// <summary>
    /// The integrity metadata string for <paramref name="document"/>: <c>&lt;algorithm&gt;-</c> followed by the standard
    /// base64 digest of its octets, for an issuer setting <c>vct#integrity</c> or a publisher setting
    /// <c>extends#integrity</c> or <c>uri#integrity</c>.
    /// </summary>
    /// <param name="document">The exact octets the consumer will retrieve.</param>
    /// <param name="algorithm"><see cref="Sha256"/> (the default), <see cref="Sha384"/> or <see cref="Sha512"/>.</param>
    /// <exception cref="ArgumentException">When <paramref name="algorithm"/> is not one of the three.</exception>
    public static string Compute(ReadOnlySpan<byte> document, string algorithm = Sha256)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        var rank = Rank(algorithm);
        if (rank == 0 || !string.Equals(algorithm, Name(rank), StringComparison.Ordinal))
            throw new ArgumentException($"Unsupported integrity algorithm '{algorithm}'; use sha256, sha384 or sha512.", nameof(algorithm));
        return $"{algorithm}-{Convert.ToBase64String(Hash(rank, document))}";
    }

    /// <summary>Checks <paramref name="integrityMetadata"/> against <paramref name="document"/>, as -27 §6 defines it.</summary>
    internal static Outcome Check(string integrityMetadata, ReadOnlySpan<byte> document)
    {
        var expressions = new List<(int Rank, byte[] Digest)>();
        foreach (var token in integrityMetadata.Split([' ', '\t', '\n', '\r', '\f'], StringSplitOptions.RemoveEmptyEntries))
        {
            var question = token.IndexOf('?');
            var expression = question < 0 ? token : token[..question];
            var dash = expression.IndexOf('-');
            if (dash <= 0)
                return Outcome.Malformed;

            var algorithm = expression[..dash];
            var value = expression[(dash + 1)..];
            if (!algorithm.All(char.IsAsciiLetterOrDigit))
                return Outcome.Malformed;

            // An algorithm this consumer does not support is ignored with whatever follows it (SRI §3.3.3), so a
            // future name such as sha3-256 neither fails nor satisfies the check.
            var rank = Rank(algorithm);
            if (rank == 0)
                continue;

            if (!IsBase64Value(value) || Decode(value) is not { } digest || digest.Length != DigestLength(rank))
                return Outcome.Malformed;
            expressions.Add((rank, digest));
        }

        if (expressions.Count == 0)
            return integrityMetadata.Trim().Length == 0 ? Outcome.Malformed : Outcome.Unsupported;

        var strongest = expressions.Max(e => e.Rank);
        var computed = Hash(strongest, document);
        return expressions.Any(e => e.Rank == strongest && e.Digest.AsSpan().SequenceEqual(computed))
            ? Outcome.Match
            : Outcome.Mismatch;
    }

    /// <summary>The strength order of the supported algorithms, 0 for any other (ASCII case-insensitive).</summary>
    private static int Rank(string algorithm) => algorithm.ToLowerInvariant() switch
    {
        Sha256 => 1,
        Sha384 => 2,
        Sha512 => 3,
        _ => 0,
    };

    private static string Name(int rank) => rank switch { 1 => Sha256, 2 => Sha384, _ => Sha512 };

    private static int DigestLength(int rank) => rank switch { 1 => 32, 2 => 48, _ => 64 };

    private static byte[] Hash(int rank, ReadOnlySpan<byte> document) => rank switch
    {
        1 => NetCrypto.Hash.Sha256(document),
        2 => NetCrypto.Hash.Sha384(document),
        _ => NetCrypto.Hash.Sha512(document),
    };

    /// <summary>The CSP2 <c>base64-value</c> production: <c>1*( ALPHA / DIGIT / "+" / "/" )*2( "=" )</c>.</summary>
    private static bool IsBase64Value(string value)
    {
        var body = value.TrimEnd('=');
        return body.Length > 0
            && value.Length - body.Length <= 2
            && body.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/');
    }

    private static byte[]? Decode(string value)
    {
        var padded = value.Contains('=') ? value : value.PadRight((value.Length + 3) / 4 * 4, '=');
        var buffer = new byte[padded.Length / 4 * 3];
        return Convert.TryFromBase64String(padded, buffer, out var written) ? buffer[..written] : null;
    }
}
