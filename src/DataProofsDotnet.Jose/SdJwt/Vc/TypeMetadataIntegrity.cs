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

    /// <summary>
    /// Checks <paramref name="integrityMetadata"/> against <paramref name="document"/>, as -27 §6 defines it. Two passes
    /// over the value's characters, without allocating per expression: the first checks the grammar and finds the
    /// strongest supported algorithm, the second compares each of its digests, decoded into a stack buffer, with the
    /// one hash of the document. The cost is linear in the value and the document, whatever the number of expressions.
    /// </summary>
    internal static Outcome Check(string integrityMetadata, ReadOnlySpan<byte> document)
    {
        Span<byte> digest = stackalloc byte[64];
        var strongest = 0;
        var tokens = 0;
        for (var position = 0; NextToken(integrityMetadata, ref position, out var token);)
        {
            tokens++;
            if (!Split(token, out var rank, out var value))
                return Outcome.Malformed;
            if (rank == 0)
                continue; // An algorithm this consumer does not support is ignored with whatever follows it (SRI §3.3.3).
            if (!TryDecodeCanonical(value, DigestLength(rank), digest))
                return Outcome.Malformed;
            strongest = Math.Max(strongest, rank);
        }

        if (tokens == 0)
            return Outcome.Malformed;
        if (strongest == 0)
            return Outcome.Unsupported;

        var computed = Hash(strongest, document);
        for (var position = 0; NextToken(integrityMetadata, ref position, out var token);)
        {
            Split(token, out var rank, out var value);
            if (rank == strongest && TryDecodeCanonical(value, DigestLength(rank), digest) && digest[..computed.Length].SequenceEqual(computed))
                return Outcome.Match;
        }
        return Outcome.Mismatch;
    }

    /// <summary>The next token separated by ASCII whitespace (SRI splits on spaces; the ABNF allows any WSP).</summary>
    private static bool NextToken(string value, ref int position, out ReadOnlySpan<char> token)
    {
        while (position < value.Length && IsSpace(value[position]))
            position++;
        var start = position;
        while (position < value.Length && !IsSpace(value[position]))
            position++;
        token = value.AsSpan(start, position - start);
        return token.Length > 0;
    }

    private static bool IsSpace(char c) => c is ' ' or '\t' or '\n' or '\r' or '\f';

    /// <summary>
    /// Splits <c>alg-value[?options]</c>: <c>false</c> when there is no <c>alg</c> or it is not alphanumeric. The rank is
    /// 0 for an algorithm this consumer does not support.
    /// </summary>
    private static bool Split(ReadOnlySpan<char> token, out int rank, out ReadOnlySpan<char> value)
    {
        var question = token.IndexOf('?');
        var expression = question < 0 ? token : token[..question];
        var dash = expression.IndexOf('-');
        rank = 0;
        value = default;
        if (dash <= 0)
            return false;
        var algorithm = expression[..dash];
        foreach (var c in algorithm)
        {
            if (!char.IsAsciiLetterOrDigit(c))
                return false;
        }
        rank = Rank(algorithm);
        value = expression[(dash + 1)..];
        return true;
    }

    /// <summary>The strength order of the supported algorithms, 0 for any other (ASCII case-insensitive).</summary>
    private static int Rank(ReadOnlySpan<char> algorithm)
        => algorithm.Equals(Sha256, StringComparison.OrdinalIgnoreCase) ? 1
            : algorithm.Equals(Sha384, StringComparison.OrdinalIgnoreCase) ? 2
            : algorithm.Equals(Sha512, StringComparison.OrdinalIgnoreCase) ? 3
            : 0;

    private static int Rank(string algorithm) => Rank(algorithm.AsSpan());

    private static string Name(int rank) => rank switch { 1 => Sha256, 2 => Sha384, _ => Sha512 };

    private static int DigestLength(int rank) => rank switch { 1 => 32, 2 => 48, _ => 64 };

    private static byte[] Hash(int rank, ReadOnlySpan<byte> document) => rank switch
    {
        1 => NetCrypto.Hash.Sha256(document),
        2 => NetCrypto.Hash.Sha384(document),
        _ => NetCrypto.Hash.Sha512(document),
    };

    /// <summary>
    /// Decodes <paramref name="value"/> into <paramref name="destination"/> when it is the canonical standard base64 of
    /// exactly <paramref name="length"/> octets, padded or not (the CSP2 <c>base64-value</c> production admits both). Any
    /// other spelling is refused, non-zero pad bits included (RFC 4648 §3.5 lets a decoder refuse them), so one digest
    /// has one integrity string, as a cache keyed by it (-27 §5.3.4) assumes. Nothing is allocated.
    /// </summary>
    private static bool TryDecodeCanonical(ReadOnlySpan<char> value, int length, Span<byte> destination)
    {
        var padded = (length + 2) / 3 * 4;
        var unpadded = (length * 4 + 2) / 3;
        if (value.Length != padded && value.Length != unpadded)
            return false;

        Span<char> canonical = stackalloc char[88];
        Span<char> input = stackalloc char[88];
        value.CopyTo(input);
        for (var i = value.Length; i < padded; i++)
            input[i] = '=';
        var candidate = input[..padded];

        return Convert.TryFromBase64Chars(candidate, destination, out var written)
            && written == length
            && Convert.TryToBase64Chars(destination[..length], canonical, out var encoded)
            && canonical[..encoded].SequenceEqual(candidate);
    }
}
