namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// The structural decomposition of an SD-JWT compact serialization (RFC 9901 §5.1 / §7): the
/// issuer-signed JWT, the ordered Disclosures, and an optional Key Binding JWT. Performs no
/// cryptographic validation — it splits on the <c>~</c> separator and parses each Disclosure's
/// shape. Immutable and thread-safe.
/// </summary>
/// <remarks>
/// SD-JWT grammar (RFC 9901 §4): <c>&lt;Issuer-JWT&gt;~&lt;D1&gt;~…~&lt;Dn&gt;~&lt;optional KB-JWT&gt;</c>.
/// A trailing <c>~</c> with nothing after it means there is no KB-JWT; a non-empty final element
/// is the KB-JWT (which itself is a compact JWT and so contains no <c>~</c>).
/// </remarks>
public sealed class SdJwtComponents
{
    private SdJwtComponents(
        string issuerJwt,
        IReadOnlyList<Disclosure> disclosures,
        string? keyBindingJwt,
        string sdJwtWithoutKeyBinding)
    {
        IssuerJwt = issuerJwt;
        Disclosures = disclosures;
        KeyBindingJwt = keyBindingJwt;
        SdJwtWithoutKeyBinding = sdJwtWithoutKeyBinding;
    }

    /// <summary>The issuer-signed JWT (the first <c>~</c>-separated element; a compact JWS).</summary>
    public string IssuerJwt { get; }

    /// <summary>The ordered Disclosures presented with the SD-JWT (may be empty).</summary>
    public IReadOnlyList<Disclosure> Disclosures { get; }

    /// <summary>The Key Binding JWT (<c>kb+jwt</c>) when present; <c>null</c> otherwise.</summary>
    public string? KeyBindingJwt { get; }

    /// <summary>True when a Key Binding JWT is present.</summary>
    public bool HasKeyBinding => KeyBindingJwt is not null;

    /// <summary>
    /// The SD-JWT up to and including the final <c>~</c>, excluding any KB-JWT — the exact string
    /// the KB-JWT <c>sd_hash</c> is computed over (RFC 9901 §7.3).
    /// </summary>
    public string SdJwtWithoutKeyBinding { get; }

    /// <summary>
    /// Parse a compact SD-JWT (with or without a trailing Key Binding JWT).
    /// </summary>
    /// <param name="compact">The compact SD-JWT serialization.</param>
    /// <exception cref="MalformedJoseException">
    /// When the string lacks the issuer JWT, has no trailing <c>~</c> on the SD-JWT portion, or
    /// carries a malformed Disclosure.
    /// </exception>
    public static SdJwtComponents Parse(string compact)
    {
        ArgumentException.ThrowIfNullOrEmpty(compact);

        // Split keeping empty trailing element so we can tell "ends in ~" (no KB) from "ends in
        // KB". RFC 9901 §4: the SD-JWT portion always ends in '~'.
        var parts = compact.Split('~');
        if (parts.Length < 2)
            throw new MalformedJoseException(
                "SD-JWT must contain at least the issuer JWT and a trailing '~' (RFC 9901 §4).");

        var issuerJwt = parts[0];
        if (string.IsNullOrEmpty(issuerJwt))
            throw new MalformedJoseException("SD-JWT issuer JWT (first '~'-separated element) is empty.");

        // The last element is either empty (no KB-JWT, the SD-JWT ends in '~') or the KB-JWT.
        var lastIndex = parts.Length - 1;
        var lastIsEmpty = string.IsNullOrEmpty(parts[lastIndex]);
        string? keyBindingJwt = lastIsEmpty ? null : parts[lastIndex];

        // Disclosures are everything between the issuer JWT and the final element.
        var disclosureEnd = lastIndex; // exclusive
        var disclosures = new List<Disclosure>();
        for (var i = 1; i < disclosureEnd; i++)
        {
            // A genuinely empty disclosure slot ("a~~b") is malformed.
            if (string.IsNullOrEmpty(parts[i]))
                throw new MalformedJoseException("SD-JWT contains an empty Disclosure slot ('~~') (RFC 9901 §4).");
            disclosures.Add(Disclosure.Parse(parts[i]));
        }

        // Reconstruct the SD-JWT-without-KB string with its mandatory trailing '~' (RFC 9901 §7.3
        // sd_hash input): issuerJwt ~ D1 ~ … ~ Dn ~.
        var sdJwtWithoutKb = string.Concat(issuerJwt, "~");
        if (disclosures.Count > 0)
            sdJwtWithoutKb = string.Concat(issuerJwt, "~", string.Join("~", parts[1..disclosureEnd]), "~");

        return new SdJwtComponents(issuerJwt, disclosures, keyBindingJwt, sdJwtWithoutKb);
    }
}
