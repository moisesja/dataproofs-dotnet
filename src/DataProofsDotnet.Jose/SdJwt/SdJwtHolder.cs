using DataProofsDotnet.Jose.Signing;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Holder-side SD-JWT operations (RFC 9901 §7): from an issued SD-JWT, select the subset of
/// Disclosures to reveal and assemble a presentation, optionally appending a Key Binding JWT
/// over the selected presentation. Stateless and thread-safe; the KB-JWT path is async over a
/// NetCrypto <see cref="JwsSigner"/>.
/// </summary>
public static class SdJwtHolder
{
    /// <summary>
    /// Build a presentation from an issued SD-JWT by keeping only the Disclosures whose encoded
    /// strings appear in <paramref name="disclosuresToReveal"/>, in their original issuance order.
    /// No Key Binding JWT is appended (the result ends in <c>~</c>).
    /// </summary>
    /// <param name="issuedSdJwt">The full issued SD-JWT (<c>issuer-JWT~D1~…~Dn~</c>).</param>
    /// <param name="disclosuresToReveal">The encoded Disclosure strings to keep; others are dropped.</param>
    /// <exception cref="MalformedJoseException">When <paramref name="issuedSdJwt"/> is not a valid SD-JWT.</exception>
    public static string CreatePresentation(string issuedSdJwt, IEnumerable<string> disclosuresToReveal)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuedSdJwt);
        ArgumentNullException.ThrowIfNull(disclosuresToReveal);

        var components = SdJwtComponents.Parse(issuedSdJwt);
        var keep = new HashSet<string>(disclosuresToReveal, StringComparer.Ordinal);

        var revealed = components.Disclosures
            .Select(d => d.Encoded)
            .Where(keep.Contains)
            .ToList();

        return string.Concat(
            components.IssuerJwt, "~",
            revealed.Count == 0 ? string.Empty : string.Join("~", revealed) + "~");
    }

    /// <summary>
    /// Build a presentation and append a Key Binding JWT binding it to <paramref name="audience"/>
    /// and <paramref name="nonce"/> (RFC 9901 §7.3). The <c>sd_hash</c> is computed over the
    /// selected SD-JWT (up to and including its final <c>~</c>) under the SD-JWT's <c>_sd_alg</c>.
    /// </summary>
    /// <param name="issuedSdJwt">The full issued SD-JWT.</param>
    /// <param name="disclosuresToReveal">The encoded Disclosure strings to keep.</param>
    /// <param name="holderSigner">The Holder's signer (its public key must match the issuer's <c>cnf</c>).</param>
    /// <param name="audience">The intended Verifier (KB-JWT <c>aud</c>).</param>
    /// <param name="nonce">The Verifier-supplied nonce (KB-JWT <c>nonce</c>).</param>
    /// <param name="issuedAt">The KB-JWT <c>iat</c>. Defaults to <see cref="DateTimeOffset.UtcNow"/>.</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <exception cref="MalformedJoseException">When the SD-JWT is malformed or its <c>_sd_alg</c> is unsupported.</exception>
    public static async Task<string> CreatePresentationWithKeyBindingAsync(
        string issuedSdJwt,
        IEnumerable<string> disclosuresToReveal,
        JwsSigner holderSigner,
        string audience,
        string nonce,
        DateTimeOffset? issuedAt = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(holderSigner);

        var sdJwtPresentation = CreatePresentation(issuedSdJwt, disclosuresToReveal);

        // Resolve _sd_alg from the issuer JWT payload (default sha-256 when absent).
        var issuerJwt = CompactJwt.Decode(SdJwtComponents.Parse(sdJwtPresentation).IssuerJwt);
        var sdAlg = SdJwtClaims.ResolveSdAlg(issuerJwt.Payload);

        var kbJwt = await KeyBindingJwt.IssueAsync(
            sdJwtPresentation, sdAlg, nonce, audience, issuedAt ?? DateTimeOffset.UtcNow, holderSigner, cancellationToken)
            .ConfigureAwait(false);

        return sdJwtPresentation + kbJwt;
    }
}
