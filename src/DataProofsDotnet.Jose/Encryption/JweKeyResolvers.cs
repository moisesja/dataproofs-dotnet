namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// Lookup of recipient decryption keys for <see cref="JweParser"/>: private ECDH JWKs for the
/// ECDH-ES / ECDH-1PU algorithms, or symmetric (<c>kty="oct"</c>) KEK JWKs for standalone
/// <c>A256KW</c>. Mirrors didcomm-dotnet's <c>IInternalSecretsLookup</c> (PRD §1.4 item 2);
/// synchronous because decryption performs no I/O (NFR-3 reserves async for signing/resolving
/// paths — callers performing I/O should pre-resolve).
/// </summary>
public interface IJweRecipientKeyResolver
{
    /// <summary>Return the decryption JWK held for <paramref name="kid"/>, or <c>null</c> when not held.</summary>
    /// <param name="kid">The recipient key identifier from the JWE.</param>
    Jwk? TryGet(string kid);

    /// <summary>
    /// Return the subset of <paramref name="kids"/> for which a key is held, preserving no
    /// particular order. Lets the parser pick a recipient without N lookups on multi-recipient
    /// envelopes.
    /// </summary>
    /// <param name="kids">Recipient kids carried by the JWE.</param>
    IReadOnlyList<string> FindPresent(IEnumerable<string> kids);
}

/// <summary>
/// Lookup of sender <i>public</i> keys for the authenticated (ECDH-1PU) path — the
/// <c>skid</c>/<c>apu</c>-named sender key whose static ECDH feeds <c>Zs</c>. Mirrors
/// didcomm-dotnet's <c>IInternalSenderKeyLookup</c> (PRD §1.4 item 2).
/// </summary>
public interface IJweSenderKeyResolver
{
    /// <summary>Return the sender's public JWK for <paramref name="skid"/>, or <c>null</c> when unknown.</summary>
    /// <param name="skid">The sender key identifier.</param>
    Jwk? TryGet(string skid);
}
