namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Options controlling SD-JWT issuance (RFC 9901 §5): which hash algorithm names the
/// Disclosures, how many decoy digests obscure the count, and an optional Holder confirmation
/// (<c>cnf</c>) public key for Key Binding. Immutable; defaults match the RFC's conventions.
/// </summary>
public sealed record SdJwtIssuerOptions
{
    /// <summary>The <c>_sd_alg</c> hash algorithm name (RFC 9901 §4.1.1). Defaults to <c>sha-256</c>.</summary>
    public string HashAlgorithm { get; init; } = SdHashAlgorithm.Default;

    /// <summary>
    /// The number of decoy digests added to each <c>_sd</c> array to obscure the true number of
    /// selectively disclosable claims (RFC 9901 §4.2.7). Defaults to 0.
    /// </summary>
    public int DecoyDigestCount { get; init; }

    /// <summary>
    /// The Holder's public confirmation key, emitted as the <c>cnf</c>/<c>jwk</c> claim for Key
    /// Binding (RFC 9901 §6 / §7.3). <c>null</c> to omit Key Binding support.
    /// </summary>
    public Jwk? HolderConfirmationKey { get; init; }
}
