namespace DataProofsDotnet.DataIntegrity;

/// <summary>
/// Resolves a verification-method URL to public key material plus the controller
/// metadata required for proof-purpose authorization (FR-7). This package ships no
/// DID-aware implementation; DID-method resolvers implement this interface in adapters
/// at their own composition layer.
/// </summary>
public interface IVerificationMethodResolver
{
    /// <summary>
    /// Resolves <paramref name="verificationMethodUrl"/>. Returns <c>null</c> when the
    /// method cannot be resolved (unknown URL, no extractable key). Implementations
    /// should throw only for infrastructure faults; the verification pipeline fails
    /// closed on either signal.
    /// </summary>
    /// <param name="verificationMethodUrl">The proof's <c>verificationMethod</c> value, treated opaquely.</param>
    /// <param name="cancellationToken">Cancels the resolution.</param>
    Task<ResolvedVerificationMethod?> ResolveAsync(
        string verificationMethodUrl,
        CancellationToken cancellationToken = default);
}
