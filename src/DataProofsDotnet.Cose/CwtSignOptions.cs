namespace DataProofsDotnet.Cose;

/// <summary>
/// Options controlling CWT creation (<see cref="Cwt.SignAsync"/>).
/// Immutable after construction (init-only).
/// </summary>
public sealed class CwtSignOptions
{
    /// <summary>The COSE_Sign1 signature algorithm. Must match the signer's key type.</summary>
    public required CoseAlgorithm Algorithm { get; init; }

    /// <summary>Optional kid (label 4), emitted in the unprotected bucket.</summary>
    public ReadOnlyMemory<byte>? KeyId { get; init; }

    /// <summary>
    /// Whether to wrap the tagged COSE_Sign1 in the CWT CBOR tag (61), i.e. emit
    /// <c>61(18(…))</c> instead of <c>18(…)</c> (RFC 8392 §6). Defaults to <see langword="false"/>,
    /// matching the RFC 8392 Appendix A.3 signed-CWT example.
    /// </summary>
    public bool IncludeCwtTag { get; init; }
}
