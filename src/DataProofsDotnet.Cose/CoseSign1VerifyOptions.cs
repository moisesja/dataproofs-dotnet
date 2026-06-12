namespace DataProofsDotnet.Cose;

/// <summary>
/// Options controlling COSE_Sign1 verification (<see cref="CoseSign1.Verify"/>).
/// Immutable after construction (init-only).
/// </summary>
public sealed class CoseSign1VerifyOptions
{
    /// <summary>
    /// Externally supplied authenticated data that was mixed into the Sig_structure at signing
    /// time (RFC 9052 §4.4). Must be byte-identical to the signer's value. Empty = none.
    /// </summary>
    public ReadOnlyMemory<byte> ExternalData { get; init; }

    /// <summary>
    /// The payload for a detached-payload message (message payload field is nil). Must not be
    /// supplied when the message carries an embedded payload.
    /// </summary>
    public ReadOnlyMemory<byte>? DetachedPayload { get; init; }
}
