namespace DataProofsDotnet.Cose;

/// <summary>
/// Options controlling COSE_Sign1 creation (<see cref="CoseSign1.SignAsync"/>).
/// Immutable after construction (init-only).
/// </summary>
public sealed class CoseSign1SignOptions
{
    /// <summary>The signature algorithm. Must match the signer's key type.</summary>
    public required CoseAlgorithm Algorithm { get; init; }

    /// <summary>Optional kid (label 4), emitted in the unprotected bucket.</summary>
    public ReadOnlyMemory<byte>? KeyId { get; init; }

    /// <summary>
    /// Optional content type (label 3) as a media-type text string, emitted in the protected
    /// bucket. Mutually exclusive with <see cref="ContentFormat"/>.
    /// </summary>
    public string? ContentType { get; init; }

    /// <summary>
    /// Optional content type (label 3) as a CoAP content-format integer, emitted in the
    /// protected bucket. Mutually exclusive with <see cref="ContentType"/>.
    /// </summary>
    public int? ContentFormat { get; init; }

    /// <summary>Optional typ (label 16, RFC 9596) text string, emitted in the protected bucket.</summary>
    public string? Type { get; init; }

    /// <summary>
    /// When <see langword="true"/>, the payload is signed but carried detached: the message
    /// payload field is nil and the verifier must supply the payload
    /// (<see cref="CoseSign1VerifyOptions.DetachedPayload"/>).
    /// </summary>
    public bool DetachedPayload { get; init; }

    /// <summary>Whether to emit the COSE_Sign1 CBOR tag (18). Defaults to <see langword="true"/>.</summary>
    public bool IncludeCoseSign1Tag { get; init; } = true;

    /// <summary>
    /// Externally supplied authenticated data mixed into the Sig_structure (RFC 9052 §4.4) but
    /// not carried in the message. The verifier must supply the identical bytes. Empty = none.
    /// </summary>
    public ReadOnlyMemory<byte> ExternalData { get; init; }
}
