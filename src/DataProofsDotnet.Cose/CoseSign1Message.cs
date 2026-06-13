using DataProofsDotnet.Cose.Internal;

namespace DataProofsDotnet.Cose;

/// <summary>
/// A decoded COSE_Sign1 message (RFC 9052 §4.2). Immutable after construction; binary fields
/// are exposed as <see cref="ReadOnlyMemory{T}"/> views over internal buffers.
/// Obtain instances via <see cref="CoseSign1.Decode"/> or from a verification result.
/// </summary>
public sealed class CoseSign1Message
{
    private readonly byte[] _protectedBytes;
    private readonly byte[]? _keyId;
    private readonly byte[]? _payload;
    private readonly byte[] _signature;

    internal CoseSign1Message(HeaderBag headers, bool isTagged, byte[] protectedBytes, byte[]? payload, byte[] signature)
    {
        _protectedBytes = protectedBytes;
        _keyId = headers.KeyId;
        _payload = payload;
        _signature = signature;
        IsTagged = isTagged;
        AlgorithmId = headers.AlgorithmId;
        AlgorithmText = headers.AlgorithmText;
        AlgorithmValueInvalid = headers.AlgorithmValueInvalid;
        Algorithm = headers.AlgorithmId is { } id && CoseAlgorithms.TryMap(id, out CoseAlgorithm mapped) ? mapped : null;
        ContentType = headers.ContentType;
        ContentFormat = headers.ContentFormat is >= int.MinValue and <= int.MaxValue ? (int?)headers.ContentFormat : null;
        ContentTypeIsProtected = headers.ContentTypeIsProtected;
        Type = headers.Type;
        TypeIsProtected = headers.TypeIsProtected;
        UnknownCriticalHeaderLabels = headers.UnknownCriticalLabels;
        MissingCriticalHeaderLabels = ComputeMissingCriticalLabels(headers);
    }

    /// <summary>
    /// RFC 9052 §3.1: every label named in the crit (2) array MUST also appear as a parameter in
    /// the protected header bucket. Returns the crit labels that have no matching protected
    /// parameter — a non-empty list means the message must be rejected.
    /// </summary>
    private static IReadOnlyList<string> ComputeMissingCriticalLabels(HeaderBag headers)
    {
        List<string>? missing = null;
        foreach (long label in headers.CriticalIntLabels)
        {
            if (!headers.IsProtectedLabelPresent(label))
            {
                (missing ??= []).Add(label.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
        }

        foreach (string label in headers.CriticalTextLabels)
        {
            if (!headers.IsProtectedLabelPresent(label))
            {
                (missing ??= []).Add($"\"{label}\"");
            }
        }

        return missing ?? (IReadOnlyList<string>)Array.Empty<string>();
    }

    /// <summary>Whether the message carried the COSE_Sign1 CBOR tag (18).</summary>
    public bool IsTagged { get; }

    /// <summary>
    /// The algorithm (label 1) header mapped to the supported v1 set, or <see langword="null"/>
    /// when the header is absent or carries an identifier outside <see cref="CoseAlgorithm"/>.
    /// </summary>
    public CoseAlgorithm? Algorithm { get; }

    /// <summary>The kid (label 4) header, or <see langword="null"/> when absent.</summary>
    /// <remarks>The explicit null check matters: the implicit <c>byte[]</c> conversion would
    /// otherwise wrap a null array as a non-null empty memory.</remarks>
    public ReadOnlyMemory<byte>? KeyId => _keyId is null ? null : (ReadOnlyMemory<byte>?)_keyId;

    /// <summary>The content type (label 3) header when it is a text string, e.g. <c>application/vc</c>.</summary>
    public string? ContentType { get; }

    /// <summary>The content type (label 3) header when it is a CoAP content-format integer.</summary>
    public int? ContentFormat { get; }

    /// <summary>The typ (label 16, RFC 9596) header when it is a text string, e.g. <c>application/vc+cose</c>.</summary>
    public string? Type { get; }

    /// <summary>The embedded payload, or <see langword="null"/> when the payload is detached (nil).</summary>
    /// <remarks>A zero-length embedded payload is a non-null empty memory; only a detached (nil)
    /// payload yields <see langword="null"/>.</remarks>
    public ReadOnlyMemory<byte>? Payload => _payload is null ? null : (ReadOnlyMemory<byte>?)_payload;

    /// <summary>The raw signature bytes (fixed-width R‖S for ECDSA, 64 bytes for EdDSA).</summary>
    public ReadOnlyMemory<byte> Signature => _signature;

    /// <summary>The protected header bucket exactly as carried on the wire (the serialized byte string content).</summary>
    public ReadOnlyMemory<byte> EncodedProtectedHeaders => _protectedBytes;

    internal long? AlgorithmId { get; }

    internal string? AlgorithmText { get; }

    internal bool AlgorithmValueInvalid { get; }

    internal bool ContentTypeIsProtected { get; }

    internal bool TypeIsProtected { get; }

    internal IReadOnlyList<string> UnknownCriticalHeaderLabels { get; }

    /// <summary>
    /// crit (2) labels with no matching parameter in the protected header bucket (RFC 9052 §3.1).
    /// Non-empty ⇒ the message must not verify.
    /// </summary>
    internal IReadOnlyList<string> MissingCriticalHeaderLabels { get; }

    internal byte[]? PayloadBytes => _payload;

    internal byte[] SignatureBytes => _signature;

    internal byte[] ProtectedBytes => _protectedBytes;
}
