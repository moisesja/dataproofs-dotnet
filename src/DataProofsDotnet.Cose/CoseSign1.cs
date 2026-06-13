using DataProofsDotnet.Cose.Internal;
using NetCrypto;

namespace DataProofsDotnet.Cose;

/// <summary>
/// COSE_Sign1 signing and verification per RFC 9052 (FR-19). Signing is asynchronous over a
/// NetCrypto <see cref="ISigner"/> — a signer backed by a non-exporting <c>IKeyStore</c> is
/// sufficient; no raw private-key bytes appear in any API. Verification is synchronous
/// (no I/O, NFR-3) over a raw public key. Stateless and thread-safe.
/// </summary>
public static class CoseSign1
{
    /// <summary>
    /// Signs <paramref name="payload"/> as a COSE_Sign1 message. The algorithm header (and any
    /// content type / typ headers from <paramref name="options"/>) is emitted in the protected
    /// bucket; kid is emitted unprotected. Output CBOR is canonical/deterministic (NFR-5).
    /// </summary>
    /// <exception cref="CoseException">
    /// Misconfiguration: the algorithm does not match the signer's key type, both
    /// <see cref="CoseSign1SignOptions.ContentType"/> and <see cref="CoseSign1SignOptions.ContentFormat"/>
    /// are set, or the signer produced an unusable signature encoding.
    /// </exception>
    public static async Task<byte[]> SignAsync(
        ReadOnlyMemory<byte> payload,
        ISigner signer,
        CoseSign1SignOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(options);
        CoseAlgorithm algorithm = options.Algorithm;
        if (!CoseAlgorithms.IsDefined(algorithm))
        {
            throw new CoseException($"COSE algorithm {(long)algorithm} is not in the supported set (EdDSA -8, ES256 -7, ES384 -35, ES256K -47).");
        }

        if (options.ContentType is not null && options.ContentFormat is not null)
        {
            throw new CoseException("ContentType and ContentFormat are mutually exclusive encodings of the content type (3) header.");
        }

        if (options.ContentFormat is < 0)
        {
            throw new CoseException("ContentFormat must be a non-negative CoAP content-format identifier.");
        }

        KeyType requiredKeyType = CoseAlgorithms.GetKeyType(algorithm);
        if (signer.KeyType != requiredKeyType)
        {
            throw new CoseException($"Algorithm {algorithm} requires a {requiredKeyType} key, but the signer holds {signer.KeyType}.");
        }

        byte[] protectedBytes = CoseSign1Codec.EncodeProtectedHeaders(algorithm, options.ContentType, options.ContentFormat, options.Type);
        byte[] signatureInput = CoseSign1Codec.BuildSignatureInput(protectedBytes, options.ExternalData.Span, payload.Span);
        byte[] rawSignature = await signer.SignAsync(signatureInput, cancellationToken).ConfigureAwait(false);
        byte[] signature = CoseAlgorithms.IsNistEcdsa(algorithm)
            ? EcdsaDerSignature.NormalizeToIeeeP1363(rawSignature, CoseAlgorithms.GetEcdsaFieldWidth(algorithm))
            : rawSignature;

        return CoseSign1Codec.EncodeMessage(
            protectedBytes,
            options.KeyId,
            options.DetachedPayload ? null : payload.ToArray(),
            signature,
            options.IncludeCoseSign1Tag);
    }

    /// <summary>
    /// Decodes a COSE_Sign1 message (tag 18 or untagged) without verifying anything.
    /// </summary>
    /// <exception cref="CoseException">The input is not a structurally valid COSE_Sign1.</exception>
    public static CoseSign1Message Decode(ReadOnlyMemory<byte> encodedMessage)
    {
        if (!CoseSign1Codec.TryDecode(encodedMessage, CoseTagAcceptance.Sign1, out CoseSign1Message? message, out CoseVerificationFailure? failure))
        {
            throw new CoseException(failure.Message);
        }

        return message;
    }

    /// <summary>
    /// Verifies a COSE_Sign1 message against a raw public key. Returns a structured result for
    /// every invalid input — malformed bytes, unexpected tags, unsupported algorithms, unknown
    /// critical headers, and bad signatures all yield <c>Verified == false</c> with a
    /// documented <see cref="CoseVerificationFailure.Code"/>, never an exception.
    /// </summary>
    /// <param name="encodedMessage">The encoded COSE_Sign1 (tag 18 or untagged).</param>
    /// <param name="keyType">The NetCrypto key type of <paramref name="publicKey"/>; must match the message's algorithm.</param>
    /// <param name="publicKey">The raw public key (Ed25519: 32 bytes; EC: SEC1 compressed or uncompressed point).</param>
    /// <param name="options">External AAD and detached-payload inputs.</param>
    public static CoseSign1VerificationResult Verify(
        ReadOnlyMemory<byte> encodedMessage,
        KeyType keyType,
        ReadOnlyMemory<byte> publicKey,
        CoseSign1VerifyOptions? options = null)
    {
        if (!CoseSign1Codec.TryDecode(encodedMessage, CoseTagAcceptance.Sign1, out CoseSign1Message? message, out CoseVerificationFailure? failure))
        {
            return CoseSign1VerificationResult.Fail(failure);
        }

        return VerifyCore(message, keyType, publicKey, options?.ExternalData ?? default, options?.DetachedPayload);
    }

    internal static CoseSign1VerificationResult VerifyCore(
        CoseSign1Message message,
        KeyType keyType,
        ReadOnlyMemory<byte> publicKey,
        ReadOnlyMemory<byte> externalData,
        ReadOnlyMemory<byte>? detachedPayload)
    {
        if (message.UnknownCriticalHeaderLabels.Count > 0)
        {
            return CoseSign1VerificationResult.Fail(
                CoseVerificationErrorCode.UnknownCriticalHeader,
                $"The crit (2) header lists labels this implementation does not understand: {string.Join(", ", message.UnknownCriticalHeaderLabels)} (RFC 9052 §3.1).",
                message);
        }

        if (message.MissingCriticalHeaderLabels.Count > 0)
        {
            // RFC 9052 §3.1: a label named in crit (2) MUST also be present as a parameter in the
            // protected bucket. A crit label we understand but that has no matching protected
            // parameter is a malformed message and must be rejected before any signature math.
            // (Unknown crit labels are caught above regardless of presence.)
            return CoseSign1VerificationResult.Fail(
                CoseVerificationErrorCode.MalformedMessage,
                $"The crit (2) header lists labels that are absent from the protected header bucket: {string.Join(", ", message.MissingCriticalHeaderLabels)} (RFC 9052 §3.1).",
                message);
        }

        if (message.AlgorithmText is not null || message.AlgorithmValueInvalid)
        {
            return CoseSign1VerificationResult.Fail(
                CoseVerificationErrorCode.UnsupportedAlgorithm,
                message.AlgorithmText is not null
                    ? $"COSE algorithm \"{message.AlgorithmText}\" is not in the supported set (EdDSA -8, ES256 -7, ES384 -35, ES256K -47)."
                    : "The algorithm (1) header value is neither an integer nor a text string.",
                message);
        }

        if (message.AlgorithmId is not { } algorithmId)
        {
            return CoseSign1VerificationResult.Fail(
                CoseVerificationErrorCode.MissingAlgorithm,
                "No algorithm (1) header parameter is present.",
                message);
        }

        if (!CoseAlgorithms.TryMap(algorithmId, out CoseAlgorithm algorithm))
        {
            return CoseSign1VerificationResult.Fail(
                CoseVerificationErrorCode.UnsupportedAlgorithm,
                $"COSE algorithm {algorithmId} is not in the supported set (EdDSA -8, ES256 -7, ES384 -35, ES256K -47).",
                message);
        }

        KeyType requiredKeyType = CoseAlgorithms.GetKeyType(algorithm);
        if (requiredKeyType != keyType)
        {
            return CoseSign1VerificationResult.Fail(
                CoseVerificationErrorCode.AlgorithmKeyMismatch,
                $"The message algorithm {algorithm} requires a {requiredKeyType} key, but a {keyType} key was supplied.",
                message);
        }

        if (message.PayloadBytes is not null && detachedPayload is not null)
        {
            throw new ArgumentException("The message carries an embedded payload; a detached payload must not be supplied.", nameof(detachedPayload));
        }

        byte[]? payload = message.PayloadBytes ?? detachedPayload?.ToArray();
        if (payload is null)
        {
            return CoseSign1VerificationResult.Fail(
                CoseVerificationErrorCode.PayloadMissing,
                "The message payload is detached (nil) and no detached payload was supplied.",
                message);
        }

        if (message.SignatureBytes.Length != CoseAlgorithms.GetSignatureLength(algorithm))
        {
            return CoseSign1VerificationResult.Fail(
                CoseVerificationErrorCode.InvalidSignature,
                $"The signature is {message.SignatureBytes.Length} bytes; {algorithm} requires {CoseAlgorithms.GetSignatureLength(algorithm)}.",
                message);
        }

        byte[] signatureInput = CoseSign1Codec.BuildSignatureInput(
            CoseSign1Codec.NormalizeProtectedForSignatureInput(message.ProtectedBytes),
            externalData.Span,
            payload);

        // Fail closed (FR-23): a malformed/wrong-length public key makes the NetCrypto import
        // throw (FormatException, ArgumentException, CryptographicException, …). Verification
        // must return a structured failure for any attacker-controlled input, never throw — the
        // same narrow catch the Core/Rdfc Data Integrity suites use. OperationCanceledException
        // is deliberately excluded so cooperative cancellation still propagates.
        bool verified;
        try
        {
            verified = CoseCryptography.Verify(keyType, publicKey.Span, signatureInput, message.SignatureBytes);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return CoseSign1VerificationResult.Fail(
                CoseVerificationErrorCode.InvalidSignature,
                "The supplied public key could not be used to verify the signature (the key is malformed or has the wrong length for the message algorithm).",
                message);
        }

        return verified
            ? CoseSign1VerificationResult.Success(message)
            : CoseSign1VerificationResult.Fail(CoseVerificationErrorCode.InvalidSignature, "Signature verification failed.", message);
    }

    /// <summary>
    /// Rebuilds the Sig_structure signing input for a decoded message — exposed internally for
    /// byte-exactness conformance tests against the cose-wg <c>ToBeSign_hex</c> intermediates.
    /// </summary>
    internal static byte[] GetSignatureInput(CoseSign1Message message, ReadOnlyMemory<byte> externalData = default, ReadOnlyMemory<byte>? detachedPayload = null)
    {
        byte[]? payload = message.PayloadBytes ?? detachedPayload?.ToArray()
            ?? throw new CoseException("The message payload is detached and no detached payload was supplied.");
        return CoseSign1Codec.BuildSignatureInput(
            CoseSign1Codec.NormalizeProtectedForSignatureInput(message.ProtectedBytes),
            externalData.Span,
            payload);
    }
}
