using System.Text.Json;
using DataProofsDotnet.Cose.Internal;
using NetCrypto;

namespace DataProofsDotnet.Cose;

/// <summary>
/// The COSE half of VC-JOSE-COSE (FR-19): enveloping a W3C VCDM 2.0 credential as a
/// COSE_Sign1 per "Securing Verifiable Credentials using JOSE and COSE". The credential is
/// treated as opaque, well-formed JSON bytes — credential data-model validation is out of
/// scope (PRD §11). The envelope carries the content type (label 3) protected header
/// <c>application/vc</c> and the typ (label 16, RFC 9596) protected header
/// <c>application/vc+cose</c>; verification rejects envelopes where either header is wrong,
/// absent, or not integrity-protected. Stateless and thread-safe.
/// </summary>
public static class VcCose
{
    /// <summary>The required content type (label 3) protected header value: the VCDM 2.0 media type.</summary>
    public const string CredentialContentType = "application/vc";

    /// <summary>The required typ (label 16) protected header value: the COSE envelope media type.</summary>
    public const string EnvelopeType = "application/vc+cose";

    /// <summary>
    /// Envelopes a VCDM 2.0 credential (UTF-8 JSON object bytes) as a tagged COSE_Sign1 with
    /// the spec's content type and typ protected headers.
    /// </summary>
    /// <exception cref="CoseException">
    /// The payload is not a well-formed JSON object, or the algorithm does not match the
    /// signer's key type.
    /// </exception>
    public static Task<byte[]> EnvelopeCredentialAsync(
        ReadOnlyMemory<byte> credentialJson,
        ISigner signer,
        CoseAlgorithm algorithm,
        ReadOnlyMemory<byte>? keyId = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            using var document = JsonDocument.Parse(credentialJson);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new CoseException("A VCDM 2.0 credential must be a JSON object.");
            }
        }
        catch (JsonException ex)
        {
            throw new CoseException("The credential payload is not well-formed JSON.", ex);
        }

        var options = new CoseSign1SignOptions
        {
            Algorithm = algorithm,
            KeyId = keyId,
            ContentType = CredentialContentType,
            Type = EnvelopeType,
        };
        return CoseSign1.SignAsync(credentialJson, signer, options, cancellationToken);
    }

    /// <summary>
    /// Verifies a VC-JOSE-COSE COSE envelope: the typ (16) protected header must be
    /// <c>application/vc+cose</c> and the content type (3) protected header must be
    /// <c>application/vc</c> — a wrong, absent, or unprotected value is rejected with
    /// <see cref="CoseVerificationErrorCode.InvalidType"/> /
    /// <see cref="CoseVerificationErrorCode.InvalidContentType"/> — then the COSE_Sign1
    /// signature is verified. The enveloped credential is available as
    /// <see cref="CoseSign1Message.Payload"/> on the result's message.
    /// </summary>
    public static CoseSign1VerificationResult Verify(
        ReadOnlyMemory<byte> envelope,
        KeyType keyType,
        ReadOnlyMemory<byte> publicKey)
    {
        if (!CoseSign1Codec.TryDecode(envelope, CoseTagAcceptance.Sign1, out CoseSign1Message? message, out CoseVerificationFailure? failure))
        {
            return CoseSign1VerificationResult.Fail(failure);
        }

        if (message.Type != EnvelopeType || !message.TypeIsProtected)
        {
            return CoseSign1VerificationResult.Fail(
                CoseVerificationErrorCode.InvalidType,
                message.Type is null
                    ? $"VC-JOSE-COSE requires the typ (16) protected header \"{EnvelopeType}\"; the header is absent."
                    : message.TypeIsProtected
                        ? $"VC-JOSE-COSE requires the typ (16) protected header \"{EnvelopeType}\"; found \"{message.Type}\"."
                        : "VC-JOSE-COSE requires the typ (16) header to be integrity-protected; it was found in the unprotected bucket.",
                message);
        }

        if (message.ContentType != CredentialContentType || !message.ContentTypeIsProtected)
        {
            return CoseSign1VerificationResult.Fail(
                CoseVerificationErrorCode.InvalidContentType,
                message.ContentType is null
                    ? $"VC-JOSE-COSE requires the content type (3) protected header \"{CredentialContentType}\"; the header is absent."
                    : message.ContentTypeIsProtected
                        ? $"VC-JOSE-COSE requires the content type (3) protected header \"{CredentialContentType}\"; found \"{message.ContentType}\"."
                        : "VC-JOSE-COSE requires the content type (3) header to be integrity-protected; it was found in the unprotected bucket.",
                message);
        }

        return CoseSign1.VerifyCore(message, keyType, publicKey, externalData: default, detachedPayload: null);
    }
}
