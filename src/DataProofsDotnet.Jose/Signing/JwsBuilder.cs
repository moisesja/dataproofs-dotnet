using System.Text;
using System.Text.Json;

namespace DataProofsDotnet.Jose.Signing;

/// <summary>
/// Builds JWS envelopes (PRD FR-13): compact serialization, Flattened JSON (one signer),
/// General JSON (any number of signers, multi-signature), and detached-payload variants
/// (RFC 7515 Appendix F).
/// </summary>
/// <remarks>
/// Ported from didcomm-dotnet <c>DidComm.Jose.Signing.JwsBuilder</c> (PRD §1.4 item 2):
/// signing-input construction (<c>ASCII(protectedB64u "." payloadB64u)</c>), deterministic
/// sorted header bytes, flattened-for-one / general-for-many selection. Adapted: payloads are
/// arbitrary bytes instead of DIDComm messages, signing flows through NetCrypto
/// <see cref="JwsSigner"/> (async, no raw private keys — AC-8), and compact/detached support
/// is new work the porting source lacked.
/// </remarks>
public static class JwsBuilder
{
    /// <summary>
    /// Build a JSON-serialization JWS: Flattened when exactly one signer, General when two or
    /// more (RFC 7515 §7.2).
    /// </summary>
    /// <param name="payload">Payload bytes; base64url-encoded as the JWS payload.</param>
    /// <param name="signers">One or more signers. Each contributes one signature entry.</param>
    /// <param name="typ">Optional <c>typ</c> protected-header value applied to every signature.</param>
    /// <param name="detachedPayload">
    /// When <c>true</c>, the output omits the <c>payload</c> member (detached payload,
    /// RFC 7515 Appendix F); verification then needs the payload-supplying parse overload.
    /// </param>
    /// <param name="cancellationToken">Cancels the signing operations.</param>
    public static async Task<string> BuildJsonAsync(
        ReadOnlyMemory<byte> payload,
        IReadOnlyList<JwsSigner> signers,
        string? typ = null,
        bool detachedPayload = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signers);
        if (signers.Count == 0)
            throw new ArgumentException("At least one signer is required.", nameof(signers));

        var payloadB64u = Base64Url.Encode(payload.Span);

        var signatures = new List<SignatureEntry>(signers.Count);
        foreach (var signer in signers)
            signatures.Add(await SignOneAsync(signer, payloadB64u, typ, cancellationToken).ConfigureAwait(false));

        return signatures.Count == 1
            ? RenderFlattened(detachedPayload ? null : payloadB64u, signatures[0])
            : RenderGeneral(detachedPayload ? null : payloadB64u, signatures);
    }

    /// <summary>Build a compact-serialization JWS: <c>BASE64URL(header).BASE64URL(payload).BASE64URL(signature)</c>.</summary>
    /// <param name="payload">Payload bytes.</param>
    /// <param name="signer">The single signer (compact serialization carries exactly one signature).</param>
    /// <param name="typ">Optional <c>typ</c> protected-header value.</param>
    /// <param name="detachedPayload">When <c>true</c>, the payload segment is left empty (RFC 7515 Appendix F).</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    public static async Task<string> BuildCompactAsync(
        ReadOnlyMemory<byte> payload,
        JwsSigner signer,
        string? typ = null,
        bool detachedPayload = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signer);

        var payloadB64u = Base64Url.Encode(payload.Span);
        var entry = await SignOneAsync(signer, payloadB64u, typ, cancellationToken).ConfigureAwait(false);

        return string.Concat(
            entry.ProtectedB64u, ".",
            detachedPayload ? string.Empty : payloadB64u, ".",
            Base64Url.Encode(entry.Signature));
    }

    private static async Task<SignatureEntry> SignOneAsync(
        JwsSigner signer, string payloadB64u, string? typ, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signer);

        var header = new JwsProtectedHeader
        {
            Alg = signer.Algorithm,
            Kid = signer.Kid ?? string.Empty,
            Typ = typ,
        };
        var protectedB64u = header.EncodeBase64Url();
        var signingInput = Encoding.ASCII.GetBytes(protectedB64u + "." + payloadB64u);
        var signature = await signer.SignAsync(signingInput, cancellationToken).ConfigureAwait(false);
        return new SignatureEntry(protectedB64u, signer.Kid, signature);
    }

    private static string RenderFlattened(string? payloadB64u, SignatureEntry entry)
    {
        // Anonymous-object member order is the spec-conventional payload/protected/header/signature;
        // 'header' (unprotected, kid carrier) is omitted entirely when the signer has no kid so a
        // kid-less JWS byte-matches the RFC 7520 cookbook json_flat form.
        if (string.IsNullOrEmpty(entry.Kid))
        {
            return payloadB64u is null
                ? JsonSerializer.Serialize(new
                {
                    @protected = entry.ProtectedB64u,
                    signature = Base64Url.Encode(entry.Signature),
                })
                : JsonSerializer.Serialize(new
                {
                    payload = payloadB64u,
                    @protected = entry.ProtectedB64u,
                    signature = Base64Url.Encode(entry.Signature),
                });
        }

        return payloadB64u is null
            ? JsonSerializer.Serialize(new
            {
                @protected = entry.ProtectedB64u,
                header = new { kid = entry.Kid },
                signature = Base64Url.Encode(entry.Signature),
            })
            : JsonSerializer.Serialize(new
            {
                payload = payloadB64u,
                @protected = entry.ProtectedB64u,
                header = new { kid = entry.Kid },
                signature = Base64Url.Encode(entry.Signature),
            });
    }

    private static string RenderGeneral(string? payloadB64u, IReadOnlyList<SignatureEntry> signatures)
    {
        var entries = signatures.Select(s => string.IsNullOrEmpty(s.Kid)
            ? (object)new
            {
                @protected = s.ProtectedB64u,
                signature = Base64Url.Encode(s.Signature),
            }
            : new
            {
                @protected = s.ProtectedB64u,
                header = new { kid = s.Kid },
                signature = Base64Url.Encode(s.Signature),
            }).ToArray();

        return payloadB64u is null
            ? JsonSerializer.Serialize(new { signatures = entries })
            : JsonSerializer.Serialize(new { payload = payloadB64u, signatures = entries });
    }

    private readonly record struct SignatureEntry(string ProtectedB64u, string? Kid, byte[] Signature);
}
