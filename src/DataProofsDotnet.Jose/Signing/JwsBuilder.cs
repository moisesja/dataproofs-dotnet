using System.Text;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Json;

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
    /// The DIDComm v2.1 signed-message media type. A JSON-serialized JWS declaring it carries the
    /// signer <c>kid</c> in the per-signature unprotected header under
    /// <see cref="JwsKidPlacement.Auto"/> (issue #25).
    /// </summary>
    private const string DidCommSignedMediaType = "application/didcomm-signed+json";

    /// <summary>
    /// The same media type with the <c>application/</c> prefix omitted. DIDComm v2.1 §Message
    /// Formats: "IANA types for DIDComm messages MAY omit the <c>application/</c> prefix; the
    /// recipient MUST treat media types not containing <c>/</c> as having the <c>application/</c>
    /// prefix present."
    /// </summary>
    private const string DidCommSignedMediaTypeShort = "didcomm-signed+json";

    /// <summary>
    /// Build a JSON-serialization JWS: Flattened when exactly one signer, General when two or
    /// more (RFC 7515 §7.2) — or always General when <paramref name="typ"/> is the DIDComm signed
    /// media type, which is the form its reference implementations require.
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
        {
            signatures.Add(await SignOneAsync(
                signer, payloadB64u, typ, unprotectedHeaderAvailable: true, cancellationToken).ConfigureAwait(false));
        }

        // One signer normally flattens (RFC 7515 §7.2.2), which is also the RFC 7520 cookbook's
        // json_flat form. DIDComm is the exception: every signed example in v2.1 Appendix C.2 uses
        // the General form even for a single signature, and didcomm-python 0.3.2 requires it —
        // `core/sign.py`'s unpack_sign calls validate_jws on the RAW envelope dict, which rejects
        // anything without a `signatures` array before authlib ever normalizes the serialization
        // (`core/validation.py`). The spec itself allows either form and requires recipients to
        // process both (v2.1 §Message Signing), so this is an interop accommodation, not a
        // conformance fix — hence it is scoped to the media type that needs it.
        var useGeneral = signatures.Count > 1 || IsDidCommSignedMediaType(typ);
        return useGeneral
            ? RenderGeneral(detachedPayload ? null : payloadB64u, signatures)
            : RenderFlattened(detachedPayload ? null : payloadB64u, signatures[0]);
    }

    /// <summary>Build a compact-serialization JWS: <c>BASE64URL(header).BASE64URL(payload).BASE64URL(signature)</c>.</summary>
    /// <param name="payload">Payload bytes.</param>
    /// <param name="signer">The single signer (compact serialization carries exactly one signature).</param>
    /// <param name="typ">Optional <c>typ</c> protected-header value.</param>
    /// <param name="detachedPayload">When <c>true</c>, the payload segment is left empty (RFC 7515 Appendix F).</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <exception cref="ArgumentException">
    /// When <paramref name="signer"/> both carries a <c>kid</c> and requests
    /// <see cref="JwsKidPlacement.Unprotected"/>: compact serialization has no unprotected header
    /// (RFC 7515 §7.1). A kid-less signer has nothing to place, so its placement is moot and no
    /// exception is thrown.
    /// </exception>
    public static async Task<string> BuildCompactAsync(
        ReadOnlyMemory<byte> payload,
        JwsSigner signer,
        string? typ = null,
        bool detachedPayload = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signer);

        var payloadB64u = Base64Url.Encode(payload.Span);
        var entry = await SignOneAsync(
            signer, payloadB64u, typ, unprotectedHeaderAvailable: false, cancellationToken).ConfigureAwait(false);

        return string.Concat(
            entry.ProtectedB64u, ".",
            detachedPayload ? string.Empty : payloadB64u, ".",
            Base64Url.Encode(entry.Signature));
    }

    private static async Task<SignatureEntry> SignOneAsync(
        JwsSigner signer,
        string payloadB64u,
        string? typ,
        bool unprotectedHeaderAvailable,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signer);

        var unprotectedKid = ResolveUnprotectedKid(signer, typ, unprotectedHeaderAvailable);
        var header = new JwsProtectedHeader
        {
            Alg = signer.Algorithm,
            // Exactly one header carries the kid — never both. RFC 7515 §7.2.1 requires the two
            // parameter-name sets to be disjoint, and strict verifiers enforce it (issue #17).
            Kid = unprotectedKid is null ? signer.Kid ?? string.Empty : string.Empty,
            Typ = typ,
        };
        var protectedB64u = header.EncodeBase64Url();
        var signingInput = Encoding.ASCII.GetBytes(protectedB64u + "." + payloadB64u);
        var signature = await signer.SignAsync(signingInput, cancellationToken).ConfigureAwait(false);
        return new SignatureEntry(protectedB64u, signature, unprotectedKid);
    }

    /// <summary>
    /// Decide whether this signature's <c>kid</c> travels in the per-signature unprotected
    /// <c>header</c>, returning the value to write there or <c>null</c> to keep it protected.
    /// </summary>
    /// <param name="signer">The signer, carrying the kid and the requested placement.</param>
    /// <param name="typ">The <c>typ</c> being stamped into the protected header, if any.</param>
    /// <param name="unprotectedHeaderAvailable">
    /// <c>false</c> for compact serialization, which has no unprotected header (RFC 7515 §7.1).
    /// </param>
    private static string? ResolveUnprotectedKid(JwsSigner signer, string? typ, bool unprotectedHeaderAvailable)
    {
        var kid = signer.Kid;
        if (string.IsNullOrEmpty(kid))
            return null; // Nothing to place; a kid-less envelope is byte-identical in every mode.

        switch (signer.KidPlacement)
        {
            case JwsKidPlacement.Protected:
                return null;

            case JwsKidPlacement.Unprotected when !unprotectedHeaderAvailable:
                // Fail loudly rather than quietly signing the kid the caller asked to leave
                // unsigned — that would change the signing input away from the requested shape.
                throw new ArgumentException(
                    "Compact JWS has no unprotected header (RFC 7515 §7.1), so JwsKidPlacement.Unprotected "
                    + "cannot be honored; use a JSON serialization or JwsKidPlacement.Protected.",
                    nameof(signer));

            case JwsKidPlacement.Unprotected:
                return kid;

            default:
                // Auto: the placement the declared media type requires. DIDComm v2.1 signed
                // messages carry the kid unprotected (Appendix C.2; both reference implementations
                // reject an envelope without it — issue #25). Everything else, and all of compact,
                // keeps it under the signature.
                return unprotectedHeaderAvailable && IsDidCommSignedMediaType(typ) ? kid : null;
        }
    }

    private static bool IsDidCommSignedMediaType(string? typ)
        => string.Equals(typ, DidCommSignedMediaType, StringComparison.OrdinalIgnoreCase)
        || string.Equals(typ, DidCommSignedMediaTypeShort, StringComparison.OrdinalIgnoreCase);

    private static string RenderFlattened(string? payloadB64u, SignatureEntry entry)
    {
        // Member order is the spec-conventional payload/protected/header/signature (RFC 7515
        // §7.2.2); a JsonObject preserves insertion order, so the kid-less output stays
        // byte-identical to the RFC 7520 cookbook json_flat form. The unprotected 'header' object
        // appears only when this signature's kid was placed there — carrying the same name in both
        // headers would violate RFC 7515 §7.2.1 (issue #17).
        var json = new JsonObject();
        if (payloadB64u is not null)
            json["payload"] = payloadB64u;
        json["protected"] = entry.ProtectedB64u;
        AddUnprotectedHeader(json, entry);
        json["signature"] = Base64Url.Encode(entry.Signature);
        // JoseJson.Default's relaxed encoder, so a '+' or a non-ASCII character in a kid emits as
        // the literal character — matching the protected header, which DeterministicJsonWriter
        // already writes with that encoder. The default HTML-escaping encoder would render the
        // same kid differently in the two headers of one envelope.
        return json.ToJsonString(JoseJson.Default);
    }

    private static string RenderGeneral(string? payloadB64u, IReadOnlyList<SignatureEntry> signatures)
    {
        var entries = new JsonArray();
        foreach (var entry in signatures)
        {
            var element = new JsonObject { ["protected"] = entry.ProtectedB64u };
            AddUnprotectedHeader(element, entry);
            element["signature"] = Base64Url.Encode(entry.Signature);
            entries.Add(element);
        }

        var json = new JsonObject();
        if (payloadB64u is not null)
            json["payload"] = payloadB64u;
        json["signatures"] = entries;
        // JoseJson.Default's relaxed encoder, so a '+' or a non-ASCII character in a kid emits as
        // the literal character — matching the protected header, which DeterministicJsonWriter
        // already writes with that encoder. The default HTML-escaping encoder would render the
        // same kid differently in the two headers of one envelope.
        return json.ToJsonString(JoseJson.Default);
    }

    private static void AddUnprotectedHeader(JsonObject signatureObject, SignatureEntry entry)
    {
        if (entry.UnprotectedKid is not null)
            signatureObject["header"] = new JsonObject { ["kid"] = entry.UnprotectedKid };
    }

    private readonly record struct SignatureEntry(string ProtectedB64u, byte[] Signature, string? UnprotectedKid);
}
