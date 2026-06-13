using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Signing;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Issues SD-JWTs (RFC 9901 §5): walks an input claims set against a <see cref="DisclosureFrame"/>,
/// replaces selectively disclosable claims with salted-hash digests (object properties into
/// <c>_sd</c> arrays, array elements into <c>{"...": digest}</c> placeholders, recursively),
/// adds decoy digests, writes <c>_sd_alg</c> and an optional <c>cnf</c> Holder key, signs the
/// resulting payload as a JWS through a NetCrypto <see cref="JwsSigner"/>, and returns the
/// combined issuance string. Stateless and thread-safe.
/// </summary>
public static class SdJwtIssuer
{
    /// <summary>The result of issuing an SD-JWT: the combined serialization plus its parts.</summary>
    /// <param name="Issuance">The full SD-JWT compact serialization (<c>issuer-JWT~D1~…~Dn~</c>).</param>
    /// <param name="IssuerJwt">The signed issuer JWT (the issuance string's first element).</param>
    /// <param name="Disclosures">Every Disclosure produced, in creation order.</param>
    public sealed record Result(string Issuance, string IssuerJwt, IReadOnlyList<Disclosure> Disclosures);

    /// <summary>
    /// Issue an SD-JWT from an input claims set and a disclosure frame.
    /// </summary>
    /// <param name="claims">The input claims set (a JSON object). Not mutated.</param>
    /// <param name="frame">Which claims are selectively disclosable.</param>
    /// <param name="signer">The Issuer's NetCrypto-backed JWS signer.</param>
    /// <param name="options">Issuance options (hash algorithm, decoys, holder cnf key).</param>
    /// <param name="typ">The issuer-JWT <c>typ</c> protected-header value (e.g. <c>example+sd-jwt</c>, <c>dc+sd-jwt</c>).</param>
    /// <param name="cancellationToken">Cancels the signing operation.</param>
    /// <exception cref="MalformedJoseException">When the frame references a claim shape the claims set does not have.</exception>
    public static async Task<Result> IssueAsync(
        JsonObject claims,
        DisclosureFrame frame,
        JwsSigner signer,
        SdJwtIssuerOptions? options = null,
        string? typ = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(frame);
        ArgumentNullException.ThrowIfNull(signer);

        options ??= new SdJwtIssuerOptions();
        if (!SdHashAlgorithm.IsSupported(options.HashAlgorithm))
            throw new MalformedJoseException($"Unsupported SD-JWT '_sd_alg' value '{options.HashAlgorithm}'.");
        if (options.DecoyDigestCount < 0)
            throw new ArgumentOutOfRangeException(nameof(options), "DecoyDigestCount must be non-negative.");

        var crypto = new JoseCryptoProvider();
        var disclosures = new List<Disclosure>();

        var payload = (JsonObject)ApplyFrame((JsonObject)claims.DeepClone(), frame, options, crypto, disclosures);

        payload["_sd_alg"] = options.HashAlgorithm;
        if (options.HolderConfirmationKey is not null)
            payload["cnf"] = BuildConfirmation(options.HolderConfirmationKey);

        var payloadBytes = CompactJwt.SerializePayload(payload);
        var issuerJwt = await JwsBuilder.BuildCompactAsync(payloadBytes, signer, typ: typ, detachedPayload: false, cancellationToken)
            .ConfigureAwait(false);

        var issuance = string.Concat(issuerJwt, "~",
            disclosures.Count == 0 ? string.Empty : string.Join("~", disclosures.Select(d => d.Encoded)) + "~");
        // Normalize: when there are no disclosures the issuance is "<jwt>~".
        if (disclosures.Count == 0)
            issuance = issuerJwt + "~";

        return new Result(issuance, issuerJwt, disclosures);
    }

    private static JsonNode ApplyFrame(
        JsonObject obj,
        DisclosureFrame frame,
        SdJwtIssuerOptions options,
        JoseCryptoProvider crypto,
        List<Disclosure> disclosures)
    {
        var sdDigests = new List<string>();

        foreach (var (claimName, entry) in frame.Entries)
        {
            if (!obj.TryGetPropertyValue(claimName, out var value))
                throw new MalformedJoseException($"DisclosureFrame references claim '{claimName}' that is not present in the claims set.");

            switch (entry.Kind)
            {
                case DisclosureFrame.FrameKind.WholeValue:
                {
                    obj.Remove(claimName);
                    var salt = SaltSource.Generate(crypto);
                    var disclosure = Disclosure.ForObjectProperty(salt, claimName, value);
                    disclosures.Add(disclosure);
                    sdDigests.Add(disclosure.ComputeDigest(options.HashAlgorithm));
                    break;
                }

                case DisclosureFrame.FrameKind.NestedObject:
                {
                    if (value is not JsonObject nestedObj)
                        throw new MalformedJoseException($"DisclosureFrame marks claim '{claimName}' as an object, but its value is not a JSON object.");

                    // Recurse: rewrite the nested object so its named sub-claims become _sd digests.
                    var rewritten = (JsonObject)ApplyFrame((JsonObject)nestedObj.DeepClone(), entry.Nested!, options, crypto, disclosures);

                    if (entry.Recursive)
                    {
                        // §6.3: wrap the rewritten object in its own Disclosure; the parent keeps
                        // only the digest of that Disclosure.
                        obj.Remove(claimName);
                        var salt = SaltSource.Generate(crypto);
                        var disclosure = Disclosure.ForObjectProperty(salt, claimName, rewritten);
                        disclosures.Add(disclosure);
                        sdDigests.Add(disclosure.ComputeDigest(options.HashAlgorithm));
                    }
                    else
                    {
                        // §6.2: the object stays in the clear, carrying its own _sd array.
                        obj[claimName] = rewritten;
                    }
                    break;
                }

                case DisclosureFrame.FrameKind.ArrayElements:
                {
                    if (value is not JsonArray array)
                        throw new MalformedJoseException($"DisclosureFrame marks claim '{claimName}' as an array, but its value is not a JSON array.");

                    var newArray = new JsonArray();
                    for (var i = 0; i < array.Count; i++)
                    {
                        if (entry.ArrayIndices!.Contains(i))
                        {
                            var salt = SaltSource.Generate(crypto);
                            var disclosure = Disclosure.ForArrayElement(salt, array[i]);
                            disclosures.Add(disclosure);
                            var digest = disclosure.ComputeDigest(options.HashAlgorithm);
                            newArray.Add(new JsonObject { ["..."] = digest });
                        }
                        else
                        {
                            newArray.Add(array[i]?.DeepClone());
                        }
                    }
                    obj[claimName] = newArray;
                    break;
                }
            }
        }

        // Decoys (RFC 9901 §4.2.7): random digest-shaped strings with no Disclosure behind them.
        for (var i = 0; i < options.DecoyDigestCount; i++)
            sdDigests.Add(GenerateDecoyDigest(options.HashAlgorithm, crypto));

        if (sdDigests.Count > 0)
        {
            // RFC 9901 §4.2.4.1 RECOMMENDS sorting the _sd digests so their order does not leak the
            // original claim order. Matches the worked-example payloads.
            sdDigests.Sort(StringComparer.Ordinal);
            var sd = new JsonArray();
            foreach (var d in sdDigests)
                sd.Add(d);
            obj["_sd"] = sd;
        }

        return obj;
    }

    private static string GenerateDecoyDigest(string sdAlg, JoseCryptoProvider crypto)
    {
        // A decoy is the digest of a random salt-length value — indistinguishable from a real
        // digest, but no Disclosure produces it (RFC 9901 §4.2.7).
        Span<byte> buffer = stackalloc byte[SaltSource.SaltByteLength];
        crypto.Fill(buffer);
        return SdHashAlgorithm.ComputeDigest(sdAlg, Base64Url.Encode(buffer));
    }

    private static JsonObject BuildConfirmation(Jwk holderKey)
    {
        // cnf = { "jwk": { public members only } } (RFC 7800 / RFC 9901 §6).
        var jwk = new JsonObject { ["kty"] = holderKey.Kty };
        if (holderKey.Crv is not null) jwk["crv"] = holderKey.Crv;
        if (holderKey.X is not null) jwk["x"] = holderKey.X;
        if (holderKey.Y is not null) jwk["y"] = holderKey.Y;
        return new JsonObject { ["jwk"] = jwk };
    }
}
