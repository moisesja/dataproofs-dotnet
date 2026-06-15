using System.Text.Json;
using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt;

/// <summary>
/// Implements the SD-JWT payload-reconstruction algorithm (RFC 9901 §7.1): resolve every
/// <c>_sd</c> digest and array-element <c>{"...": digest}</c> placeholder against the supplied
/// Disclosures, recursively, producing the processed (disclosed) payload. Rejects unknown,
/// duplicate, and unused-Disclosure conditions with documented failures (RFC 9901 §7.1 steps and
/// §10 security considerations); decoy digests with no matching Disclosure are silently dropped.
/// </summary>
internal static class SdJwtReconstructor
{
    /// <summary>
    /// Maximum payload/disclosure nesting depth resolved during reconstruction. RFC 9901 §6.3
    /// recursive disclosures let a presentation chain one extra frame per link, bounded only by
    /// input size — so an attacker-rooted chain (a malicious/compromised Issuer, or any deployment
    /// whose Issuer-key resolver can return an attacker-controlled key) would otherwise drive the
    /// mutual recursion below into an uncatchable <c>StackOverflowException</c> that terminates the
    /// host process, defeating the verifier's fail-closed contract (PRD FR-3/FR-23). We bound it
    /// and fail closed as a normal <see cref="MalformedJoseException"/>. The limit matches the
    /// per-document JSON parse depth (<c>JsonNode.Parse</c> default <c>MaxDepth</c> = 64) and is far
    /// above any legitimate SD-JWT nesting.
    /// </summary>
    private const int MaxReconstructionDepth = 64;

    /// <summary>
    /// Reconstruct the disclosed payload. The input payload and Disclosures are consumed
    /// read-only; a fresh <see cref="JsonObject"/> is returned.
    /// </summary>
    /// <param name="payload">The SD-JWT issuer-signed payload (carries <c>_sd</c>/<c>...</c>/<c>_sd_alg</c>).</param>
    /// <param name="disclosures">The Disclosures presented alongside the SD-JWT.</param>
    /// <param name="sdAlg">The resolved <c>_sd_alg</c> hash algorithm name.</param>
    /// <exception cref="MalformedJoseException">
    /// On a duplicate digest in an <c>_sd</c> array, a Disclosure whose digest is referenced more
    /// than once, a Disclosure of the wrong shape for its placement, or a Disclosure that is
    /// presented but never referenced (RFC 9901 §7.1 / §10).
    /// </exception>
    public static JsonObject Reconstruct(JsonObject payload, IReadOnlyList<Disclosure> disclosures, string sdAlg)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(disclosures);

        // Index Disclosures by their digest under the active _sd_alg. A digest collision between
        // two distinct Disclosures is itself an attack signal — reject it.
        var byDigest = new Dictionary<string, Disclosure>(StringComparer.Ordinal);
        foreach (var disclosure in disclosures)
        {
            var digest = disclosure.ComputeDigest(sdAlg);
            if (!byDigest.TryAdd(digest, disclosure))
                throw new MalformedJoseException(
                    "Two SD-JWT Disclosures share the same digest; the presentation is malformed (RFC 9901 §7.1).");
        }

        var used = new HashSet<string>(StringComparer.Ordinal);
        var result = (JsonObject)ProcessNode(payload.DeepClone(), byDigest, used, depth: 0)!;

        // RFC 9901 §7.1 step 4.3.4: every presented Disclosure MUST be referenced exactly once by
        // a digest found in the payload. A leftover Disclosure means the Holder sent something the
        // SD-JWT does not account for — reject (defends against Disclosure injection).
        if (used.Count != byDigest.Count)
        {
            var unused = byDigest.Keys.Where(d => !used.Contains(d)).Count();
            throw new MalformedJoseException(
                $"{unused} presented SD-JWT Disclosure(s) were not referenced by any digest in the payload (RFC 9901 §7.1).");
        }

        return result;
    }

    private static JsonNode? ProcessNode(JsonNode? node, IReadOnlyDictionary<string, Disclosure> byDigest, HashSet<string> used, int depth)
    {
        // Bound the recursion. A chained recursive-disclosure presentation (RFC 9901 §6.3) adds one
        // frame per link; without this guard a deep chain overflows the stack and crashes the host
        // (uncatchable StackOverflowException) instead of failing closed. `>=` so the permitted
        // nesting matches the named bound exactly (depths 0..MaxReconstructionDepth-1).
        if (depth >= MaxReconstructionDepth)
            throw new MalformedJoseException(
                $"SD-JWT reconstruction exceeded the maximum nesting depth of {MaxReconstructionDepth} (RFC 9901 §7.1); the presentation is malformed.");

        switch (node)
        {
            case JsonObject obj:
                return ProcessObject(obj, byDigest, used, depth);
            case JsonArray arr:
                return ProcessArray(arr, byDigest, used, depth);
            default:
                return node;
        }
    }

    private static JsonObject ProcessObject(JsonObject obj, IReadOnlyDictionary<string, Disclosure> byDigest, HashSet<string> used, int depth)
    {
        var output = new JsonObject();

        // First copy non-control members, recursing into them.
        foreach (var (key, value) in obj.ToList())
        {
            if (key is "_sd" or "_sd_alg")
                continue;
            output[key] = ProcessNode(value?.DeepClone(), byDigest, used, depth + 1);
        }

        // Then resolve the _sd digest array into disclosed object properties.
        if (obj.TryGetPropertyValue("_sd", out var sdNode) && sdNode is not null)
        {
            if (sdNode is not JsonArray sdArray)
                throw new MalformedJoseException("SD-JWT '_sd' must be an array of digest strings (RFC 9901 §4.2.4.1).");

            var seenDigests = new HashSet<string>(StringComparer.Ordinal);
            foreach (var digestNode in sdArray)
            {
                if (digestNode is not JsonValue dv || dv.GetValueKind() != JsonValueKind.String)
                    throw new MalformedJoseException("SD-JWT '_sd' entries must be base64url digest strings (RFC 9901 §4.2.4.1).");
                var digest = dv.GetValue<string>();

                // RFC 9901 §7.1: a digest MUST NOT appear more than once within an _sd array.
                if (!seenDigests.Add(digest))
                    throw new MalformedJoseException("SD-JWT '_sd' array contains a duplicate digest (RFC 9901 §7.1).");

                if (!byDigest.TryGetValue(digest, out var disclosure))
                    continue; // No matching Disclosure: a decoy. Ignore it (RFC 9901 §4.2.7).

                if (disclosure.IsArrayElement)
                    throw new MalformedJoseException("An '_sd' digest resolved to an array-element Disclosure (RFC 9901 §7.1).");

                if (!used.Add(digest))
                    throw new MalformedJoseException("An SD-JWT Disclosure is referenced by more than one digest (RFC 9901 §7.1).");

                var name = disclosure.ClaimName!;
                // RFC 9901 §7.1: a disclosed claim name MUST NOT clash with a name already present
                // in the object (no overwriting a clear claim via a Disclosure).
                if (output.ContainsKey(name))
                    throw new MalformedJoseException(
                        $"Disclosed SD-JWT claim '{name}' collides with a claim already present in the object (RFC 9901 §7.1).");

                output[name] = ProcessNode(disclosure.ClaimValueNode?.DeepClone(), byDigest, used, depth + 1);
            }
        }

        return output;
    }

    private static JsonArray ProcessArray(JsonArray arr, IReadOnlyDictionary<string, Disclosure> byDigest, HashSet<string> used, int depth)
    {
        var output = new JsonArray();
        foreach (var element in arr)
        {
            // An array-element placeholder is an object with exactly one member named "...".
            if (element is JsonObject elemObj && IsArrayDisclosurePlaceholder(elemObj, out var digest))
            {
                if (!byDigest.TryGetValue(digest!, out var disclosure))
                    continue; // Decoy / undisclosed element: drop it (RFC 9901 §4.2.4.2 / §7.1).

                if (!disclosure.IsArrayElement)
                    throw new MalformedJoseException("An array '...' placeholder resolved to an object-property Disclosure (RFC 9901 §7.1).");

                if (!used.Add(digest!))
                    throw new MalformedJoseException("An SD-JWT Disclosure is referenced by more than one digest (RFC 9901 §7.1).");

                output.Add(ProcessNode(disclosure.ClaimValueNode?.DeepClone(), byDigest, used, depth + 1));
            }
            else
            {
                output.Add(ProcessNode(element?.DeepClone(), byDigest, used, depth + 1));
            }
        }
        return output;
    }

    private static bool IsArrayDisclosurePlaceholder(JsonObject obj, out string? digest)
    {
        digest = null;
        if (obj.Count != 1 || !obj.TryGetPropertyValue("...", out var v))
            return false;
        if (v is not JsonValue jv || jv.GetValueKind() != JsonValueKind.String)
            throw new MalformedJoseException("An array '...' disclosure placeholder must carry a base64url digest string (RFC 9901 §4.2.4.2).");
        digest = jv.GetValue<string>();
        return true;
    }
}
