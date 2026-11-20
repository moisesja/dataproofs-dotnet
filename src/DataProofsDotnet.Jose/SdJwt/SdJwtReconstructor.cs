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
    /// <param name="trace">
    /// When supplied, records where each part of the returned payload came from (SD-JWT VC claim metadata reads it,
    /// draft-ietf-oauth-sd-jwt-vc-27 §5.6). It does not change what is reconstructed or refused.
    /// </param>
    /// <exception cref="MalformedJoseException">
    /// On a digest that appears more than once in the payload, directly or through a Disclosure, whether or
    /// not a Disclosure matches it; a Disclosure of the wrong shape for its placement; or a Disclosure that is
    /// presented but never referenced (RFC 9901 §7.1 / §10).
    /// </exception>
    public static JsonObject Reconstruct(
        JsonObject payload, IReadOnlyList<Disclosure> disclosures, string sdAlg, ReconstructionTrace? trace = null)
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

        var walk = new Walk(byDigest, trace);
        var result = (JsonObject)ProcessNode(payload.DeepClone(), walk, depth: 0)!;

        // RFC 9901 §7.1 step 4.3.4: every presented Disclosure MUST be referenced exactly once by
        // a digest found in the payload. A leftover Disclosure means the Holder sent something the
        // SD-JWT does not account for — reject (defends against Disclosure injection).
        if (walk.Used.Count != byDigest.Count)
        {
            var unused = byDigest.Keys.Where(d => !walk.Used.Contains(d)).Count();
            throw new MalformedJoseException(
                $"{unused} presented SD-JWT Disclosure(s) were not referenced by any digest in the payload (RFC 9901 §7.1).");
        }

        return result;
    }

    /// <summary>
    /// The state of one reconstruction: the Disclosures by digest, and every digest encountered and resolved so far.
    /// </summary>
    private sealed class Walk(IReadOnlyDictionary<string, Disclosure> byDigest, ReconstructionTrace? trace)
    {
        public IReadOnlyDictionary<string, Disclosure> ByDigest { get; } = byDigest;

        public ReconstructionTrace? Trace { get; } = trace;

        public HashSet<string> Seen { get; } = new(StringComparer.Ordinal);

        public HashSet<string> Used { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Records an embedded digest found in an <c>_sd</c> array or a <c>...</c> placeholder. RFC 9901 §7.1 step 4: "If
        /// any digest value is encountered more than once in the Issuer-signed JWT payload (directly or recursively via
        /// other Disclosures), the SD-JWT MUST be rejected" — decoys and withheld digests included, not only those a
        /// Disclosure resolves.
        /// </summary>
        public void Encounter(string digest)
        {
            if (!Seen.Add(digest))
                throw new MalformedJoseException(
                    "An SD-JWT digest appears more than once in the payload, directly or through a Disclosure (RFC 9901 §7.1 step 4).");
        }

        /// <summary>Marks <paramref name="digest"/> resolved; <see cref="Encounter"/> has refused any second occurrence.</summary>
        public void Resolve(string digest) => Used.Add(digest);
    }

    private const string NestedSdAlg =
        "SD-JWT '_sd_alg' MUST NOT be used in any object nested within the payload, in the clear or through a Disclosure (RFC 9901 §4.1.1).";

    private static JsonNode? ProcessNode(JsonNode? node, Walk walk, int depth)
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
                return ProcessObject(obj, walk, depth);
            case JsonArray arr:
                return ProcessArray(arr, walk, depth);
            default:
                return node;
        }
    }

    private static JsonObject ProcessObject(JsonObject obj, Walk walk, int depth)
    {
        var output = new JsonObject();
        walk.Trace?.AddObject(output);

        // First copy non-control members, recursing into them.
        foreach (var (key, value) in obj.ToList())
        {
            if (key is "_sd")
                continue;
            if (key is "_sd_alg")
            {
                // RFC 9901 §4.1.1: _sd_alg "MUST appear at the top level of the SD-JWT payload. It MUST NOT be used
                // in any object nested within the payload." Only the top-level one is a control claim (§7.1 step
                // 3.f); a nested one, in the clear or in a disclosed value, makes the SD-JWT invalid. Skipping it, as
                // releases up to 2.0.0 did, dropped its value unread, digests included.
                if (depth == 0)
                    continue;
                throw new MalformedJoseException(NestedSdAlg);
            }
            output[key] = ProcessNode(value?.DeepClone(), walk, depth + 1);
        }

        // Then resolve the _sd digest array into disclosed object properties.
        if (obj.TryGetPropertyValue("_sd", out var sdNode) && sdNode is not null)
        {
            if (sdNode is not JsonArray sdArray)
                throw new MalformedJoseException("SD-JWT '_sd' must be an array of digest strings (RFC 9901 §4.2.4.1).");

            foreach (var digestNode in sdArray)
            {
                if (digestNode is not JsonValue dv || dv.GetValueKind() != JsonValueKind.String)
                    throw new MalformedJoseException("SD-JWT '_sd' entries must be base64url digest strings (RFC 9901 §4.2.4.1).");
                var digest = dv.GetValue<string>();
                walk.Encounter(digest);

                if (!walk.ByDigest.TryGetValue(digest, out var disclosure))
                {
                    walk.Trace?.AddUnresolvedDigest(output);
                    continue; // No matching Disclosure: a decoy. Ignore it (RFC 9901 §4.2.7).
                }

                if (disclosure.IsArrayElement)
                    throw new MalformedJoseException("An '_sd' digest resolved to an array-element Disclosure (RFC 9901 §7.1).");

                walk.Resolve(digest);
                var name = disclosure.ClaimName!;

                // A Disclosure named _sd_alg would put the claim into this object: below the top level that is the
                // nested use §4.1.1 forbids; at the top level it meets the clear _sd_alg below, or stands in for it.
                if (name is "_sd_alg" && depth > 0)
                    throw new MalformedJoseException(NestedSdAlg);

                // RFC 9901 §7.1 step 3.c.ii.3: "If the claim name already exists at the level of the _sd key, the
                // SD-JWT MUST be rejected" (no overwriting a clear claim via a Disclosure). The signed object counts as
                // well as the output, so the top-level _sd_alg, which the output omits, is covered.
                if (output.ContainsKey(name) || obj.ContainsKey(name))
                    throw new MalformedJoseException(
                        $"Disclosed SD-JWT claim '{name}' collides with a claim already present in the object (RFC 9901 §7.1).");

                output[name] = ProcessNode(disclosure.ClaimValueNode?.DeepClone(), walk, depth + 1);
                walk.Trace?.AddDisclosedMember(output, name);
            }
        }

        return output;
    }

    private static JsonArray ProcessArray(JsonArray arr, Walk walk, int depth)
    {
        var output = new JsonArray();
        walk.Trace?.AddArray(output);
        foreach (var element in arr)
        {
            // An array-element placeholder is an object with exactly one member named "...".
            if (element is JsonObject elemObj && IsArrayDisclosurePlaceholder(elemObj, out var digest))
            {
                walk.Encounter(digest!);
                if (!walk.ByDigest.TryGetValue(digest!, out var disclosure))
                {
                    walk.Trace?.AddElement(output, ReconstructionTrace.Origin.Undisclosed);
                    continue; // Decoy / undisclosed element: drop it (RFC 9901 §4.2.4.2 / §7.1).
                }

                if (!disclosure.IsArrayElement)
                    throw new MalformedJoseException("An array '...' placeholder resolved to an object-property Disclosure (RFC 9901 §7.1).");

                walk.Resolve(digest!);
                output.Add(ProcessNode(disclosure.ClaimValueNode?.DeepClone(), walk, depth + 1));
                walk.Trace?.AddElement(output, ReconstructionTrace.Origin.Disclosed);
            }
            else
            {
                output.Add(ProcessNode(element?.DeepClone(), walk, depth + 1));
                walk.Trace?.AddElement(output, ReconstructionTrace.Origin.Clear);
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
