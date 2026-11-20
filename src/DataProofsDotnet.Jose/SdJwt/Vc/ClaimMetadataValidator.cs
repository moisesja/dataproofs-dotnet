using System.Text.Json.Nodes;

namespace DataProofsDotnet.Jose.SdJwt.Vc;

/// <summary>
/// Validates a processed SD-JWT VC payload against processed claim metadata (draft-ietf-oauth-sd-jwt-vc-27 §5.6). Each
/// path is evaluated as §5.6.1.2 defines it, but against the payload as issued, which <see cref="ReconstructionTrace"/>
/// records: integer and null components count the array elements that were not disclosed, an undisclosed element "was
/// included in the issued credential and is selectively disclosable; its contents are unknown, so any deeper path
/// components select no claims", and a claim is selectively disclosable only when "directly represented as a Disclosure",
/// not because an ancestor is. Validation fails (§5.6) when a path errors, when a <c>mandatory</c> claim is determined
/// not to have been included, or when a selected claim's position contradicts its <c>sd</c> value.
/// </summary>
internal static class ClaimMetadataValidator
{
    private const string Revision = SdJwtVcConstants.Revision;

    private readonly record struct Selected(JsonNode? Node, ReconstructionTrace.Origin Origin);

    /// <summary>Validates <paramref name="root"/>; returns <c>null</c> when every claim metadata entry holds.</summary>
    /// <param name="root">The processed payload the reconstruction recorded in <paramref name="trace"/> returned.</param>
    /// <param name="trace">The reconstruction trace.</param>
    /// <param name="claims">The effective claim metadata.</param>
    /// <param name="allDisclosuresPresent">
    /// Every Disclosure is present (issuance), so an unresolved digest is a decoy and a missing key is absent. A
    /// Verifier cannot know that, and §5.6 forbids it to "treat absence of a selectively disclosable claim from a
    /// presentation as evidence that the Issuer failed to include a mandatory claim".
    /// </param>
    public static string? Validate(JsonObject root, ReconstructionTrace trace, IReadOnlyList<ClaimMetadata> claims, bool allDisclosuresPresent)
    {
        foreach (var claim in claims)
        {
            if (ValidateOne(root, trace, claim, allDisclosuresPresent) is { } violation)
                return violation;
        }
        return null;
    }

    private static string? ValidateOne(JsonObject root, ReconstructionTrace trace, ClaimMetadata claim, bool allDisclosuresPresent)
    {
        var path = ClaimPathComponent.Format(claim.Path);
        List<Selected> selection = [new(root, ReconstructionTrace.Origin.Clear)];
        var absent = false;

        for (var step = 0; step < claim.Path.Count; step++)
        {
            var component = claim.Path[step];
            var last = step == claim.Path.Count - 1;
            var next = new List<Selected>();
            foreach (var selected in selection)
            {
                // An element that was not disclosed: present in the issued credential, contents unknown.
                if (selected.Origin == ReconstructionTrace.Origin.Undisclosed)
                    continue;

                if (component.Key is { } key)
                {
                    if (selected.Node is not JsonObject obj)
                        return PathError(path, step, "an object");

                    if (obj.TryGetPropertyValue(key, out var value))
                    {
                        next.Add(new(value, trace.IsDisclosedMember(obj, key)
                            ? ReconstructionTrace.Origin.Disclosed
                            : ReconstructionTrace.Origin.Clear));
                    }
                    else if (allDisclosuresPresent || trace.UnresolvedDigests(obj) == 0
                        || (last && claim.SelectiveDisclosure == ClaimSelectiveDisclosure.Never))
                    {
                        // Absent: nothing in this object can hide it. With an unresolved digest it may be withheld,
                        // unless it may not be selectively disclosable at all, in which case it was not included or
                        // was wrongly made disclosable: a violation either way.
                        absent = true;
                    }
                }
                else
                {
                    if (selected.Node is not JsonArray array)
                        return PathError(path, step, "an array");

                    var asIssued = trace.AsIssued(array);
                    if (component.Index is { } index)
                    {
                        if (index < asIssued.Count)
                            next.Add(Element(array, asIssued[index]));
                        else
                            absent = true;
                    }
                    else
                    {
                        foreach (var element in asIssued)
                            next.Add(Element(array, element));
                    }
                }
            }
            selection = next;
        }

        if (claim.Mandatory && absent)
            return $"VC_CLAIM_MANDATORY_MISSING: the mandatory claim {path} was not included in the issued credential ({Revision} §5.6, §5.6.3).";

        foreach (var selected in selection)
        {
            var disclosable = selected.Origin != ReconstructionTrace.Origin.Clear;
            if (claim.SelectiveDisclosure == ClaimSelectiveDisclosure.Always && !disclosable)
                return $"VC_CLAIM_SD_VIOLATION: the claim at {path} must be selectively disclosable (sd: always) but is in the clear ({Revision} §5.6, §5.6.4).";
            if (claim.SelectiveDisclosure == ClaimSelectiveDisclosure.Never && disclosable)
                return $"VC_CLAIM_SD_VIOLATION: the claim at {path} must not be selectively disclosable (sd: never) but is a Disclosure ({Revision} §5.6, §5.6.4).";
        }

        return null;
    }

    private static Selected Element(JsonArray array, (ReconstructionTrace.Origin Origin, int ProcessedIndex) element)
        => element.Origin == ReconstructionTrace.Origin.Undisclosed
            ? new(null, element.Origin)
            : new(array[element.ProcessedIndex], element.Origin);

    private static string PathError(string path, int step, string expected)
        => $"VC_CLAIM_PATH_INVALID: claim path {path} selects a value that is not {expected} at component {step} ({Revision} §5.6.1.2).";
}
