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

    /// <summary>
    /// The most path selections one validation makes, summed over every claim metadata entry and path component. The
    /// work is claims times the elements each path selects, so a large issuer-signed credential and a large document,
    /// each within its own bound, could otherwise take tens of seconds (a 27,000-leaf credential against 27,000 claims
    /// took 22 s). Figure 30 against its credential makes about thirty; a credential past this bound is refused, since
    /// processing that is required and cannot complete rejects (-27 §5.7).
    /// </summary>
    internal const int SelectionBudget = 4_000_000;

    private sealed class Budget
    {
        public int Remaining { get; set; } = SelectionBudget;
    }

    /// <summary>Validates <paramref name="root"/>; returns <c>null</c> when every claim metadata entry holds.</summary>
    /// <param name="root">The processed payload the reconstruction recorded in <paramref name="trace"/> returned.</param>
    /// <param name="trace">The reconstruction trace.</param>
    /// <param name="claims">The effective claim metadata.</param>
    /// <param name="allDisclosuresPresent">
    /// Every Disclosure is present (issuance), so an unresolved digest or element placeholder is a decoy. A Verifier
    /// cannot know that, and §5.6 forbids it to "treat absence of a selectively disclosable claim from a presentation as
    /// evidence that the Issuer failed to include a mandatory claim". The issuance check then runs twice: once on the
    /// credential as a Verifier sees it (array decoys counted as undisclosed elements, as -27 counts them), so it refuses
    /// whatever that Verifier would, and once on the complete Unsecured Payload (§5.6: "Whether a mandatory claim was
    /// included can be determined by a Holder that has all Disclosures by evaluating the path against the complete
    /// Unsecured Payload"), where array decoys are not elements, so a decoy cannot stand in for a mandatory element.
    /// The second pass reports only a missing mandatory claim: its indices skip the decoys, so its path errors and
    /// <c>sd</c> findings would be about other elements than the ones -27 numbers "as issued".
    /// </param>
    public static string? Validate(JsonObject root, ReconstructionTrace trace, IReadOnlyList<ClaimMetadata> claims, bool allDisclosuresPresent)
    {
        var budget = new Budget();
        foreach (var claim in claims)
        {
            if (ValidateOne(root, trace, claim, allDisclosuresPresent, complete: false, budget) is { } violation)
                return violation;
            if (allDisclosuresPresent && ValidateOne(root, trace, claim, allDisclosuresPresent, complete: true, budget) is { } incomplete)
                return incomplete;
        }
        return null;
    }

    private static string? ValidateOne(
        JsonObject root, ReconstructionTrace trace, ClaimMetadata claim, bool allDisclosuresPresent, bool complete, Budget budget)
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
                        return complete ? null : PathError(path, step, "an object");

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
                        return complete ? null : PathError(path, step, "an array");

                    var asIssued = complete
                        ? [.. trace.AsIssued(array).Where(e => e.Origin != ReconstructionTrace.Origin.Undisclosed)]
                        : trace.AsIssued(array);
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
            budget.Remaining -= next.Count;
            if (budget.Remaining < 0)
                return $"VC_CLAIM_METADATA_INVALID: evaluating the claim metadata against this credential selects more than {SelectionBudget} "
                    + $"elements, so it cannot be processed ({Revision} §5.7).";
            selection = next;
        }

        if (claim.Mandatory && absent)
            return $"VC_CLAIM_MANDATORY_MISSING: the mandatory claim {path} was not included in the issued credential ({Revision} §5.6, §5.6.3).";
        if (complete)
            return null;

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
