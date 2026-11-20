using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.SdJwt;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// The reconstructor reports where it resolved each presented Disclosure (issue #48): the claim path in the processed
/// payload, in the concrete form of draft-ietf-oauth-sd-jwt-vc-27 §5.6.1 (member names and array indices from the
/// top-level object down). The SD-JWT VC must-not-disclose rule reads it, and the Type Metadata <c>sd</c> rules can.
/// </summary>
public sealed class SdJwtReconstructorPositionTests
{
    private const string SdAlg = "sha-256";

    private static JsonArray Sd(params Disclosure[] disclosures)
    {
        var sd = new JsonArray();
        foreach (var disclosure in disclosures)
            sd.Add((JsonNode)disclosure.ComputeDigest(SdAlg));
        return sd;
    }

    private static JsonObject Placeholder(Disclosure disclosure) => new() { ["..."] = disclosure.ComputeDigest(SdAlg) };

    private static Dictionary<string, string> PathsByEncoded(JsonObject payload, params Disclosure[] disclosures)
    {
        SdJwtReconstructor.Reconstruct(payload, disclosures, SdAlg, out var positions);
        positions.Should().HaveCount(disclosures.Length, "every presented Disclosure is resolved exactly once");
        return positions.ToDictionary(p => p.Disclosure.Encoded, p => p.ToString());
    }

    [Fact]
    public void Each_structuring_style_records_its_claim_path()
    {
        var flat = Disclosure.ForObjectProperty("s1", "given_name", JsonValue.Create("John"));
        var structured = Disclosure.ForObjectProperty("s2", "locality", JsonValue.Create("Anytown"));
        var recursiveInner = Disclosure.ForObjectProperty("s3", "status", JsonValue.Create("employed"));
        var recursiveOuter = Disclosure.ForObjectProperty("s4", "employment", new JsonObject { ["_sd"] = Sd(recursiveInner) });
        var payload = new JsonObject
        {
            ["_sd"] = Sd(flat, recursiveOuter),
            ["address"] = new JsonObject { ["country"] = "US", ["_sd"] = Sd(structured) },
        };

        var paths = PathsByEncoded(payload, flat, structured, recursiveInner, recursiveOuter);

        paths[flat.Encoded].Should().Be("given_name");
        paths[structured.Encoded].Should().Be("address.locality");
        paths[recursiveOuter.Encoded].Should().Be("employment");
        paths[recursiveInner.Encoded].Should().Be("employment.status");
    }

    [Fact]
    public void An_array_index_counts_the_processed_array_so_withheld_and_decoy_elements_do_not_count()
    {
        // [withheld, "clear", disclosed, decoy, disclosed]: the processed array is ["clear", "b", "c"].
        var withheld = Disclosure.ForArrayElement("s-w", JsonValue.Create("a"));
        var second = Disclosure.ForArrayElement("s-b", JsonValue.Create("b"));
        var third = Disclosure.ForArrayElement("s-c", JsonValue.Create("c"));
        var payload = new JsonObject
        {
            ["nationalities"] = new JsonArray(
                Placeholder(withheld),
                JsonValue.Create("clear"),
                Placeholder(second),
                new JsonObject { ["..."] = "decoy-digest-with-no-disclosure-behind-it" },
                Placeholder(third)),
        };

        var paths = PathsByEncoded(payload, second, third);

        paths[second.Encoded].Should().Be("nationalities[1]");
        paths[third.Encoded].Should().Be("nationalities[2]");
    }

    [Fact]
    public void Paths_run_through_arrays_and_disclosed_values_alike()
    {
        // lists[0] is an array-element Disclosure whose value carries an _sd: the member resolves at lists[0].idx.
        var idx = Disclosure.ForObjectProperty("s-idx", "idx", JsonValue.Create(7));
        var element = Disclosure.ForArrayElement("s-el", new JsonObject { ["_sd"] = Sd(idx) });
        var nested = Disclosure.ForObjectProperty("s-n", "kind", JsonValue.Create("x"));
        var payload = new JsonObject
        {
            ["status"] = new JsonObject { ["lists"] = new JsonArray(Placeholder(element)) },
            ["items"] = new JsonArray(new JsonArray(new JsonObject { ["_sd"] = Sd(nested) })),
        };

        SdJwtReconstructor.Reconstruct(payload, [element, idx, nested], SdAlg, out var positions);

        var byEncoded = positions.ToDictionary(p => p.Disclosure.Encoded);
        byEncoded[element.Encoded].ToString().Should().Be("status.lists[0]");
        byEncoded[idx.Encoded].ToString().Should().Be("status.lists[0].idx");
        byEncoded[nested.Encoded].ToString().Should().Be("items[0][0].kind");
        byEncoded[idx.Encoded].TopLevelClaim.Should().Be("status");
        byEncoded[idx.Encoded].Path.Select(c => c.Name ?? (object)c.Index)
            .Should().Equal("status", "lists", 0, "idx");
    }

    [Fact]
    public void Reconstructing_without_disclosures_reports_no_positions()
    {
        SdJwtReconstructor.Reconstruct(new JsonObject { ["a"] = 1 }, [], SdAlg, out var positions);

        positions.Should().BeEmpty();
    }
}
