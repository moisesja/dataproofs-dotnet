using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// Issue #27: the package's source-generated metadata is bound to a copy of
/// <see cref="DataProofsJsonOptions.Default"/>. The copy matters for bbs-2023, whose
/// <c>DeriveProof</c> returns a reveal document serialized here: its escaping is the library's wire
/// output, not something a canonicalizer re-derives.
/// </summary>
public sealed class RdfcJsonTests
{
    [Fact]
    public void Options_CarryDefaultsWireSettings_AndResolveThroughThePackageContextOnly()
    {
        var options = RdfcJson.Options;

        options.IsReadOnly.Should().BeTrue();
        options.Encoder.Should().BeSameAs(DataProofsJsonOptions.Default.Encoder);
        options.DefaultIgnoreCondition.Should().Be(DataProofsJsonOptions.Default.DefaultIgnoreCondition);
        options.WriteIndented.Should().BeFalse();
        options.PropertyNamingPolicy.Should().BeNull();
        options.TypeInfoResolverChain.Should().ContainSingle().Which.Should().BeSameAs(RdfcJsonContext.Default);
    }

    [Fact]
    public void TypedMetadata_SerializesLikeDefault()
    {
        var node = new JsonObject { ["name"] = "<A+B & \u00e9>", ["absent"] = null, ["n"] = new JsonArray(1, null) };
        var proof = new DataIntegrityProof { Cryptosuite = "bbs-2023", Challenge = "<&'+>", ProofValue = "u2V0D+" };

        JsonSerializer.Serialize(node, RdfcJson.JsonObjectTypeInfo).Should().Be(JsonSerializer.Serialize(node, DataProofsJsonOptions.Default));
        JsonSerializer.Serialize(proof, RdfcJson.ProofTypeInfo).Should().Be(JsonSerializer.Serialize(proof, DataProofsJsonOptions.Default));
        JsonSerializer.Serialize(node, RdfcJson.JsonObjectTypeInfo).Should().Contain("<A+B & \u00e9>", "the relaxed encoder keeps these literal");
    }
}
