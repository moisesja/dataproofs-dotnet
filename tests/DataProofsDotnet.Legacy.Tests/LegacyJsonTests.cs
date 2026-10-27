using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// Issue #27: the package's source-generated metadata is bound to a copy of
/// <see cref="DataProofsJsonOptions.Default"/>. Everything serialized here is canonicalized before it
/// is signed, so the settings do not reach the signed bytes; this pins that the package nonetheless
/// shares the library's one set of wire settings.
/// </summary>
public sealed class LegacyJsonTests
{
    [Fact]
    public void Options_CarryDefaultsWireSettings_AndResolveThroughThePackageContextOnly()
    {
        var options = LegacyJson.Options;

        options.IsReadOnly.Should().BeTrue();
        options.Encoder.Should().BeSameAs(DataProofsJsonOptions.Default.Encoder);
        options.DefaultIgnoreCondition.Should().Be(DataProofsJsonOptions.Default.DefaultIgnoreCondition);
        options.WriteIndented.Should().BeFalse();
        options.TypeInfoResolverChain.Should().ContainSingle().Which.Should().BeSameAs(LegacyJsonContext.Default);
    }

    [Fact]
    public void TypedMetadata_SerializesLikeDefault()
    {
        var node = new JsonObject { ["name"] = "<A+B & \u00e9>", ["n"] = new JsonArray(1, null) };
        var proof = new DataIntegrityProof { Type = "Ed25519Signature2020", Challenge = "<&'+>" };

        JsonSerializer.Serialize(node, LegacyJson.JsonObjectTypeInfo).Should().Be(JsonSerializer.Serialize(node, DataProofsJsonOptions.Default));
        JsonSerializer.Serialize((JsonNode)node, LegacyJson.JsonNodeTypeInfo).Should().Be(JsonSerializer.Serialize(node, DataProofsJsonOptions.Default));
        JsonSerializer.Serialize(proof, LegacyJson.ProofTypeInfo).Should().Be(JsonSerializer.Serialize(proof, DataProofsJsonOptions.Default));
    }
}
