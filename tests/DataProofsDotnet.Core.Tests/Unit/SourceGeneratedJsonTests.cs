using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>
/// Issue #27 (native AOT and trimming): this package's types serialize through source-generated
/// metadata, byte-identical to the reflection-based serialization of earlier versions, and
/// <see cref="DataProofsJsonOptions.Default"/> keeps its behaviour for consumer types in JIT hosts.
/// </summary>
public sealed class SourceGeneratedJsonTests
{
    /// <summary>
    /// The pre-#27 oracle: the same wire settings as <see cref="DataProofsJsonOptions.Default"/> with
    /// the reflection resolver only. Test projects run under JIT with reflection enabled.
    /// </summary>
    private static readonly JsonSerializerOptions Reflection = new(DataProofsJsonOptions.Default)
    {
        TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
    };

    private static JsonElement Json(string text) => JsonDocument.Parse(text).RootElement.Clone();

    public static TheoryData<string, DataIntegrityProof> Proofs => new()
    {
        {
            "every member, array-form previousProof, awkward characters",
            new DataIntegrityProof
            {
                Id = "urn:uuid:proof-1",
                Cryptosuite = "eddsa-jcs-2022",
                Created = "2026-01-01T00:00:00Z",
                Expires = "2027-01-01T00:00:00Z",
                VerificationMethod = "did:example:issuer#key-1",
                ProofPurpose = ProofPurposes.AssertionMethod,
                Challenge = "c+h<a>l&l'e\"nge",
                Domain = "example.com",
                Nonce = "nönce ☃",
                PreviousProof = PreviousProofReference.FromValues(["urn:uuid:proof-0", "urn:uuid:proof-a"]),
                Context = Json("""["https://www.w3.org/ns/credentials/v2",{"x+y":"<&'>","é":1.5}]"""),
                ProofValue = "z3FXQ+/=",
                AdditionalProperties = new Dictionary<string, JsonElement>
                {
                    ["ext"] = Json("""{"a":[1,null,"s<"],"b":{}}"""),
                    ["nullExt"] = Json("null"),
                },
            }
        },
        { "minimal (type only)", new DataIntegrityProof() },
        {
            "string-form previousProof",
            new DataIntegrityProof { Cryptosuite = "ecdsa-jcs-2019", PreviousProof = "urn:uuid:proof-0", ProofValue = "zabc" }
        },
        {
            "empty extension bag",
            new DataIntegrityProof { Cryptosuite = "eddsa-rdfc-2022", AdditionalProperties = new Dictionary<string, JsonElement>() }
        },
    };

    [Theory]
    [MemberData(nameof(Proofs))]
    public void Proof_SourceGenerated_SerializesByteIdenticalToReflection(string label, DataIntegrityProof proof)
    {
        var viaReflection = JsonSerializer.SerializeToUtf8Bytes(proof, Reflection);

        // The typed overloads the package itself uses …
        JsonSerializer.SerializeToUtf8Bytes(proof, DataProofsJsonOptions.ProofTypeInfo).Should().Equal(viaReflection, label);
        JsonSerializer.SerializeToElement(proof, DataProofsJsonOptions.ProofTypeInfo).GetRawText()
            .Should().Be(Encoding.UTF8.GetString(viaReflection), label);
        JsonSerializer.SerializeToNode(proof, DataProofsJsonOptions.ProofTypeInfo)!.ToJsonString(DataProofsJsonOptions.Default)
            .Should().Be(Encoding.UTF8.GetString(viaReflection), label);
        // … and the options-based overload consumers use, which resolves through the source-generated link.
        JsonSerializer.SerializeToUtf8Bytes(proof, DataProofsJsonOptions.Default).Should().Equal(viaReflection, label);
    }

    [Theory]
    [MemberData(nameof(Proofs))]
    public void Proof_SourceGenerated_DeserializesLikeReflection(string label, DataIntegrityProof proof)
    {
        var json = JsonSerializer.Serialize(proof, Reflection);

        var viaSourceGen = JsonSerializer.Deserialize(json, DataProofsJsonOptions.ProofTypeInfo)!;
        var viaReflection = JsonSerializer.Deserialize<DataIntegrityProof>(json, Reflection)!;

        JsonSerializer.Serialize(viaSourceGen, Reflection).Should().Be(JsonSerializer.Serialize(viaReflection, Reflection), label);
        viaSourceGen.Type.Should().Be(viaReflection.Type, label);
        viaSourceGen.PreviousProof.Should().Be(viaReflection.PreviousProof, label);
        Keys(viaSourceGen).Should().Equal(Keys(viaReflection), label);

        static string[] Keys(DataIntegrityProof p) => p.AdditionalProperties?.Keys.ToArray() ?? [];
    }

    [Fact]
    public void Proof_AbsentTypeMember_KeepsTheDefault_LikeReflection()
    {
        // The source generator models init-only members as constructor parameters, which would reset a
        // missing `type` to null. `Type` is settable so the initializer default survives, as it does
        // with reflection and did in 1.3.x. (The pipeline still requires `type` on the wire.)
        const string json = """{"cryptosuite":"eddsa-jcs-2022","proofValue":"zabc"}""";

        JsonSerializer.Deserialize(json, DataProofsJsonOptions.ProofTypeInfo)!.Type
            .Should().Be(DataIntegrityProof.DataIntegrityProofType);
        JsonSerializer.Deserialize<DataIntegrityProof>(json, Reflection)!.Type
            .Should().Be(DataIntegrityProof.DataIntegrityProofType);
    }

    [Fact]
    public void Proof_ExtensionData_DeserializesThroughSourceGeneratedMetadata()
    {
        // An init-only extension-data bag makes the generated metadata throw at first use; this guards
        // the settable shape.
        const string json = """{"type":"DataIntegrityProof","ext":{"a":1}}""";

        var proof = JsonSerializer.Deserialize(json, DataProofsJsonOptions.ProofTypeInfo)!;

        proof.AdditionalProperties.Should().ContainKey("ext").WhoseValue.GetRawText().Should().Be("""{"a":1}""");
    }

    [Fact]
    public void JsonNodeFamily_SourceGenerated_SerializesByteIdenticalToReflection()
    {
        var node = new JsonObject
        {
            ["@context"] = new JsonArray("https://www.w3.org/ns/credentials/v2"),
            ["name+"] = "<&'>é",
            ["n"] = new JsonArray(1, null, 2.5),
            ["nested"] = new JsonObject { ["empty"] = new JsonObject(), ["t"] = true },
        };

        JsonSerializer.SerializeToElement(node, DataProofsJsonOptions.JsonObjectTypeInfo).GetRawText()
            .Should().Be(JsonSerializer.SerializeToElement(node, Reflection).GetRawText());
        JsonSerializer.SerializeToElement((JsonNode)node, DataProofsJsonOptions.JsonNodeTypeInfo).GetRawText()
            .Should().Be(JsonSerializer.SerializeToElement((JsonNode)node, Reflection).GetRawText());

        var element = Json("""{"a":"<+>","b":[null]}""");
        JsonSerializer.Serialize(element, DataProofsJsonOptions.JsonElementTypeInfo)
            .Should().Be(JsonSerializer.Serialize(element, Reflection));
    }

    [Fact]
    public void Default_IsReadOnly_AndResolvesThroughTheSourceGeneratedContextFirst()
    {
        var options = DataProofsJsonOptions.Default;

        options.IsReadOnly.Should().BeTrue();
        options.TypeInfoResolverChain[0].Should().BeSameAs(DataProofsJsonContext.Default);
        // The typed accessors are bound to Default, so they carry its encoder and null handling.
        DataProofsJsonOptions.ProofTypeInfo.Options.Should().BeSameAs(options);
        DataProofsJsonOptions.JsonObjectTypeInfo.Options.Should().BeSameAs(options);
        DataProofsJsonOptions.JsonNodeTypeInfo.Options.Should().BeSameAs(options);
        DataProofsJsonOptions.JsonElementTypeInfo.Options.Should().BeSameAs(options);
        // The context alone knows every type the package serializes: no link further down the chain
        // is ever consulted for them.
        foreach (var type in new[] { typeof(DataIntegrityProof), typeof(JsonObject), typeof(JsonNode), typeof(JsonElement) })
        {
            DataProofsJsonContext.Default.GetTypeInfo(type).Should().NotBeNull(type.Name);
        }
    }

    [Fact]
    public void Default_HasReflectionFallback_ExactlyWhenTheHostEnablesReflection()
    {
        var chain = DataProofsJsonOptions.Default.TypeInfoResolverChain;

        if (JsonSerializer.IsReflectionEnabledByDefault)
        {
            // An ordinary JIT host, such as this test run: consumer types keep serializing as before #27.
            chain.Should().HaveCount(2);
            chain[1].Should().BeOfType<DefaultJsonTypeInfoResolver>();
            JsonSerializer.Serialize(new ConsumerType { Name = "x" }, DataProofsJsonOptions.Default)
                .Should().Be("""{"Name":"x"}""");
        }
        else
        {
            // A trimmed or native-AOT host: the source-generated link only (exercised by tasks/aot-smoke).
            chain.Should().ContainSingle().Which.Should().BeSameAs(DataProofsJsonContext.Default);
        }
    }

    private sealed class ConsumerType
    {
        public string? Name { get; set; }

        public string? Omitted { get; set; }
    }
}
