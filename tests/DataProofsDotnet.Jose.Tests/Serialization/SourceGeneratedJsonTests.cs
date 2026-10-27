using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using DataProofsDotnet.Jose.Encryption;
using DataProofsDotnet.Jose.Json;
using DataProofsDotnet.Jose.Signing;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Serialization;

/// <summary>
/// Issue #27 (native AOT and trimming): the JOSE DTOs serialize through source-generated metadata,
/// byte-identical to the reflection-based serialization of earlier versions, so signing inputs and
/// AADs do not move.
/// </summary>
public sealed class SourceGeneratedJsonTests
{
    /// <summary>The pre-#27 oracle: <see cref="JoseJson.Default"/>'s wire settings with the reflection resolver only.</summary>
    private static readonly JsonSerializerOptions Reflection = new(JoseJson.Default)
    {
        TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
    };

    private static JsonElement Json(string text) => JsonDocument.Parse(text).RootElement.Clone();

    private static Dictionary<string, JsonElement> Extensions() => new(StringComparer.Ordinal)
    {
        ["cty"] = Json("\"application/didcomm-plain+json\""),
        ["crit"] = Json("""["b64","x<&>"]"""),
        ["b64"] = Json("false"),
        ["ext"] = Json("""{"n":[1,null],"s":"é+"}"""),
    };

    private static JwsProtectedHeader JwsHeader(string label) => label switch
    {
        "alg, kid, typ, extensions" => new JwsProtectedHeader
        {
            Alg = JoseAlgorithms.EdDSA,
            Kid = "did:example:alice#key-1+<\u00e9>",
            Typ = "application/didcomm-signed+json",
            AdditionalMembers = Extensions(),
        },
        "alg only (kid sentinel, typ null)" => new JwsProtectedHeader { Alg = JoseAlgorithms.ES256 },
        "empty extension bag" => new JwsProtectedHeader
        {
            Alg = JoseAlgorithms.ES384,
            Kid = "k",
            AdditionalMembers = new Dictionary<string, JsonElement>(),
        },
        _ => throw new ArgumentOutOfRangeException(nameof(label), label, null),
    };

    [Theory]
    [InlineData("alg, kid, typ, extensions")]
    [InlineData("alg only (kid sentinel, typ null)")]
    [InlineData("empty extension bag")]
    public void JwsProtectedHeader_SourceGenerated_SerializesByteIdenticalToReflection(string label)
    {
        var header = JwsHeader(label);
        var viaReflection = JsonSerializer.Serialize(header, Reflection);

        JsonSerializer.Serialize(header, JoseJson.JwsHeaderTypeInfo).Should().Be(viaReflection, label);
        JsonSerializer.SerializeToNode(header, JoseJson.JwsHeaderTypeInfo)!.ToJsonString(JoseJson.Default).Should().Be(viaReflection, label);

        // The signing-input encoding is the deterministic writer over that node, minus the kid sentinel.
        var formerNode = (JsonObject)JsonSerializer.SerializeToNode(header, Reflection)!;
        if (formerNode.TryGetPropertyValue("kid", out var kid) && kid?.GetValue<string>() is "")
            formerNode.Remove("kid");
        header.EncodeBase64Url().Should().Be(Base64Url.Encode(DeterministicJsonWriter.WriteUtf8(formerNode)), label);
    }

    private static JweProtectedHeader JweHeader(string label) => label switch
    {
        "ECDH-1PU: epk with extensions, apu/apv, skid, extensions" => new JweProtectedHeader
        {
            Typ = "application/didcomm-encrypted+json",
            Alg = JoseAlgorithms.Ecdh1PuA256Kw,
            Enc = JoseAlgorithms.A256CbcHs512,
            Epk = new Jwk
            {
                Kty = "OKP",
                Crv = JoseAlgorithms.CrvX25519,
                X = "x+/=",
                AdditionalData = new Dictionary<string, JsonElement> { ["use+"] = Json("\"enc<\"") },
            },
            Apu = "YWxpY2U",
            Apv = "Ym9i",
            Skid = "did:example:alice#key-x25519-1",
            AdditionalMembers = Extensions(),
        },
        "A256KW with kid" => new JweProtectedHeader { Alg = JoseAlgorithms.A256Kw, Enc = JoseAlgorithms.A256Gcm, Kid = "kek+1" },
        "ECDH-ES minimal" => new JweProtectedHeader
        {
            Alg = JoseAlgorithms.EcdhEsA256Kw,
            Enc = JoseAlgorithms.XC20P,
            Epk = new Jwk { Kty = "EC", Crv = JoseAlgorithms.CrvP256, X = "x", Y = "y" },
        },
        _ => throw new ArgumentOutOfRangeException(nameof(label), label, null),
    };

    [Theory]
    [InlineData("ECDH-1PU: epk with extensions, apu/apv, skid, extensions")]
    [InlineData("A256KW with kid")]
    [InlineData("ECDH-ES minimal")]
    public void JweProtectedHeader_SourceGenerated_SerializesAndDecodesLikeReflection(string label)
    {
        var header = JweHeader(label);
        var viaReflection = JsonSerializer.Serialize(header, Reflection);

        JsonSerializer.Serialize(header, JoseJson.JweHeaderTypeInfo).Should().Be(viaReflection, label);
        var encoded = header.EncodeBase64Url();
        encoded.Should().Be(Base64Url.Encode(DeterministicJsonWriter.WriteUtf8(JsonSerializer.SerializeToNode(header, Reflection))), label);

        // Decoding (source-generated) yields the same model as reflection does from the same bytes.
        var wire = Encoding.UTF8.GetString(Base64Url.Decode(encoded));
        var viaSourceGenDecode = JweProtectedHeader.Decode(encoded);
        var viaReflectionDecode = JsonSerializer.Deserialize<JweProtectedHeader>(wire, Reflection)!;
        JsonSerializer.Serialize(viaSourceGenDecode, Reflection).Should().Be(JsonSerializer.Serialize(viaReflectionDecode, Reflection), label);
    }

    public static TheoryData<string, Jwk> Jwks => new()
    {
        {
            "EC private with every member and extensions",
            new Jwk
            {
                Kty = "EC",
                Crv = JoseAlgorithms.CrvP256,
                X = "x+",
                Y = "y/",
                D = "d=",
                K = null,
                Kid = "k<é>",
                Alg = JoseAlgorithms.ES256,
                Use = "sig",
                AdditionalData = new Dictionary<string, JsonElement>
                {
                    ["key_ops"] = Json("""["sign","verify"]"""),
                    ["x5c"] = Json("null"),
                },
            }
        },
        { "oct", new Jwk { Kty = "oct", K = "AAAA", Kid = "kek" } },
        { "OKP minimal", new Jwk { Kty = "OKP", Crv = JoseAlgorithms.CrvEd25519, X = "x" } },
    };

    [Theory]
    [MemberData(nameof(Jwks))]
    public void Jwk_SourceGenerated_SerializesAndDeserializesLikeReflection(string label, Jwk jwk)
    {
        var json = JsonSerializer.Serialize(jwk, Reflection);

        JsonSerializer.Serialize(jwk, JoseJson.JwkTypeInfo).Should().Be(json, label);
        // The options-based overload resolves through the context (no reflection link in JoseJson.Default).
        JsonSerializer.Serialize(jwk, JoseJson.Default).Should().Be(json, label);
        var back = JsonSerializer.Deserialize(json, JoseJson.JwkTypeInfo)!;
        JsonSerializer.Serialize(back, Reflection).Should().Be(json, label);
    }

    [Theory]
    [InlineData("""{"alg":"EdDSA"}""", false, "")]
    [InlineData("""{"alg":"EdDSA","kid":""}""", true, "")]
    [InlineData("""{"alg":"EdDSA","kid":"k+<>"}""", true, "k+<>")]
    public void JwsProtectedHeader_Decode_KeepsKidMembershipSemantics(string json, bool hasKidMember, string kid)
    {
        var header = JwsProtectedHeader.Decode(Base64Url.Encode(Encoding.UTF8.GetBytes(json)));

        header.HasKidMember.Should().Be(hasKidMember);
        header.Kid.Should().Be(kid);
    }

    [Fact]
    public void JwsProtectedHeader_Decode_RejectsDuplicateMembers()
    {
        // Behavioural: the JWS decoder parses with JoseJson.StrictDocument before the model is
        // deserialized, so this rejection does not depend on the typed metadata's options (see below).
        var act = () => JwsProtectedHeader.Decode(Base64Url.Encode("""{"alg":"EdDSA","alg":"ES256"}"""u8));

        act.Should().Throw<MalformedJoseException>();
    }

    [Fact]
    public void TypedMetadata_RejectsDuplicateMembers_BecauseItIsBoundToJoseJsonDefault()
    {
        // AllowDuplicateProperties=false lives on JoseJson.Default. The JWE header decoder and the SD-JWT
        // cnf/jwk reader deserialize with these typed infos and no earlier strict parse, so the binding is
        // the only guard against a last-wins duplicate there.
        Rejects(() => JsonSerializer.Deserialize("""{"alg":"EdDSA","alg":"ES256"}""", JoseJson.JwsHeaderTypeInfo));
        Rejects(() => JsonSerializer.Deserialize("""{"alg":"A256KW","alg":"A256KW","enc":"A256GCM"}""", JoseJson.JweHeaderTypeInfo));
        Rejects(() => JsonSerializer.Deserialize("""{"kty":"EC","kty":"OKP","crv":"X25519","x":"AA"}""", JoseJson.JwkTypeInfo));

        static void Rejects(Action deserialize) => deserialize.Should().Throw<JsonException>();
    }

    [Theory]
    [InlineData("""{"alg":"A256KW","alg":"A256KW","enc":"A256GCM"}""")]
    [InlineData("""{"alg":"ECDH-ES+A256KW","enc":"A256GCM","epk":{"kty":"EC","kty":"OKP","crv":"X25519","x":"AA"}}""")]
    public void JweProtectedHeader_Decode_RejectsDuplicateMembers_IncludingInTheEpk(string json)
    {
        var act = () => JweProtectedHeader.Decode(Base64Url.Encode(Encoding.UTF8.GetBytes(json)));

        act.Should().Throw<MalformedJoseException>();
    }

    [Fact]
    public void JoseJsonDefault_IsReadOnly_WithTheSourceGeneratedContextAsItsOnlyResolver()
    {
        JoseJson.Default.IsReadOnly.Should().BeTrue();
        JoseJson.Default.TypeInfoResolverChain.Should().ContainSingle().Which.Should().BeSameAs(JoseJsonContext.Default);
        JoseJson.JwsHeaderTypeInfo.Options.Should().BeSameAs(JoseJson.Default);
        JoseJson.JweHeaderTypeInfo.Options.Should().BeSameAs(JoseJson.Default);
        JoseJson.JwkTypeInfo.Options.Should().BeSameAs(JoseJson.Default);
        JoseJson.StringTypeInfo.Options.Should().BeSameAs(JoseJson.Default);
    }

    [Fact]
    public async Task VcJoseEnvelope_ProtectedHeader_IsPinned()
    {
        // The cty member is now serialized through typed metadata instead of an option-less reflection
        // call. Pin the whole protected header: sorted members, cty as the JSON string "vc", and the
        // relaxed encoder's literal '+' in the kid.
        var key = new NetCrypto.DefaultKeyGenerator().FromPrivateKey(NetCrypto.KeyType.Ed25519, Enumerable.Repeat((byte)1, 32).ToArray());
        var signer = new JwsSigner(new NetCrypto.KeyPairSigner(key, new NetCrypto.DefaultCryptoProvider()), "did:example:issuer#k+1");

        var envelope = await VcJose.EnvelopeCredentialAsync("""{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"]}"""u8.ToArray(), signer);

        Base64Url.DecodeUtf8(envelope.Split('.')[0])
            .Should().Be("""{"alg":"EdDSA","cty":"vc","kid":"did:example:issuer#k+1","typ":"vc+jwt"}""");
    }
}
