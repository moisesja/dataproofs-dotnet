using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.Signing;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Hardening;

/// <summary>
/// Verify-side regression coverage for issue #19. RFC 7515 §5.2 step 4 requires the protected
/// and unprotected header parameter-name sets to be disjoint before a signature is verified.
/// </summary>
public class JwsParserHeaderDisjointnessTests
{
    private static readonly IKeyGenerator KeyGenerator = new DefaultKeyGenerator();
    private static readonly NetCrypto.ICryptoProvider NetCrypto = new DefaultCryptoProvider();
    private static readonly JoseCryptoProvider Jose = new();

    [Theory]
    [InlineData(false, "kid")]
    [InlineData(true, "kid")]
    [InlineData(false, "alg")]
    [InlineData(true, "alg")]
    [InlineData(false, "x-example")]
    [InlineData(true, "x-example")]
    public async Task JsonSerialization_DuplicateProtectedAndUnprotectedParameter_IsRejectedBeforeResolution(
        bool generalSerialization,
        string duplicateParameter)
    {
        var (parts, publicJwk) = await CreateCompactAsync(protectedKid: true);
        JsonObject unprotectedHeader;
        if (duplicateParameter == "kid")
        {
            unprotectedHeader = new JsonObject { ["kid"] = "k1" };
        }
        else if (duplicateParameter == "alg")
        {
            unprotectedHeader = new JsonObject { ["alg"] = "EdDSA" };
        }
        else
        {
            var protectedJson = JsonNode.Parse(
                Encoding.UTF8.GetString(DataProofsDotnet.Jose.Base64Url.Decode(parts[0])))!.AsObject();
            protectedJson[duplicateParameter] = "protected-value";
            parts[0] = DataProofsDotnet.Jose.Base64Url.Encode(
                Encoding.UTF8.GetBytes(protectedJson.ToJsonString()));
            unprotectedHeader = new JsonObject { [duplicateParameter] = "unprotected-value" };
        }
        var packed = RenderJson(parts, generalSerialization, unprotectedHeader);
        var resolverCalls = 0;

        var act = () => JwsParser.Parse(
            packed,
            _ =>
            {
                resolverCalls++;
                return publicJwk;
            },
            Jose);

        act.Should().Throw<MalformedJoseException>()
            .WithMessage($"*parameter '{duplicateParameter}' appears in both*");
        resolverCalls.Should().Be(0, "header disjointness is a pre-verification structural check");
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, true)]
    [InlineData(false, false)]
    [InlineData(true, false)]
    public async Task JsonSerialization_KidInExactlyOneHeader_VerifiesAndReportsSigner(
        bool generalSerialization,
        bool protectedKid)
    {
        var (parts, publicJwk) = await CreateCompactAsync(protectedKid);
        var unprotectedHeader = protectedKid ? null : new JsonObject { ["kid"] = "k1" };
        var packed = RenderJson(parts, generalSerialization, unprotectedHeader);

        var result = JwsParser.Parse(
            packed,
            kid => kid == "k1" ? publicJwk : null,
            Jose);

        result.SignerKid.Should().Be("k1");
        Encoding.UTF8.GetString(result.PayloadBytes).Should().Be("hello");
    }

    [Theory]
    [InlineData(false, "null")]
    [InlineData(true, "null")]
    [InlineData(false, "\"not-an-object\"")]
    [InlineData(true, "[]")]
    [InlineData(false, "42")]
    [InlineData(true, "false")]
    public async Task JsonSerialization_PresentNonObjectUnprotectedHeader_IsRejected(
        bool generalSerialization,
        string headerJson)
    {
        var (parts, _) = await CreateCompactAsync(protectedKid: true);
        var packedNode = JsonNode.Parse(RenderJson(parts, generalSerialization, unprotectedHeader: null))!.AsObject();
        if (generalSerialization)
        {
            packedNode["signatures"]!.AsArray()[0]!.AsObject()["header"] = JsonNode.Parse(headerJson);
        }
        else
        {
            packedNode["header"] = JsonNode.Parse(headerJson);
        }

        var act = () => JwsParser.Parse(packedNode.ToJsonString(), _ => null, Jose);

        act.Should().Throw<MalformedJoseException>().WithMessage("*'header' must be a JSON object*");
    }

    [Fact]
    public async Task JsonSerialization_MixedFlattenedAndGeneralMembers_IsRejectedBeforeResolution()
    {
        var (parts, publicJwk) = await CreateCompactAsync(protectedKid: true);
        var flattened = JsonNode.Parse(RenderJson(parts, generalSerialization: false, unprotectedHeader: null))!.AsObject();
        flattened["signatures"] = new JsonArray(new JsonObject
        {
            ["protected"] = parts[0],
            ["header"] = new JsonObject { ["kid"] = "k1" },
            ["signature"] = parts[2],
        });
        var resolverCalls = 0;

        var act = () => JwsParser.Parse(
            flattened.ToJsonString(),
            _ =>
            {
                resolverCalls++;
                return publicJwk;
            },
            Jose);

        act.Should().Throw<MalformedJoseException>().WithMessage("*cannot mix Flattened*");
        resolverCalls.Should().Be(0);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task JsonSerialization_EmptyProtectedHeader_IsMalformedNotRawArgumentException(
        bool generalSerialization)
    {
        var (parts, _) = await CreateCompactAsync(protectedKid: true);
        parts[0] = string.Empty;
        var packed = RenderJson(parts, generalSerialization, unprotectedHeader: null);

        var act = () => JwsParser.Parse(packed, _ => null, Jose);

        act.Should().Throw<MalformedJoseException>().WithMessage("*protected header is empty*");
    }

    private static async Task<(string[] Parts, Jwk PublicJwk)> CreateCompactAsync(bool protectedKid)
    {
        var pair = KeyGenerator.Generate(KeyType.Ed25519);
        var publicJwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, "k1");
        var signer = new JwsSigner(new KeyPairSigner(pair, NetCrypto), protectedKid ? "k1" : null);
        var compact = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes("hello"), signer);
        return (compact.Split('.'), publicJwk);
    }

    private static string RenderJson(string[] compactParts, bool generalSerialization, JsonObject? unprotectedHeader)
    {
        var signature = new JsonObject
        {
            ["protected"] = compactParts[0],
            ["signature"] = compactParts[2],
        };
        if (unprotectedHeader is not null)
            signature["header"] = unprotectedHeader;

        if (generalSerialization)
        {
            return new JsonObject
            {
                ["payload"] = compactParts[1],
                ["signatures"] = new JsonArray(signature),
            }.ToJsonString();
        }

        signature["payload"] = compactParts[1];
        return signature.ToJsonString();
    }
}
