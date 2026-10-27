using System.Text.Json;
using DataProofsDotnet.Jose.Signing;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Hardening;

/// <summary>
/// Issue #28: a JWS protected header whose decoded octets are not valid UTF-8 must be rejected as
/// <see cref="MalformedJoseException"/> on every entry point. RFC 7515 §5.2 step 3 requires the
/// verifier to check that the decoded header "is a UTF-8-encoded representation of a completely
/// valid JSON object". Before the fix only <c>JwsParser.Parse</c> rejected an invalid member
/// <em>name</em> — as a side effect of enumerating member names for the §5.2 step 4 disjointness
/// check, which the compact path skips — and an invalid extension <em>value</em> was accepted on
/// every path, the JSON one included. Every fixture here carries a genuine signature over the
/// malformed header: this is a contract and conformance gap, not a forgery, exactly as reported.
/// </summary>
public sealed class Issue28InvalidUtf8Tests
{
    private static readonly JoseCryptoProvider Jose = new();

    private const string Kid = "did:example:issuer#key-1";

    private static readonly byte[] Payload = Encoding.UTF8.GetBytes(
        """{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],"issuer":"did:example:issuer","credentialSubject":{"id":"did:example:s"}}""");

    // typ/cty are what VcJose requires; JwsParser ignores them, so one header shape drives every path.
    private static readonly byte[] HeaderPrefix = Encoding.UTF8.GetBytes(
        """{"alg":"EdDSA","typ":"vc+jwt","cty":"vc","kid":"did:example:issuer#key-1",""");

    /// <summary>
    /// Byte sequences that are not well-formed UTF-8 (RFC 3629 §4), each a different failure class
    /// so a validator that only catches one kind is caught out.
    /// </summary>
    private static readonly (string Hex, string Why)[] InvalidUtf8 =
    [
        ("FFFE", "bytes that never occur in UTF-8"),
        ("C080", "overlong encoding of U+0000"),
        ("EDA080", "UTF-16 surrogate U+D800 encoded as UTF-8"),
        ("E282", "truncated three-byte sequence"),
        ("80", "lone continuation byte"),
    ];

    public enum Placement
    {
        /// <summary>The invalid bytes form a member name: <c>{…, "&lt;bad&gt;": 1}</c>.</summary>
        MemberName,

        /// <summary>The invalid bytes form an extension member's string value: <c>{…, "x": "&lt;bad&gt;"}</c>.</summary>
        ExtensionValue,
    }

    [Theory]
    [InlineData("flattened", Placement.MemberName)]
    [InlineData("flattened", Placement.ExtensionValue)]
    [InlineData("general", Placement.MemberName)]
    [InlineData("general", Placement.ExtensionValue)]
    [InlineData("compact", Placement.MemberName)]
    [InlineData("compact", Placement.ExtensionValue)]
    [InlineData("vcjose", Placement.MemberName)]
    [InlineData("vcjose", Placement.ExtensionValue)]
    [InlineData("flattened-detached", Placement.MemberName)]
    [InlineData("flattened-detached", Placement.ExtensionValue)]
    [InlineData("compact-detached", Placement.MemberName)]
    [InlineData("compact-detached", Placement.ExtensionValue)]
    public async Task AProtectedHeaderThatIsNotValidUtf8_IsMalformed_BeforeKeyResolution(string entryPoint, Placement placement)
    {
        foreach (var (hex, why) in InvalidUtf8)
        {
            var signed = await SignAsync(HeaderWith(Convert.FromHexString(hex), placement));
            var resolverCalled = false;
            Func<string, Jwk?> resolver = _ =>
            {
                resolverCalled = true;
                return signed.Key.PublicJwk;
            };

            var act = () => Invoke(entryPoint, signed, resolver);

            act.Should().Throw<MalformedJoseException>(
                    $"{entryPoint}: RFC 7515 §5.2 step 3 requires the decoded header to be UTF-8, and 0x{hex} ({why}) in the {placement} is not")
                .WithMessage("*not valid UTF-8*");
            resolverCalled.Should().BeFalse($"{entryPoint}: the header is rejected before any key resolution (0x{hex} in the {placement})");
        }
    }

    [Theory]
    [InlineData("flattened")]
    [InlineData("general")]
    [InlineData("compact")]
    [InlineData("vcjose")]
    [InlineData("flattened-detached")]
    [InlineData("compact-detached")]
    public async Task AProtectedHeaderWithWellFormedNonAsciiUtf8_StillVerifies(string entryPoint)
    {
        // Guards against over-rejection: well-formed multi-byte UTF-8 in both a member name and a
        // string value is exactly what the §5.2 step 3 check must let through.
        byte[] header = [.. HeaderPrefix, .. Encoding.UTF8.GetBytes("\"ключ\":\"é\"}")];
        var signed = await SignAsync(header);

        var payload = Invoke(entryPoint, signed, _ => signed.Key.PublicJwk);

        payload.Should().Equal(Payload);
    }

    private static byte[] HeaderWith(byte[] invalid, Placement placement) => placement switch
    {
        Placement.MemberName => [.. HeaderPrefix, (byte)'"', .. invalid, .. Encoding.UTF8.GetBytes("\":1}")],
        Placement.ExtensionValue => [.. HeaderPrefix, .. Encoding.UTF8.GetBytes("\"x\":\""), .. invalid, .. Encoding.UTF8.GetBytes("\"}")],
        _ => throw new ArgumentOutOfRangeException(nameof(placement)),
    };

    private sealed record Signed(string ProtectedB64u, string PayloadB64u, string SignatureB64u, TestKeyMaterial Key);

    private static async Task<Signed> SignAsync(byte[] headerBytes)
    {
        // Hand-rolled because JwsBuilder cannot emit a malformed header. Ed25519 signatures are
        // already JOSE-native, so the raw ISigner output needs no transcoding.
        var key = TestKeyMaterial.Generate(KeyType.Ed25519, Kid);
        var protectedB64u = Base64Url.Encode(headerBytes);
        var payloadB64u = Base64Url.Encode(Payload);
        var signingInput = Encoding.ASCII.GetBytes($"{protectedB64u}.{payloadB64u}");
        var signature = await key.Signer.Signer.SignAsync(signingInput, CancellationToken.None);
        return new Signed(protectedB64u, payloadB64u, Base64Url.Encode(signature), key);
    }

    /// <summary>Runs one public verification entry point and returns the verified payload bytes.</summary>
    private static byte[] Invoke(string entryPoint, Signed s, Func<string, Jwk?> resolver) => entryPoint switch
    {
        "flattened" => JwsParser.Parse(
            JsonSerializer.Serialize(new { payload = s.PayloadB64u, @protected = s.ProtectedB64u, signature = s.SignatureB64u }),
            resolver, Jose).PayloadBytes,
        "general" => JwsParser.Parse(
            JsonSerializer.Serialize(new { payload = s.PayloadB64u, signatures = new[] { new { @protected = s.ProtectedB64u, signature = s.SignatureB64u } } }),
            resolver, Jose).PayloadBytes,
        "compact" => JwsParser.ParseCompact($"{s.ProtectedB64u}.{s.PayloadB64u}.{s.SignatureB64u}", resolver, Jose).PayloadBytes,
        "vcjose" => VcJose.VerifyCredential($"{s.ProtectedB64u}.{s.PayloadB64u}.{s.SignatureB64u}", resolver, Jose),
        "flattened-detached" => JwsParser.Parse(
            JsonSerializer.Serialize(new { @protected = s.ProtectedB64u, signature = s.SignatureB64u }),
            Payload, resolver, Jose).PayloadBytes,
        "compact-detached" => JwsParser.ParseCompact($"{s.ProtectedB64u}..{s.SignatureB64u}", Payload, resolver, Jose).PayloadBytes,
        _ => throw new ArgumentOutOfRangeException(nameof(entryPoint), entryPoint, "unknown entry point"),
    };
}
