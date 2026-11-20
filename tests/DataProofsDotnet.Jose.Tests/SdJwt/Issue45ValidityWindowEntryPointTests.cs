using System.Text;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.SdJwt.Vc;
using DataProofsDotnet.Jose.Signing;
using FluentAssertions;
using NetCrypto;
using Xunit;
using static DataProofsDotnet.Jose.Tests.X509.TestCertificates;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// Issue #45 on every SD-JWT and SD-JWT VC verification entry point: <see cref="SdJwtVerifier.Verify"/>,
/// <see cref="SdJwtVerifier.VerifyWithCertificateChain"/>, <see cref="SdJwtVcVerifier.VerifyAsync"/>,
/// <see cref="SdJwtVcVerifier.VerifyWithTypeMetadataAsync"/> (issue #47) and
/// <see cref="SdJwtVcVerifier.VerifyWithCertificateChainAsync"/> (issue #46), with and without Type Metadata. One
/// presentation, signed by a key with an <c>x5c</c> chain, goes through each, so the kid and the certificate routes judge
/// the same bytes. A credential outside its window never reaches the Type Metadata resolver.
/// </summary>
public sealed class Issue45ValidityWindowEntryPointTests
{
    private const string Vct = "https://credentials.example.com/identity_credential";

    private static readonly DateTimeOffset Now = new(2026, 11, 19, 12, 0, 0, TimeSpan.Zero);
    private static readonly long NowSeconds = Now.ToUnixTimeSeconds();

    private static readonly Pki IssuerPki = CreatePki(KeyType.P256);
    private static readonly Jwk IssuerPublicJwk = JwkConversion.ToPublicJwk(IssuerPki.Leaf.Key.KeyType, IssuerPki.Leaf.Key.PublicKey);

    private static readonly byte[] TypeDocument = Encoding.UTF8.GetBytes($$"""{"vct":"{{Vct}}","name":"Identity"}""");

    /// <summary>A Type Metadata document resolver that counts its calls.</summary>
    private sealed class CountingResolver : ITypeMetadataDocumentResolver
    {
        public int Calls { get; private set; }

        public Task<byte[]?> ResolveDocumentAsync(string reference, CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult<byte[]?>(reference == Vct ? TypeDocument : null);
        }
    }

    private sealed record Outcome(bool IsValid, IReadOnlyList<string> Errors, bool MetadataProcessed);

    private static readonly SdJwtVerificationOptions Options = new() { CurrentTime = Now };

    private static bool Trusted(X509CertificateChain chain) => ValidateWithAnchors(chain, IssuerPki.Root);

    /// <summary>Each entry point, as a function of the presentation and the resolver it may consult.</summary>
    private static readonly Dictionary<string, Func<string, CountingResolver, Task<Outcome>>> EntryPoints = new()
    {
        ["SdJwtVerifier.Verify"] = (p, _) =>
        {
            var r = SdJwtVerifier.Verify(p, _ => IssuerPublicJwk, Options);
            return Task.FromResult(new Outcome(r.IsValid, r.Errors, false));
        },
        ["SdJwtVerifier.VerifyWithCertificateChain"] = (p, _) =>
        {
            var r = SdJwtVerifier.VerifyWithCertificateChain(p, Trusted, Options);
            return Task.FromResult(new Outcome(r.IsValid, r.Errors, false));
        },
        ["SdJwtVcVerifier.VerifyAsync"] = async (p, _) =>
        {
            var r = await SdJwtVcVerifier.VerifyAsync(p, _ => IssuerPublicJwk, Options);
            return new Outcome(r.IsValid, r.Errors, false);
        },
        ["SdJwtVcVerifier.VerifyWithTypeMetadataAsync"] = async (p, resolver) =>
        {
            var r = await SdJwtVcVerifier.VerifyWithTypeMetadataAsync(p, _ => IssuerPublicJwk, new(resolver), Options);
            return new Outcome(r.IsValid, r.Errors, r.ProcessedTypeMetadata is not null);
        },
        ["SdJwtVcVerifier.VerifyWithCertificateChainAsync"] = async (p, _) =>
        {
            var r = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(p, Trusted, Options);
            return new Outcome(r.IsValid, r.Errors, false);
        },
        ["SdJwtVcVerifier.VerifyWithCertificateChainAsync with Type Metadata"] = async (p, resolver) =>
        {
            var r = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(p, Trusted, Options, new(resolver));
            return new Outcome(r.IsValid, r.Errors, r.ProcessedTypeMetadata is not null);
        },
    };

    private static bool ProcessesMetadata(string entryPoint) => entryPoint.Contains("TypeMetadata") || entryPoint.Contains("Type Metadata");

    /// <summary>The cases: a claim and its value, and the code it must fail with (<c>null</c>: it verifies).</summary>
    private static readonly Dictionary<string, (JsonObject Claims, string? Code)> Cases = new()
    {
        ["exp passed"] = (new JsonObject { ["exp"] = NowSeconds - 3600 }, "SD_JWT_EXPIRED"),
        ["nbf ahead"] = (new JsonObject { ["nbf"] = NowSeconds + 3600 }, "SD_JWT_NOT_YET_VALID"),
        ["exp a string"] = (new JsonObject { ["exp"] = "2030-01-01" }, "SD_JWT_EXP_INVALID"),
        ["nbf a boolean"] = (new JsonObject { ["nbf"] = true }, "SD_JWT_NBF_INVALID"),
        ["inside the window"] = (new JsonObject { ["nbf"] = NowSeconds - 60, ["exp"] = NowSeconds + 3600 }, null),
    };

    public static TheoryData<string, string> Matrix()
    {
        var data = new TheoryData<string, string>();
        foreach (var entryPoint in EntryPoints.Keys)
            foreach (var @case in Cases.Keys)
                data.Add(entryPoint, @case);
        return data;
    }

    private static async Task<string> Present(JsonObject claims)
    {
        var payload = new JsonObject { ["vct"] = Vct, ["given_name"] = "Erika", ["_sd_alg"] = "sha-256" };
        foreach (var (name, value) in claims)
            payload[name] = value?.DeepClone();
        var jwt = await JwsBuilder.BuildCompactAsync(Encoding.UTF8.GetBytes(payload.ToJsonString()), IssuerPki.SignerWithChain(), typ: "dc+sd-jwt");
        return jwt + "~";
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public async Task Every_entry_point_enforces_the_window(string entryPoint, string @case)
    {
        var (claims, code) = Cases[@case];
        var presentation = await Present(claims);
        var resolver = new CountingResolver();

        var outcome = await EntryPoints[entryPoint](presentation, resolver);

        if (code is null)
        {
            outcome.IsValid.Should().BeTrue(string.Join("; ", outcome.Errors));
            outcome.MetadataProcessed.Should().Be(ProcessesMetadata(entryPoint));
            resolver.Calls.Should().Be(ProcessesMetadata(entryPoint) ? 1 : 0);
        }
        else
        {
            outcome.IsValid.Should().BeFalse();
            outcome.Errors.Should().ContainSingle().Which.Should().StartWith(code + ":");
            resolver.Calls.Should().Be(0, "an expired or not-yet-valid credential never reaches the Type Metadata resolver");
        }
    }
}
