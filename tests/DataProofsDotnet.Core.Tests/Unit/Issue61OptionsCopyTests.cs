using System.Text.Json;
using DataProofsDotnet.Core.Tests.TestSupport;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Tests.Shared;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>Issue #61: the shared options-copy matrix through <c>eddsa-jcs-2022</c>.</summary>
public sealed class Issue61EddsaJcsOptionsCopyTests : Issue61OptionsCopyTestsBase
{
    protected override ICryptosuite Suite { get; } = new EddsaJcs2022Cryptosuite();

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x21));

    protected override DataIntegrityProof Options() => new()
    {
        Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = "did:example:x#k",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };
}

/// <summary>Issue #61: the shared options-copy matrix through <c>ecdsa-jcs-2019</c>.</summary>
public sealed class Issue61EcdsaJcsOptionsCopyTests : Issue61OptionsCopyTestsBase
{
    protected override ICryptosuite Suite { get; } = new EcdsaJcs2019Cryptosuite();

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x21, KeyType.P256));

    protected override DataIntegrityProof Options() => new()
    {
        Cryptosuite = EcdsaJcs2019Cryptosuite.CryptosuiteName,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = "did:example:x#k",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };
}

/// <summary>
/// Issue #61: the pipeline hands a registered suite its own copy of the options, so a suite this library does not
/// ship, which may await as it likes, cannot be reached through the caller's object either.
/// </summary>
public sealed class Issue61PipelineOptionsCopyTests
{
    [Fact]
    public async Task ThePipeline_HandsTheSuiteACopyThatSharesNothingWithTheCaller()
    {
        var suite = new RecordingSuite();
        var registry = new CryptosuiteRegistry();
        registry.Register(suite);
        using var note = JsonDocument.Parse("\"x\"");
        using var context = JsonDocument.Parse("\"https://www.w3.org/ns/credentials/v2\"");
        var options = new DataIntegrityProof
        {
            Cryptosuite = RecordingSuite.SuiteName,
            VerificationMethod = "did:example:x#k",
            ProofPurpose = ProofPurposes.AssertionMethod,
            Context = context.RootElement,
            AdditionalProperties = new Dictionary<string, JsonElement> { ["note"] = note.RootElement },
        };

        await new DataIntegrityProofPipeline(registry).AddProofAsync(
            Fx.Json("constructed", "controller", "unsigned-credential.json"), options, Fx.Signer(Fx.SeedKey(0x21)));

        var received = suite.Received!;
        received.Should().NotBeSameAs(options);
        received.AdditionalProperties.Should().NotBeSameAs(options.AdditionalProperties);
        options.AdditionalProperties["note"] = JsonSerializer.Deserialize<JsonElement>("\"changed\"");
        note.Dispose();
        context.Dispose();
        received.AdditionalProperties!["note"].GetString().Should().Be("x");
        received.Context!.Value.GetString().Should().Be("https://www.w3.org/ns/credentials/v2");
    }

    private sealed class RecordingSuite : ICryptosuite
    {
        public const string SuiteName = "test-recording-2026";

        public DataIntegrityProof? Received { get; private set; }

        public string Name => SuiteName;

        public Task<DataIntegrityProof> CreateProofAsync(
            JsonElement unsecuredDocument, DataIntegrityProof proofOptions, ISigner signer, CancellationToken cancellationToken = default)
        {
            Received = proofOptions;
            return Task.FromResult(new DataIntegrityProof
            {
                Cryptosuite = SuiteName,
                VerificationMethod = "did:example:x#k",
                ProofPurpose = ProofPurposes.AssertionMethod,
                ProofValue = "z1",
            });
        }

        public ProofVerificationResult VerifyProof(JsonElement unsecuredDocument, DataIntegrityProof proof, PublicKeyMaterial publicKey)
            => throw new NotSupportedException();
    }
}
