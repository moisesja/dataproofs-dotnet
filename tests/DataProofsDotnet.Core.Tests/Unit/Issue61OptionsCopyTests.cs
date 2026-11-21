using System.Text;
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

    // The JCS suites refuse an options @context for a document without one (PR #62 follow-up b).
    protected override bool TakesTheOptionsContext => false;
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

    // The JCS suites refuse an options @context for a document without one (PR #62 follow-up b).
    protected override bool TakesTheOptionsContext => false;
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

/// <summary>
/// PR #62: the pipeline verifies each proof after awaiting its resolver, which is the caller's code. A resolver that
/// rewrites the memory behind the caller's document must not change what the later proofs are verified against.
/// </summary>
public sealed class Issue61PipelineVerifyCopyTests
{
    [Fact]
    public async Task AResolverThatRewritesTheCallersBuffer_LeavesEveryResultAboutTheDocumentAsGiven()
    {
        var signer = Fx.Signer(Fx.SeedKey(0x21));
        var pipeline = new DataIntegrityProofPipeline(CryptosuiteRegistry.CreateDefault());
        var options = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            Created = "2026-01-02T00:00:00Z",
            VerificationMethod = "did:example:x#k",
            ProofPurpose = ProofPurposes.AssertionMethod,
        };
        var secured = await pipeline.AddProofAsync(HostileJson.Parse(HostileJson.BaseDocument), options, signer);
        secured = await pipeline.AddProofAsync(secured, options, signer);
        var buffer = Encoding.UTF8.GetBytes(secured.GetRawText());
        using var document = JsonDocument.Parse(buffer.AsMemory());
        var at = buffer.AsSpan().IndexOf("\"a\":1"u8) + 4;
        var resolver = new RewritingResolver(
            new ResolvedVerificationMethod
            {
                Id = "did:example:x#k",
                Controller = "did:example:x",
                PublicKey = PublicKeyMaterial.FromRaw(signer.KeyType, signer.PublicKey.Span),
                Relationships = new HashSet<string>(StringComparer.Ordinal) { ProofPurposes.AssertionMethod },
            },
            () => buffer[at] = (byte)'2');

        var result = await pipeline.VerifyAsync(document.RootElement, resolver);

        result.ProofResults.Should().HaveCount(2).And.OnlyContain(proof => proof.Verified);
        result.Verified.Should().BeTrue();
    }

    private sealed class RewritingResolver(ResolvedVerificationMethod method, Action rewrite) : IVerificationMethodResolver
    {
        public Task<ResolvedVerificationMethod?> ResolveAsync(string verificationMethodUrl, CancellationToken cancellationToken = default)
        {
            rewrite();
            return Task.FromResult<ResolvedVerificationMethod?>(method);
        }
    }
}
