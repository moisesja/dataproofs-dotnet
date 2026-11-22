using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using DataProofsDotnet.Tests.Shared;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// Issue #61: the shared options-copy matrix through each legacy suite, in both variants. The options name the
/// suite in <c>cryptosuite</c> for the pipeline's dispatch; the suite emits its own type and no cryptosuite.
/// </summary>
public abstract class Issue61LegacyOptionsCopyTestsBase : Issue61OptionsCopyTestsBase
{
    protected override string ProofType => Suite.Name;

    protected override DataIntegrityProof Options() => new()
    {
        Type = ProofType,
        Cryptosuite = Suite.Name,
        Created = "2026-01-02T00:00:00Z",
        VerificationMethod = "did:example:x#k",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };
}

public sealed class Issue61Ed25519Signature2020JcsOptionsCopyTests : Issue61LegacyOptionsCopyTestsBase
{
    protected override ICryptosuite Suite { get; } = new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Jcs);

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x21));

    // The JCS variant has no representation for a proof chain (LegacyCryptosuiteBase).
    protected override bool SecuresAProofChain => false;
}

public sealed class Issue61Ed25519Signature2020RdfcOptionsCopyTests : Issue61LegacyOptionsCopyTestsBase
{
    protected override ICryptosuite Suite { get; } = new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Rdfc);

    protected override ICryptosuite? SuiteWhoseCanonicalizerRuns(Action during)
        => new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Rdfc, new DuringCanonicalizer(during));

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x21));
}

public sealed class Issue61EcdsaSecp256r1Signature2019JcsOptionsCopyTests : Issue61LegacyOptionsCopyTestsBase
{
    protected override ICryptosuite Suite { get; } = new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Jcs);

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x21, KeyType.P256));

    // The JCS variant has no representation for a proof chain (LegacyCryptosuiteBase).
    protected override bool SecuresAProofChain => false;
}

public sealed class Issue61EcdsaSecp256r1Signature2019RdfcOptionsCopyTests : Issue61LegacyOptionsCopyTestsBase
{
    protected override ICryptosuite Suite { get; } = new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Rdfc);

    protected override ICryptosuite? SuiteWhoseCanonicalizerRuns(Action during)
        => new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Rdfc, new DuringCanonicalizer(during));

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x21, KeyType.P256));
}

/// <summary>
/// A legacy suite verifies under its own variant first and the other next, so the proof used to be read once per pass. A
/// suite's own <c>VerifyProof</c> now reads one copy of it (PR #62 review: the adversarial pass's route).
/// </summary>
public sealed class Issue61LegacyVerifyReadsTheProofOnceTests
{
    private const string Note = "https://example.org/vocab#note";

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task BothVariantPasses_ReadTheSameCopyOfTheProof(bool tamperedFirst)
    {
        // A proof made with the RDFC variant, verified by a suite that tries JCS first. The extension dictionary
        // yields one value on its first read and another later: the verdict follows the first read alone.
        var signer = Fx.Signer(Fx.SeedKey(0x21));
        var key = PublicKeyMaterial.FromRaw(signer.KeyType, signer.PublicKey.Span);
        var document = HostileJson.Parse(HostileJson.BaseDocument);
        var options = new DataIntegrityProof
        {
            Type = Ed25519Signature2020Cryptosuite.ProofType,
            Created = "2026-01-02T00:00:00Z",
            VerificationMethod = "did:example:x#k",
            ProofPurpose = ProofPurposes.AssertionMethod,
            AdditionalProperties = new Dictionary<string, System.Text.Json.JsonElement> { [Note] = HostileJson.Parse("\"as signed\"") },
        };
        var signed = await new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Rdfc).CreateProofAsync(document, options, signer);
        KeyValuePair<string, System.Text.Json.JsonElement> Value(string text) => new(Note, HostileJson.Parse(text));
        var proof = signed with
        {
            AdditionalProperties = tamperedFirst
                ? new ScriptedDictionary([Value("\"tampered\"")], count: 1, later: [Value("\"as signed\"")])
                : new ScriptedDictionary([Value("\"as signed\"")], count: 1, later: [Value("\"tampered\"")]),
        };

        new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Jcs).VerifyProof(document, proof, key).Verified
            .Should().Be(!tamperedFirst);
    }
}

/// <summary>A canonicalizer of the caller's: the RDFC one, after running <paramref name="during"/> on every call.</summary>
internal sealed class DuringCanonicalizer(Action during) : IRdfCanonicalizer
{
    private readonly RdfcDocumentCanonicalizer _inner = new();

    public byte[] CanonicalizeJsonLd(System.Text.Json.JsonElement document, RdfCanonicalizationHashAlgorithm hashAlgorithm = RdfCanonicalizationHashAlgorithm.Sha256)
    {
        during();
        return _inner.CanonicalizeJsonLd(document, hashAlgorithm);
    }

    public string CanonicalizeNQuads(string nQuads, RdfCanonicalizationHashAlgorithm hashAlgorithm = RdfCanonicalizationHashAlgorithm.Sha256)
    {
        during();
        return _inner.CanonicalizeNQuads(nQuads, hashAlgorithm);
    }

    public IReadOnlyDictionary<string, string> CanonicalizeNQuadsToMap(string nQuads, RdfCanonicalizationHashAlgorithm hashAlgorithm = RdfCanonicalizationHashAlgorithm.Sha256)
    {
        during();
        return _inner.CanonicalizeNQuadsToMap(nQuads, hashAlgorithm);
    }
}
