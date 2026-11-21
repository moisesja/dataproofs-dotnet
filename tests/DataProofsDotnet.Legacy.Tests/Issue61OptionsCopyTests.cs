using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using DataProofsDotnet.Tests.Shared;
using NetCrypto;

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
}

public sealed class Issue61Ed25519Signature2020RdfcOptionsCopyTests : Issue61LegacyOptionsCopyTestsBase
{
    protected override ICryptosuite Suite { get; } = new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Rdfc);

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x21));
}

public sealed class Issue61EcdsaSecp256r1Signature2019JcsOptionsCopyTests : Issue61LegacyOptionsCopyTestsBase
{
    protected override ICryptosuite Suite { get; } = new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Jcs);

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x21, KeyType.P256));
}

public sealed class Issue61EcdsaSecp256r1Signature2019RdfcOptionsCopyTests : Issue61LegacyOptionsCopyTestsBase
{
    protected override ICryptosuite Suite { get; } = new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Rdfc);

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x21, KeyType.P256));
}
