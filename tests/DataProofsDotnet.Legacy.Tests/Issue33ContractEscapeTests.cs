using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Legacy.Tests.TestSupport;
using DataProofsDotnet.Tests.Shared;
using NetCrypto;

namespace DataProofsDotnet.Legacy.Tests;

/// <summary>
/// Issue #33: the shared suite matrix through each legacy suite's own <c>CreateProofAsync</c>, in
/// both variants. The JCS variant materializes and re-nests the document itself, so before the
/// check it threw raw <see cref="InvalidOperationException"/>, <see cref="System.Text.Json.JsonException"/>
/// and <see cref="ArgumentException"/>; the RDFC variant signed duplicates and invalid text.
/// </summary>
public abstract class Issue33LegacyCreateTestsBase : Issue33SuiteCreateTestsBase
{
    protected abstract string ProofType { get; }

    protected override DataIntegrityProof Options() => new()
    {
        Type = ProofType,
        Created = "2026-01-01T00:00:00Z",
        VerificationMethod = "did:example:alice#key-1",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };
}

public sealed class Issue33Ed25519Signature2020JcsCreateTests : Issue33LegacyCreateTestsBase
{
    protected override ICryptosuite Suite { get; } = new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Jcs);

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x01));

    protected override string ProofType => Ed25519Signature2020Cryptosuite.ProofType;
}

public sealed class Issue33Ed25519Signature2020RdfcCreateTests : Issue33LegacyCreateTestsBase
{
    protected override ICryptosuite Suite { get; } = new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Rdfc);

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x01));

    protected override string ProofType => Ed25519Signature2020Cryptosuite.ProofType;
}

public sealed class Issue33EcdsaSecp256r1Signature2019JcsCreateTests : Issue33LegacyCreateTestsBase
{
    protected override ICryptosuite Suite { get; } = new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Jcs);

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x01, KeyType.P256));

    protected override string ProofType => EcdsaSecp256r1Signature2019Cryptosuite.ProofType;
}

public sealed class Issue33EcdsaSecp256r1Signature2019RdfcCreateTests : Issue33LegacyCreateTestsBase
{
    protected override ICryptosuite Suite { get; } = new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Rdfc);

    protected override ISigner Signer { get; } = Fx.Signer(Fx.SeedKey(0x01, KeyType.P256));

    protected override string ProofType => EcdsaSecp256r1Signature2019Cryptosuite.ProofType;
}
