using System.Text;
using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using DataProofsDotnet.Rdfc.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// AC-1 (steps 1–3) for the RDFC cryptosuites: every <c>eddsa-rdfc-2022</c> and
/// <c>ecdsa-rdfc-2019</c> (P-256 / P-384) W3C worked vector is verified through the Core
/// <see cref="DataIntegrityProofPipeline"/> with the RDFC suite registered — exactly as a real
/// consumer would — using a static resolver for the fixture key. Documented negatives
/// (tampered document, wrong key, proofPurpose mismatch) return <c>verified=false</c> with the
/// expected problem code and never throw. The deterministic <c>eddsa-rdfc-2022</c> proofValue
/// is re-created byte-identically; <c>ecdsa-rdfc-2019</c> round-trips and its canonical form +
/// hashData match the vector intermediates byte-for-byte.
/// </summary>
public sealed class RdfcSuiteVectorTests
{
    private static DataIntegrityProofPipeline Pipeline()
        => new(RdfcCryptosuiteRegistration.CreateWithRdfcSuites());

    // ---- eddsa-rdfc-2022 ----

    [Fact]
    public async Task EddsaRdfc2022_Vector_VerifiesThroughPipeline()
    {
        var signed = Fx.Json("w3c", "vc-di-eddsa", "TestVectors", "eddsa-rdfc-2022", "signedDataInt.json");
        var vm = signed.GetProperty("proof").GetProperty("verificationMethod").GetString()!;
        var resolver = Fx.SingleMethodResolver(vm, Fx.MultikeyOf(vm));

        var result = await Pipeline().VerifyAsync(
            signed, resolver, new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeTrue();
    }

    [Fact]
    public async Task EddsaRdfc2022_ProofValue_IsRecreatedByteIdentically()
    {
        // Ed25519 signing is deterministic, so re-creating the proof over the unsigned vector
        // with the vector's proof options must reproduce the published proofValue exactly.
        var unsigned = Fx.Json("w3c", "vc-di-eddsa", "TestVectors", "unsigned.json");
        var signed = Fx.Json("w3c", "vc-di-eddsa", "TestVectors", "eddsa-rdfc-2022", "signedDataInt.json");
        var vectorProof = signed.GetProperty("proof");

        var keyPair = Fx.SecretKey(
            Fx.Json("w3c", "vc-di-eddsa", "TestVectors", "keyPair.json").GetProperty("privateKeyMultibase").GetString()!);

        var options = new DataIntegrityProof
        {
            Type = DataIntegrityProof.DataIntegrityProofType,
            Cryptosuite = EddsaRdfc2022Cryptosuite.CryptosuiteName,
            Created = vectorProof.GetProperty("created").GetString(),
            VerificationMethod = vectorProof.GetProperty("verificationMethod").GetString(),
            ProofPurpose = vectorProof.GetProperty("proofPurpose").GetString(),
        };

        var suite = new EddsaRdfc2022Cryptosuite();
        var proof = await suite.CreateProofAsync(unsigned, options, Fx.Signer(keyPair));

        proof.ProofValue.Should().Be(vectorProof.GetProperty("proofValue").GetString());
    }

    [Fact]
    public async Task EddsaRdfc2022_TamperedDocument_FailsClosed()
    {
        var signed = Fx.Json("w3c", "vc-di-eddsa", "TestVectors", "eddsa-rdfc-2022", "signedDataInt.json");
        var vm = signed.GetProperty("proof").GetProperty("verificationMethod").GetString()!;
        var resolver = Fx.SingleMethodResolver(vm, Fx.MultikeyOf(vm));

        var tampered = Fx.Mutate(signed, o => o["name"] = "Tampered Credential");

        var result = await Pipeline().VerifyAsync(tampered, resolver);

        result.Verified.Should().BeFalse();
        result.ProofResults.Should().ContainSingle()
            .Which.Problems.Should().Contain(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public async Task EddsaRdfc2022_ProofPurposeMismatch_FailsWithVerificationError()
    {
        var signed = Fx.Json("w3c", "vc-di-eddsa", "TestVectors", "eddsa-rdfc-2022", "signedDataInt.json");
        var vm = signed.GetProperty("proof").GetProperty("verificationMethod").GetString()!;
        var resolver = Fx.SingleMethodResolver(vm, Fx.MultikeyOf(vm));

        var result = await Pipeline().VerifyAsync(
            signed, resolver, new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.Authentication });

        result.Verified.Should().BeFalse();
        result.ProofResults.Should().ContainSingle()
            .Which.Problems.Should().Contain(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [Fact]
    public void EddsaRdfc2022_WrongKey_FailsClosed()
    {
        var signed = Fx.Json("w3c", "vc-di-eddsa", "TestVectors", "eddsa-rdfc-2022", "signedDataInt.json");
        var wrongKey = PublicKeyMaterial.FromRaw(KeyType.Ed25519, Fx.KeyGen.Generate(KeyType.Ed25519).PublicKey);

        var result = Pipeline().Verify(signed, wrongKey);

        result.Verified.Should().BeFalse();
    }

    // ---- ecdsa-rdfc-2019 (P-256 / P-384) ----

    [Theory]
    [InlineData("ecdsa-rdfc-2019-p256", "signedECDSAP256.json")]
    [InlineData("ecdsa-rdfc-2019-p384", "signedECDSAP384.json")]
    public async Task EcdsaRdfc2019_Vector_VerifiesThroughPipeline(string dir, string signedFile)
    {
        var signed = Fx.Json("w3c", "vc-di-ecdsa", "spec", dir, signedFile);
        var vm = signed.GetProperty("proof").GetProperty("verificationMethod").GetString()!;
        var resolver = Fx.SingleMethodResolver(vm, Fx.MultikeyOf(vm));

        var result = await Pipeline().VerifyAsync(
            signed, resolver, new ProofVerificationOptions { ExpectedProofPurpose = ProofPurposes.AssertionMethod });

        result.Verified.Should().BeTrue();
    }

    [Theory]
    [InlineData("ecdsa-rdfc-2019-p256", "p256KeyPair.json", "signedECDSAP256.json", "canonDocECDSAP256.txt", "combinedHashECDSAP256.txt", KeyType.P256)]
    [InlineData("ecdsa-rdfc-2019-p384", "p384KeyPair.json", "signedECDSAP384.json", "canonDocECDSAP384.txt", "combinedHashECDSAP384.txt", KeyType.P384)]
    public async Task EcdsaRdfc2019_RoundTrips_AndMatchesVectorIntermediates(
        string dir, string keyPairFile, string signedFile, string canonFile, string hashFile, KeyType keyType)
    {
        var signed = Fx.Json("w3c", "vc-di-ecdsa", "spec", dir, signedFile);
        var vectorProof = signed.GetProperty("proof");
        var vm = vectorProof.GetProperty("verificationMethod").GetString()!;

        // Canonical document form matches the vector intermediate byte-for-byte (public API).
        var unsigned = Fx.Mutate(signed, o => o.Remove("proof"));
        var canonicalizer = new RdfcDocumentCanonicalizer();
        var hash = keyType == KeyType.P384 ? RdfCanonicalizationHashAlgorithm.Sha384 : RdfCanonicalizationHashAlgorithm.Sha256;
        var canonicalBytes = canonicalizer.CanonicalizeJsonLd(unsigned, hash);
        // Compare the canonical N-Quads verbatim (the fixture carries the trailing newline too).
        Encoding.UTF8.GetString(canonicalBytes)
            .Should().Be(File.ReadAllText(Fx.PathOf("w3c", "vc-di-ecdsa", "spec", dir, canonFile)));

        // hashData = hash(canonicalProofConfig) ‖ hash(canonicalDocument) — recompute from the
        // public canonical forms and compare to the vector's combined hashData byte-for-byte.
        var proofConfig = Fx.Json("w3c", "vc-di-ecdsa", "spec", dir, $"proofConfig{(dir.EndsWith("p384") ? "ECDSAP384" : "ECDSAP256")}.json");
        var proofConfigCanon = canonicalizer.CanonicalizeJsonLd(proofConfig, hash);
        var computedHashData = keyType == KeyType.P384
            ? Concat(Hash.Sha384(proofConfigCanon), Hash.Sha384(canonicalBytes))
            : Concat(Hash.Sha256(proofConfigCanon), Hash.Sha256(canonicalBytes));
        Convert.ToHexString(computedHashData).ToLowerInvariant()
            .Should().Be(Fx.Text("w3c", "vc-di-ecdsa", "spec", dir, hashFile));

        // ECDSA signatures are randomized, so re-create then VERIFY (round-trip) rather than
        // byte-compare the signature. The canonical/hashData inputs are the deterministic parts.
        var keyPair = Fx.SecretKey(
            Fx.Json("w3c", "vc-di-ecdsa", "spec", keyPairFile).GetProperty("secretKeyMultibase").GetString()!);

        var options = new DataIntegrityProof
        {
            Type = DataIntegrityProof.DataIntegrityProofType,
            Cryptosuite = EcdsaRdfc2019Cryptosuite.CryptosuiteName,
            Created = vectorProof.GetProperty("created").GetString(),
            VerificationMethod = vm,
            ProofPurpose = vectorProof.GetProperty("proofPurpose").GetString(),
        };

        var suite = new EcdsaRdfc2019Cryptosuite();
        var recreated = await suite.CreateProofAsync(unsigned, options, Fx.Signer(keyPair));

        // The re-created proof verifies, and so does the published vector proof — both through
        // the same suite, proving canonical-form + hashData line up with the vector.
        var publicKey = PublicKeyMaterial.FromMultikey(Fx.MultikeyOf(vm));
        suite.VerifyProof(unsigned, recreated, publicKey).Verified.Should().BeTrue();
        suite.VerifyProof(unsigned, vectorProof.Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!, publicKey)
            .Verified.Should().BeTrue();
    }

    [Theory]
    [InlineData("ecdsa-rdfc-2019-p256", "signedECDSAP256.json")]
    [InlineData("ecdsa-rdfc-2019-p384", "signedECDSAP384.json")]
    public async Task EcdsaRdfc2019_TamperedDocument_FailsClosed(string dir, string signedFile)
    {
        var signed = Fx.Json("w3c", "vc-di-ecdsa", "spec", dir, signedFile);
        var vm = signed.GetProperty("proof").GetProperty("verificationMethod").GetString()!;
        var resolver = Fx.SingleMethodResolver(vm, Fx.MultikeyOf(vm));

        var tampered = Fx.Mutate(signed, o => o["issuer"] = "https://evil.example/");

        var result = await Pipeline().VerifyAsync(tampered, resolver);

        result.Verified.Should().BeFalse();
    }

    private static byte[] Concat(byte[] left, byte[] right)
    {
        var result = new byte[left.Length + right.Length];
        left.CopyTo(result, 0);
        right.CopyTo(result, left.Length);
        return result;
    }
}
