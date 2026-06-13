using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Rdfc.DataIntegrity;
using DataProofsDotnet.Rdfc.Tests.TestSupport;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Rdfc.Tests;

/// <summary>
/// AC-1 (step 4): the <c>bbs-2023</c> selective-disclosure lifecycle (FR-12) against the
/// vendored W3C <c>vc-di-bbs</c> fixtures (CRD 2026-04-07).
/// </summary>
/// <remarks>
/// NetCrypto's <c>IBbsCryptoProvider</c> v1 does not surface the BBS <c>header</c> argument the
/// W3C suite binds <c>bbsHeader</c> through, so the suite's <c>proofValue</c> bytes are not
/// interchangeable with the reference vectors' BBS material (see
/// <see cref="Bbs2023Cryptosuite"/> remarks). These tests therefore exercise the full live
/// lifecycle — issuer base proof → holder derive (per selective-pointer set) → verifier
/// verify-derived — and the documented negatives, while the proofValue framing
/// (multibase + CBOR headers) is checked against the fixtures structurally. The BBS native
/// library is present on CI/dev here, so the live tests run; absent it, they skip and the
/// capability-behavior test (registration succeeds, use throws) carries the contract.
/// </remarks>
public sealed class Bbs2023LifecycleTests
{
    private static (byte[] Sk, byte[] HmacKey) KeyMaterial()
    {
        var keyMat = Fx.Json("w3c", "vc-di-bbs", "TestVectors", "BBSKeyMaterial.json");
        return (
            Convert.FromHexString(keyMat.GetProperty("privateKeyHex").GetString()!),
            Convert.FromHexString(keyMat.GetProperty("hmacKeyString").GetString()!));
    }

    private static JsonElement WindDoc() => Fx.Json("w3c", "vc-di-bbs", "TestVectors", "windDoc.json");

    private static string[] WindMandatory()
        => JsonSerializer.Deserialize<string[]>(Fx.Text("w3c", "vc-di-bbs", "TestVectors", "windMandatory.json"))!;

    private static DataIntegrityProof BaseOptions() => new()
    {
        Type = DataIntegrityProof.DataIntegrityProofType,
        Cryptosuite = Bbs2023Cryptosuite.CryptosuiteName,
        Created = "2023-08-15T23:36:38Z",
        VerificationMethod = "did:key:zUC7Derd#zUC7Derd",
        ProofPurpose = ProofPurposes.AssertionMethod,
    };

    private static async Task<JsonElement> CreateSecuredBaseAsync(
        Bbs2023Cryptosuite suite, byte[] sk, byte[] hmacKey, string[] mandatory)
    {
        var baseProof = await suite.CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, mandatory);
        var secured = JsonObject.Create(WindDoc())!;
        secured["proof"] = JsonSerializer.SerializeToNode(baseProof, DataProofsJsonOptions.Default);
        return JsonSerializer.SerializeToElement(secured, DataProofsJsonOptions.Default);
    }

    private static ProofVerificationResult VerifyReveal(Bbs2023Cryptosuite suite, JsonElement reveal, PublicKeyMaterial pk)
    {
        var derivedProof = reveal.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
        var unsecured = JsonObject.Create(reveal)!;
        unsecured.Remove("proof");
        return suite.VerifyProof(JsonSerializer.SerializeToElement(unsecured, DataProofsJsonOptions.Default), derivedProof, pk);
    }

    // The fixture's selective set plus additional baseline-feature selective subsets, so each
    // distinct selective-disclosure pointer set is derived-then-verified.
    public static TheoryData<string[]> SelectivePointerSets()
    {
        var data = new TheoryData<string[]>();
        data.Add(JsonSerializer.Deserialize<string[]>(Fx.Text("w3c", "vc-di-bbs", "TestVectors", "windSelective.json"))!);
        data.Add(new[] { "/credentialSubject/sails/1" });
        data.Add(new[] { "/credentialSubject/boards/1", "/credentialSubject/sails/0" });
        data.Add(Array.Empty<string>()); // mandatory-only disclosure (no selective pointers)
        return data;
    }

    [BbsTheory]
    [MemberData(nameof(SelectivePointerSets))]
    public async Task Derive_FromOwnBaseProof_VerifiesForEachSelectiveSet(string[] selective)
    {
        var (sk, hmacKey) = KeyMaterial();
        var mandatory = WindMandatory();
        var suite = new Bbs2023Cryptosuite();

        var secured = await CreateSecuredBaseAsync(suite, sk, hmacKey, mandatory);

        // Base proof is the W3C base-proof wire form (multibase 'u', CBOR base header u2V0C).
        secured.GetProperty("proof").GetProperty("proofValue").GetString().Should().StartWith("u2V0C");

        var reveal = suite.DeriveProof(secured, selective, Convert.FromHexString("113377aa"));

        // Derived proof carries the W3C derived-proof wire form (CBOR derived header u2V0D).
        reveal.GetProperty("proof").GetProperty("proofValue").GetString().Should().StartWith("u2V0D");

        // Every mandatory value remains present in the reveal document.
        reveal.GetProperty("issuer").GetString().Should().Be("https://vc.example/windsurf/racecommittee");
        reveal.GetProperty("credentialSubject").GetProperty("sailNumber").GetString().Should().Be("Earth101");

        var pk = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk).PublicKey);
        VerifyReveal(suite, reveal, pk).Verified.Should().BeTrue();
    }

    [BbsFact]
    public async Task Derive_TamperedDisclosedValue_FailsClosed()
    {
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await CreateSecuredBaseAsync(suite, sk, hmacKey, WindMandatory());

        var reveal = suite.DeriveProof(secured, ["/credentialSubject/sails/1"], Convert.FromHexString("113377aa"));
        var pk = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk).PublicKey);

        // Tamper a mandatory statement (issuer) — must fail, not throw.
        var tampered = Fx.Mutate(reveal, o => o["issuer"] = "https://evil.example/");
        var derivedProof = reveal.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;
        var tamperedUnsecured = Fx.Mutate(tampered, o => o.Remove("proof"));

        var result = suite.VerifyProof(tamperedUnsecured, derivedProof, pk);
        result.Verified.Should().BeFalse();
        result.Problems.Should().Contain(p => p.Code == ProofProblemCodes.ProofVerificationError);
    }

    [BbsFact]
    public async Task Derive_WrongVerificationKey_FailsClosed()
    {
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await CreateSecuredBaseAsync(suite, sk, hmacKey, WindMandatory());
        var reveal = suite.DeriveProof(secured, ["/credentialSubject/sails/1"], Convert.FromHexString("113377aa"));

        var wrongPk = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.Generate(KeyType.Bls12381G2).PublicKey);
        VerifyReveal(suite, reveal, wrongPk).Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task Derive_CorruptedBbsProofBytes_FailsClosed()
    {
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var secured = await CreateSecuredBaseAsync(suite, sk, hmacKey, WindMandatory());
        var reveal = suite.DeriveProof(secured, ["/credentialSubject/sails/1"], Convert.FromHexString("113377aa"));
        var pk = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk).PublicKey);

        var unsecured = Fx.Mutate(reveal, o => o.Remove("proof"));
        var derivedProof = reveal.GetProperty("proof").Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)!;

        // Sanity: the intact proof verifies (guards against a vacuous negative).
        suite.VerifyProof(unsecured, derivedProof, pk).Verified.Should().BeTrue();

        // Flip a byte inside the decoded derived proofValue (the bbsProof component sits right
        // after the 3-byte header + CBOR byte-string prefix) — verification must fail, not throw.
        var bytes = NetCid.Multibase.Decode(derivedProof.ProofValue!, out _);
        bytes[10] ^= 0xff;
        var corruptedValue = NetCid.Multibase.Encode(bytes, NetCid.MultibaseEncoding.Base64Url);
        var corrupted = derivedProof with { ProofValue = corruptedValue };

        var result = suite.VerifyProof(unsecured, corrupted, pk);
        result.Verified.Should().BeFalse();
    }

    [BbsFact]
    public async Task Verify_RejectsBaseProofPresentedForVerification()
    {
        var (sk, hmacKey) = KeyMaterial();
        var suite = new Bbs2023Cryptosuite();
        var baseProof = await suite.CreateBaseProofAsync(WindDoc(), BaseOptions(), sk, hmacKey, WindMandatory());
        var pk = PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, Fx.KeyGen.FromPrivateKey(KeyType.Bls12381G2, sk).PublicKey);

        // A base proof (u2V0C) is not a derived proof; verification must fail, not throw.
        var result = suite.VerifyProof(WindDoc(), baseProof, pk);
        result.Verified.Should().BeFalse();
    }

    [Fact]
    public void CreateProofAsync_ViaGenericSigner_IsNotSupported()
    {
        var suite = new Bbs2023Cryptosuite();
        var signer = Fx.Signer(Fx.KeyGen.Generate(KeyType.Ed25519));
        var act = () => suite.CreateProofAsync(WindDoc(), BaseOptions(), signer);
        act.Should().ThrowAsync<NotSupportedException>();
    }

    // ---- fixture intermediate / wire-format structural checks (run regardless of BBS) ----

    [Fact]
    public void FixtureBaseProofValue_HasBbsBaseHeaderAndFiveComponents()
    {
        var signed = Fx.Json("w3c", "vc-di-bbs", "TestVectors", "addSignedSDBase.json");
        var proofValue = signed.GetProperty("proof").GetProperty("proofValue").GetString()!;

        proofValue.Should().StartWith("u2V0C");
        DecodeCbor(proofValue, header: [0xd9, 0x5d, 0x02]).Should().Be(5);
    }

    [Fact]
    public void FixtureDerivedProofValue_HasBbsDerivedHeaderAndFiveComponents()
    {
        var derived = Fx.Json("w3c", "vc-di-bbs", "TestVectors", "derivedRevealDocument.json");
        var proofValue = derived.GetProperty("proof").GetProperty("proofValue").GetString()!;

        proofValue.Should().StartWith("u2V0D");
        DecodeCbor(proofValue, header: [0xd9, 0x5d, 0x03]).Should().Be(5);
    }

    // Test-side CBOR inspection (System.Formats.Cbor is allowed in test tooling, not in src).
    private static int DecodeCbor(string proofValue, byte[] header)
    {
        var bytes = NetCid.Multibase.Decode(proofValue, out var encoding);
        encoding.Should().Be(NetCid.MultibaseEncoding.Base64Url);
        bytes.AsSpan(0, 3).ToArray().Should().Equal(header);
        var reader = new System.Formats.Cbor.CborReader(bytes.AsMemory(3).ToArray());
        return reader.ReadStartArray()!.Value;
    }
}
