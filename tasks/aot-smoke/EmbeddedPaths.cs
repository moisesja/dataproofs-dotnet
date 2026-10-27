using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Extensions.DependencyInjection;
using DataProofsDotnet.Legacy.DataIntegrity;
using DataProofsDotnet.Rdfc;
using DataProofsDotnet.Rdfc.DataIntegrity;
using Microsoft.Extensions.DependencyInjection;
using NetCid;
using NetCrypto;
using static DataProofsDotnet.Tools.AotSmoke.Fixtures;

namespace DataProofsDotnet.Tools.AotSmoke;

/// <summary>One exercised path: emit records outputs; verify re-checks another run's outputs.</summary>
internal interface ISmokePath
{
    string Name { get; }

    Task EmitAsync(Report report);

    Task VerifyAsync(Report report);
}

/// <summary>PR #35: exercise all three packages' property-metadata guards, including on cold AOT metadata.</summary>
internal sealed class ProofInputPath : ISmokePath
{
    public string Name => "Proof extension names — Core, Rdfc and Legacy metadata";

    public async Task EmitAsync(Report report)
    {
        ICryptosuite[] suites =
        [
            new EddsaJcs2022Cryptosuite(),
            new EddsaRdfc2022Cryptosuite(),
            new Ed25519Signature2020Cryptosuite(),
        ];
        foreach (var suite in suites)
        {
            var options = Proof(suite.Name, Ed) with
            {
                AdditionalProperties = new Dictionary<string, JsonElement> { ["proofValue"] = Parse("\"zFake\"") },
            };
            var rejected = false;
            try
            {
                _ = await suite.CreateProofAsync(Credential(), options, Signer(Ed));
            }
            catch (ProofGenerationException ex)
            {
                rejected = ex.Message == "The proof configuration has an extension member with a reserved proof name.";
            }

            Gate.Expect(rejected, $"{suite.Name} rejects an extension named proofValue before adding its signature");

            var validOptions = options with
            {
                AdditionalProperties = new Dictionary<string, JsonElement> { ["ProofValue"] = Parse("\"metadata\"") },
            };
            var proof = await suite.CreateProofAsync(Credential(), validOptions, Signer(Ed));
            Gate.Expect(suite.VerifyProof(Credential(), proof, Pk(Ed)).Verified,
                $"{suite.Name} accepts the case-distinct extension and verifies its proof");
        }
    }

    public Task VerifyAsync(Report report) => Task.CompletedTask;
}

/// <summary>Data Integrity with the JCS suites, including a proof chain (array-form previousProof).</summary>
internal sealed class JcsPath : ISmokePath
{
    private static readonly DataIntegrityProofPipeline Pipeline = new(CryptosuiteRegistry.CreateDefault());

    public string Name => "Data Integrity — eddsa-jcs-2022, ecdsa-jcs-2019, proof chain";

    public async Task EmitAsync(Report report)
    {
        var ed = await Pipeline.AddProofAsync(Credential(), Proof(EddsaJcs2022Cryptosuite.CryptosuiteName, Ed), Signer(Ed));
        Gate.Expect(Pipeline.Verify(ed, Pk(Ed), AssertionMethod), "eddsa-jcs-2022 verifies (raw key)");
        Gate.Expect((await Pipeline.VerifyAsync(ed, Resolver(Ed), AssertionMethod)).Verified, "eddsa-jcs-2022 verifies (resolver)");
        report.Det("dataIntegrity.jcs.eddsa.secured", Compact(ed));
        report.Det("dataIntegrity.jcs.canonicalDocumentHex", Hex(JcsCanonicalizer.Canonicalize(Credential())));

        var ecdsa = await Pipeline.AddProofAsync(Credential(), Proof(EcdsaJcs2019Cryptosuite.CryptosuiteName, P256), Signer(P256));
        Gate.Expect(Pipeline.Verify(ecdsa, Pk(P256), AssertionMethod).Verified, "ecdsa-jcs-2019 verifies (raw key)");
        report.Artifact("dataIntegrity.jcs.ecdsa", new() { ["secured"] = Wrap(ecdsa) });

        // A proof chain: the second proof references the first through an array-form previousProof,
        // so the public PreviousProofReferenceJsonConverter runs on both the write and the read side.
        var first = await Pipeline.AddProofAsync(
            Credential(), Proof(EddsaJcs2022Cryptosuite.CryptosuiteName, Ed) with { Id = "urn:uuid:aot-smoke-1" }, Signer(Ed));
        var chained = await Pipeline.AddProofAsync(
            first,
            Proof(EddsaJcs2022Cryptosuite.CryptosuiteName, Ed2) with
            {
                Id = "urn:uuid:aot-smoke-2",
                PreviousProof = PreviousProofReference.FromValues(["urn:uuid:aot-smoke-1"]),
            },
            Signer(Ed2));
        var chainResult = await Pipeline.VerifyAsync(chained, Resolver(Ed, Ed2), AssertionMethod);
        Gate.Expect(chainResult.Verified && chainResult.ProofResults.Count == 2, "proof chain verifies (2 proofs)");
        report.Det("dataIntegrity.jcs.chain.secured", Compact(chained));
    }

    public async Task VerifyAsync(Report report)
    {
        Gate.Expect(Pipeline.Verify(Parse(report.Det("dataIntegrity.jcs.eddsa.secured")), Pk(Ed), AssertionMethod).Verified,
            "eddsa-jcs-2022 document from the other run verifies");
        Gate.Expect(Pipeline.Verify(report.ArtifactElement("dataIntegrity.jcs.ecdsa", "secured"), Pk(P256), AssertionMethod).Verified,
            "ecdsa-jcs-2019 document from the other run verifies");
        Gate.Expect((await Pipeline.VerifyAsync(Parse(report.Det("dataIntegrity.jcs.chain.secured")), Resolver(Ed, Ed2), AssertionMethod)).Verified,
            "proof chain from the other run verifies");
    }
}

/// <summary>RDFC-1.0 through dotNetRdf with the offline loader, and the RDFC suites.</summary>
internal sealed class RdfcPath : ISmokePath
{
    private static readonly RdfcDocumentCanonicalizer Canonicalizer = new(OfflineDocumentLoader.Instance);
    private static readonly DataIntegrityProofPipeline Pipeline = new(RdfcCryptosuiteRegistration.CreateWithRdfcSuites(Canonicalizer));

    public string Name => "RDFC-1.0 (offline loader) — eddsa-rdfc-2022, ecdsa-rdfc-2019";

    public async Task EmitAsync(Report report)
    {
        var inline = Encoding.UTF8.GetString(Canonicalizer.CanonicalizeJsonLd(InlineContextDoc()));
        Gate.Expect(inline.Contains("_:c14n0", StringComparison.Ordinal), "inline-context document canonicalizes with a c14n blank-node label");
        report.Det("rdfc.nquads.inlineContext", inline);

        var vc = Encoding.UTF8.GetString(Canonicalizer.CanonicalizeJsonLd(Credential()));
        Gate.Expect(vc.Contains("https://www.w3.org/2018/credentials#VerifiableCredential", StringComparison.Ordinal),
            "VC v2 document canonicalizes through the offline document loader");
        report.Det("rdfc.nquads.vcV2OfflineLoader", vc);

        var ed = await Pipeline.AddProofAsync(Credential(), Proof(EddsaRdfc2022Cryptosuite.CryptosuiteName, Ed), Signer(Ed));
        Gate.Expect(Pipeline.Verify(ed, Pk(Ed), AssertionMethod).Verified, "eddsa-rdfc-2022 verifies");
        report.Det("dataIntegrity.rdfc.eddsa.secured", Compact(ed));

        var ecdsa = await Pipeline.AddProofAsync(Credential(), Proof(EcdsaRdfc2019Cryptosuite.CryptosuiteName, P256), Signer(P256));
        Gate.Expect(Pipeline.Verify(ecdsa, Pk(P256), AssertionMethod).Verified, "ecdsa-rdfc-2019 verifies");
        report.Artifact("dataIntegrity.rdfc.ecdsa", new() { ["secured"] = Wrap(ecdsa) });
    }

    public Task VerifyAsync(Report report)
    {
        Gate.Expect(Pipeline.Verify(Parse(report.Det("dataIntegrity.rdfc.eddsa.secured")), Pk(Ed), AssertionMethod).Verified,
            "eddsa-rdfc-2022 document from the other run verifies");
        Gate.Expect(Pipeline.Verify(report.ArtifactElement("dataIntegrity.rdfc.ecdsa", "secured"), Pk(P256), AssertionMethod).Verified,
            "ecdsa-rdfc-2019 document from the other run verifies");
        return Task.CompletedTask;
    }
}

/// <summary>bbs-2023: issuer base proof, holder derived proof, verifier. Required where NetCrypto ships BBS.</summary>
internal sealed class Bbs2023Path : ISmokePath
{
    // Every RID for which NetCrypto 1.4.0 ships the native BBS library (runtimes/*/native/zkryptium_ffi).
    private static readonly string[] RequiredOn = ["osx-arm64", "osx-x64", "linux-x64", "linux-arm64", "win-x64"];
    private static readonly string[] Mandatory = ["/issuer", "/credentialSubject/id"];
    private static readonly string[] Selective = ["/credentialSubject/gpa"];
    private static readonly byte[] PresentationHeader = [0x11, 0x33, 0x77, 0xaa];

    public string Name => "bbs-2023 — base proof, derive, verify";

    public static bool IsAvailable() => new Bbs2023Cryptosuite().IsAvailable;

    public async Task EmitAsync(Report report)
    {
        var suite = new Bbs2023Cryptosuite();
        if (!suite.IsAvailable)
        {
            if (RequiredOn.Contains(RuntimeInformation.RuntimeIdentifier, StringComparer.Ordinal))
            {
                Gate.Fail($"bbs-2023 is unavailable on {RuntimeInformation.RuntimeIdentifier}, where NetCrypto ships the native BBS library");
            }

            Console.WriteLine($"  note: bbs-2023 unavailable on {RuntimeInformation.RuntimeIdentifier}; path skipped");
            return;
        }

        var key = Bbs();
        var baseProof = await suite.CreateBaseProofAsync(
            BbsCredential(), Proof(Bbs2023Cryptosuite.CryptosuiteName, key), key.PrivateKey, HmacKey, Mandatory);
        var securedBase = Embed(BbsCredential(), baseProof);
        report.Det("dataIntegrity.bbs2023.base.secured", Compact(securedBase));

        var reveal = suite.DeriveProof(securedBase, Selective, PresentationHeader);
        var subject = reveal.GetProperty("credentialSubject");
        Gate.Expect(subject.TryGetProperty("gpa", out _) && !subject.TryGetProperty("favoriteColor", out _),
            "derived proof reveals the selected claim and withholds the other");
        Gate.Expect(VerifyReveal(suite, reveal, key), "bbs-2023 derived proof verifies");
        report.Artifact("dataIntegrity.bbs2023.reveal", new() { ["reveal"] = Wrap(reveal) });
    }

    public Task VerifyAsync(Report report)
    {
        if (!report.HasArtifact("dataIntegrity.bbs2023.reveal"))
        {
            Gate.Expect(report.Runtime["bbsAvailable"]?.GetValue<bool>() == false, "the other run skipped bbs-2023 only because BBS was unavailable");
            return Task.CompletedTask;
        }

        var suite = new Bbs2023Cryptosuite();
        if (!suite.IsAvailable)
        {
            Console.WriteLine("  note: bbs-2023 unavailable here; the other run's derived proof is not re-verified");
            return Task.CompletedTask;
        }

        Gate.Expect(VerifyReveal(suite, report.ArtifactElement("dataIntegrity.bbs2023.reveal", "reveal"), Bbs()),
            "bbs-2023 derived proof from the other run verifies");
        return Task.CompletedTask;
    }

    private static bool VerifyReveal(Bbs2023Cryptosuite suite, JsonElement reveal, KeyPair key)
    {
        var (unsecured, proof) = Split(reveal);
        return suite.VerifyProof(unsecured, proof, PublicKeyMaterial.FromRaw(KeyType.Bls12381G2, key.PublicKey)).Verified;
    }
}

/// <summary>The opt-in legacy suites, including the RDFC signing input zcap-dotnet uses.</summary>
internal sealed class LegacyPath : ISmokePath
{
    private static readonly RdfcDocumentCanonicalizer Canonicalizer = new(OfflineDocumentLoader.Instance);

    private static readonly DataIntegrityProofPipeline Jcs = Build(
        new Ed25519Signature2020Cryptosuite(), new EcdsaSecp256r1Signature2019Cryptosuite());
    private static readonly DataIntegrityProofPipeline Rdfc = Build(
        new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Rdfc, Canonicalizer),
        new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Rdfc, Canonicalizer));

    public string Name => "Legacy — Ed25519Signature2020 and EcdsaSecp256r1Signature2019, JCS and RDFC";

    public async Task EmitAsync(Report report)
    {
        var edJcs = await Jcs.AddProofAsync(Credential(), LegacyProof(Ed25519Signature2020Cryptosuite.ProofType, Ed), Signer(Ed));
        Gate.Expect(!edJcs.GetProperty("proof").TryGetProperty("cryptosuite", out _), "Ed25519Signature2020 emits no cryptosuite member");
        Gate.Expect(Jcs.Verify(edJcs, Pk(Ed), AssertionMethod).Verified, "Ed25519Signature2020 (JCS) verifies");
        report.Det("legacy.ed25519Signature2020.jcs.secured", Compact(edJcs));

        var p256Jcs = await Jcs.AddProofAsync(Credential(), LegacyProof(EcdsaSecp256r1Signature2019Cryptosuite.ProofType, P256), Signer(P256));
        Gate.Expect(Jcs.Verify(p256Jcs, Pk(P256), AssertionMethod).Verified, "EcdsaSecp256r1Signature2019 (JCS) verifies");
        report.Artifact("legacy.ecdsaSecp256r1Signature2019.jcs", new() { ["secured"] = Wrap(p256Jcs) });

        var edRdfc = await Rdfc.AddProofAsync(Credential(), LegacyProof(Ed25519Signature2020Cryptosuite.ProofType, Ed), Signer(Ed));
        Gate.Expect(Rdfc.Verify(edRdfc, Pk(Ed), AssertionMethod).Verified, "Ed25519Signature2020 (RDFC) verifies");
        report.Det("legacy.ed25519Signature2020.rdfc.secured", Compact(edRdfc));

        var p256 = await Rdfc.AddProofAsync(Credential(), LegacyProof(EcdsaSecp256r1Signature2019Cryptosuite.ProofType, P256), Signer(P256));
        Gate.Expect(Rdfc.Verify(p256, Pk(P256), AssertionMethod).Verified, "EcdsaSecp256r1Signature2019 (RDFC) verifies");
        report.Artifact("legacy.ecdsaSecp256r1Signature2019.rdfc", new() { ["secured"] = Wrap(p256) });
    }

    public Task VerifyAsync(Report report)
    {
        Gate.Expect(Jcs.Verify(Parse(report.Det("legacy.ed25519Signature2020.jcs.secured")), Pk(Ed), AssertionMethod).Verified,
            "Ed25519Signature2020 (JCS) document from the other run verifies");
        Gate.Expect(Jcs.Verify(report.ArtifactElement("legacy.ecdsaSecp256r1Signature2019.jcs", "secured"), Pk(P256), AssertionMethod).Verified,
            "EcdsaSecp256r1Signature2019 (JCS) document from the other run verifies");
        Gate.Expect(Rdfc.Verify(Parse(report.Det("legacy.ed25519Signature2020.rdfc.secured")), Pk(Ed), AssertionMethod).Verified,
            "Ed25519Signature2020 (RDFC) document from the other run verifies");
        Gate.Expect(Rdfc.Verify(report.ArtifactElement("legacy.ecdsaSecp256r1Signature2019.rdfc", "secured"), Pk(P256), AssertionMethod).Verified,
            "EcdsaSecp256r1Signature2019 (RDFC) document from the other run verifies");
        return Task.CompletedTask;
    }

    private static DataProofsDotnet.DataIntegrity.DataIntegrityProof LegacyProof(string proofType, KeyPair key)
        => Proof(proofType, key, type: proofType);

    private static DataIntegrityProofPipeline Build(params ICryptosuite[] suites)
    {
        var registry = CryptosuiteRegistry.CreateDefault();
        foreach (var suite in suites)
        {
            registry.Register(suite);
        }

        return new DataIntegrityProofPipeline(registry);
    }
}

/// <summary>AddDataProofs composition, and the serializer-metadata contract a consumer relies on.</summary>
internal sealed class CompositionPath : ISmokePath
{
    public string Name => "AddDataProofs composition; consumer JsonSerializerContext; DataProofsJsonOptions.Default";

    public async Task EmitAsync(Report report)
    {
        var services = new ServiceCollection();
        services.AddDataProofs((DataProofsBuilder builder) => builder
            .AddJcsSuites()
            .AddRdfcSuites()
            .AddBbs2023()
            .AddJose()
            .AddCose()
            .AddVerificationMethodResolver(Resolver(Ed)));
        using var provider = services.BuildServiceProvider();
        var registry = provider.GetRequiredService<CryptosuiteRegistry>();
        var pipeline = provider.GetRequiredService<DataIntegrityProofPipeline>();
        var names = registry.RegisteredNames.Order(StringComparer.Ordinal).ToArray();
        Gate.Expect(names.Contains(Bbs2023Cryptosuite.CryptosuiteName) && names.Contains(EddsaRdfc2022Cryptosuite.CryptosuiteName),
            "AddDataProofs registered the JCS, RDFC and bbs-2023 suites");
        report.Det("di.registeredSuites", string.Join(",", names));

        var secured = await pipeline.AddProofAsync(Credential(), Proof(EddsaJcs2022Cryptosuite.CryptosuiteName, Ed), Signer(Ed));
        var verified = await pipeline.VerifyAsync(secured, provider.GetRequiredService<IVerificationMethodResolver>(), AssertionMethod);
        Gate.Expect(verified.Verified, "the DI-resolved pipeline signs and verifies through the DI-registered resolver");
        Gate.Expect(Compact(secured) == report.Det("dataIntegrity.jcs.eddsa.secured"),
            "the DI-resolved pipeline emits the same bytes as the hand-built one");

        // The downstream scenario (zcap-dotnet#154): a consumer context lists DataIntegrityProof.
        var proofMember = secured.GetProperty("proof");
        var proof = proofMember.Deserialize(AotSmokeJson.Proof)!;
        var reserialized = JsonSerializer.Serialize(proof, AotSmokeJson.Proof);
        Gate.Expect(reserialized == proofMember.GetRawText(), "a consumer context round-trips the library's proof byte for byte");
        report.Det("consumerContext.proofType", proof.Type);
        report.Det("consumerContext.proofRoundTrip", reserialized);

        // DataProofsJsonOptions.Default resolves the library's own types without reflection in every host.
        var viaDefault = (JsonTypeInfo<DataProofsDotnet.DataIntegrity.DataIntegrityProof>)DataProofsJsonOptions.Default.GetTypeInfo(
            typeof(DataProofsDotnet.DataIntegrity.DataIntegrityProof));
        report.Det("defaultOptions.proof", JsonSerializer.Serialize(proof, viaDefault));

        // …and resolves a consumer's type only where the host enables reflection (runtime-specific, so
        // recorded in the runtime block, not compared).
        var consumerResolvable = DataProofsJsonOptions.Default.TryGetTypeInfo(typeof(ConsumerType), out _);
        Gate.Expect(consumerResolvable == JsonSerializer.IsReflectionEnabledByDefault,
            "DataProofsJsonOptions.Default resolves a consumer type exactly when reflection-based serialization is enabled");
        report.Runtime["defaultOptionsResolvesConsumerType"] = consumerResolvable;
    }

    public Task VerifyAsync(Report report)
    {
        var proof = JsonSerializer.Deserialize(report.Det("consumerContext.proofRoundTrip"), AotSmokeJson.Proof)!;
        Gate.Expect(proof.Type == report.Det("consumerContext.proofType"), "the other run's proof parses through the consumer context");
        Gate.Expect(report.Runtime["defaultOptionsResolvesConsumerType"]?.GetValue<bool>() == report.Runtime["reflectionEnabled"]?.GetValue<bool>(),
            "the other run's DataProofsJsonOptions.Default consumer-type resolution matched its reflection switch");
        return Task.CompletedTask;
    }

    private sealed class ConsumerType
    {
        public string? Name { get; set; }
    }
}
