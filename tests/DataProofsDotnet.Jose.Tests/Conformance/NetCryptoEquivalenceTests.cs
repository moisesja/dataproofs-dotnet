using System.Text.RegularExpressions;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Conformance;

/// <summary>
/// AC-3 step 4 — the FR-14 ↔ NetCrypto equivalence checkpoint: the set of JWE
/// content-encryption and key-management algorithms <c>Jose</c> registers must equal the set
/// derivable from NetCrypto v1's published primitive surface, with every deliberate gap
/// documented in <c>jwe-algorithm-omissions.md</c>. Fails on any unexplained divergence — the
/// standing CI guard that no Jose algorithm bypasses NetCrypto and no backable algorithm goes
/// silently missing.
/// </summary>
public sealed partial class NetCryptoEquivalenceTests
{
    [GeneratedRegex(@"^\|\s*`(?<alg>[^`]+)`\s*\|")]
    private static partial Regex OmissionRow();

    private static (IReadOnlySet<string> Alg, IReadOnlySet<string> Enc) ReadOmissions()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "jwe-algorithm-omissions.md");
        var lines = File.ReadAllLines(path);
        var alg = new HashSet<string>(StringComparer.Ordinal);
        var enc = new HashSet<string>(StringComparer.Ordinal);
        HashSet<string>? current = null;
        foreach (var line in lines)
        {
            if (line.StartsWith("## Omitted key-management", StringComparison.Ordinal)) { current = alg; continue; }
            if (line.StartsWith("## Omitted content-encryption", StringComparison.Ordinal)) { current = enc; continue; }
            if (line.StartsWith("## ", StringComparison.Ordinal)) { current = null; continue; }
            if (current is null) continue;
            var m = OmissionRow().Match(line);
            if (m.Success && m.Groups["alg"].Value != "Algorithm")
                current.Add(m.Groups["alg"].Value);
        }
        return (alg, enc);
    }

    /// <summary>
    /// The standard JOSE algorithms derivable from NetCrypto's published primitive surface,
    /// discovered by reflection over the NetCrypto assembly (not hard-coded names of what we
    /// happen to implement).
    /// </summary>
    private static (IReadOnlySet<string> Alg, IReadOnlySet<string> Enc) DeriveBackableFromNetCrypto()
    {
        var netCrypto = typeof(NetCrypto.KeyType).Assembly;
        bool Has(string typeName) => netCrypto.GetType($"NetCrypto.{typeName}") is not null;
        var hasRawEcdh = typeof(NetCrypto.ICryptoProvider).GetMethod("DeriveSharedSecret") is not null;
        var hasConcatKdf = Has("ConcatKdf");
        var hasAesKw = Has("AesKeyWrap"); // 32-byte KEK only ⇒ backs exactly the 256-bit wrap

        var enc = new HashSet<string>(StringComparer.Ordinal);
        if (Has("AesGcmCipher")) enc.Add("A256GCM");
        if (Has("AesCbcHmacCipher")) enc.Add("A256CBC-HS512");
        if (Has("XChaCha20Poly1305Cipher")) enc.Add("XC20P");

        var alg = new HashSet<string>(StringComparer.Ordinal) { "dir" }; // 'dir' needs no primitive at all
        if (hasAesKw) alg.Add("A256KW");
        if (hasRawEcdh && hasConcatKdf)
        {
            alg.Add("ECDH-ES");
            alg.Add("ECDH-1PU");
            if (hasAesKw)
            {
                alg.Add("ECDH-ES+A256KW");
                alg.Add("ECDH-1PU+A256KW");
            }
        }
        return (alg, enc);
    }

    [Fact]
    public void Every_registered_jwe_algorithm_has_a_netcrypto_backing()
    {
        var (backableAlg, backableEnc) = DeriveBackableFromNetCrypto();

        JoseAlgorithms.SupportedContentEncryptionAlgorithms.Should().BeSubsetOf(backableEnc,
            because: "no implemented content-encryption algorithm may lack a NetCrypto primitive (PRD FR-14: none is rolled locally).");
        JoseAlgorithms.SupportedKeyManagementAlgorithms.Should().BeSubsetOf(backableAlg,
            because: "no implemented key-management algorithm may lack a NetCrypto backing.");
    }

    [Fact]
    public void Every_backable_but_unregistered_algorithm_is_documented_in_the_omissions_file()
    {
        var (backableAlg, backableEnc) = DeriveBackableFromNetCrypto();
        var (omittedAlg, omittedEnc) = ReadOmissions();

        var missingEnc = backableEnc.Except(JoseAlgorithms.SupportedContentEncryptionAlgorithms, StringComparer.Ordinal).ToHashSet(StringComparer.Ordinal);
        missingEnc.Should().BeEquivalentTo(omittedEnc,
            because: "every NetCrypto-backable 'enc' that Jose does not register must have a documented reason in jwe-algorithm-omissions.md — and nothing else may be listed there.");

        var missingAlg = backableAlg.Except(JoseAlgorithms.SupportedKeyManagementAlgorithms, StringComparer.Ordinal).ToHashSet(StringComparer.Ordinal);
        missingAlg.Should().BeEquivalentTo(omittedAlg,
            because: "every NetCrypto-backable 'alg' that Jose does not register must have a documented reason in jwe-algorithm-omissions.md — and nothing else may be listed there.");
    }

    [Fact]
    public void No_documented_omission_is_actually_registered()
    {
        var (omittedAlg, omittedEnc) = ReadOmissions();

        JoseAlgorithms.SupportedKeyManagementAlgorithms.Should().NotIntersectWith(omittedAlg,
            because: "an algorithm cannot be both registered and documented as omitted — the omissions file would be stale.");
        JoseAlgorithms.SupportedContentEncryptionAlgorithms.Should().NotIntersectWith(omittedEnc);
    }
}
