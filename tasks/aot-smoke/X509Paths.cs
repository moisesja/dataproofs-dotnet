using System.Formats.Asn1;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.SdJwt.Vc;
using DataProofsDotnet.Jose.Signing;
using static DataProofsDotnet.Tools.AotSmoke.Fixtures;

namespace DataProofsDotnet.Tools.AotSmoke;

/// <summary>
/// <c>x5c</c> (issue #46): a compact JWS and an SD-JWT VC signed with a certificate chain, verified with the
/// end-entity key and a hook pinned to the certificate. The certificate is assembled here from fixed fields so every
/// leg emits the same bytes; its signature value is fixed filler, since the library validates no chain.
/// </summary>
internal sealed class X509Path : ISmokePath
{
    private static readonly byte[] Certificate = AssembleCertificate();

    public string Name => "JOSE — x5c certificate chain";

    private static JwsSigner ChainSigner() => new(Signer(Ed)) { CertificateChain = X509CertificateChain.Create([Certificate]) };

    private static bool Pinned(X509CertificateChain chain) => chain.EndEntityCertificate.Span.SequenceEqual(Certificate);

    public async Task EmitAsync(Report report)
    {
        var compact = await JwsBuilder.BuildCompactAsync(Payload, ChainSigner(), typ: "example+jwt");
        Gate.Expect(VerifyCompact(compact), "compact JWS with x5c verifies with the end-entity key");
        Gate.Expect(RefusedUntrusted(compact), "a chain the hook refuses is X5C_UNTRUSTED");
        report.Det("jose.jws.compact.x5c", compact);

        var claims = new JsonObject { ["vct"] = "https://credentials.example.com/identity", ["given_name"] = "John" };
        var issued = await SdJwtVcIssuer.IssueAsync(claims, new DisclosureFrame().Disclose("given_name"), ChainSigner());
        Gate.Expect(await VerifyVc(issued.Issuance), "SD-JWT VC with x5c verifies under the Inline X.509 mechanism");
        report.Artifact("sdJwtVc.x5c", new() { ["issuance"] = issued.Issuance });
    }

    public async Task VerifyAsync(Report report)
    {
        Gate.Expect(VerifyCompact(report.Det("jose.jws.compact.x5c")), "x5c compact JWS from the other run verifies");
        Gate.Expect(await VerifyVc(report.ArtifactString("sdJwtVc.x5c", "issuance")), "x5c SD-JWT VC from the other run verifies");
    }

    private static bool VerifyCompact(string compact)
    {
        var result = JwsParser.ParseCompactWithCertificateChain(compact, Pinned, JoseCrypto);
        return result.PayloadBytes.AsSpan().SequenceEqual(Payload) && result.CertificateChain is { Certificates.Count: 1 };
    }

    private static bool RefusedUntrusted(string compact)
    {
        try
        {
            JwsParser.ParseCompactWithCertificateChain(compact, _ => false, JoseCrypto);
            return false;
        }
        catch (JoseCryptoException ex)
        {
            return ex.Message.StartsWith("X5C_UNTRUSTED", StringComparison.Ordinal);
        }
    }

    private static async Task<bool> VerifyVc(string issuance)
    {
        var result = await SdJwtVcVerifier.VerifyWithCertificateChainAsync(issuance, Pinned, cryptoProvider: JoseCrypto);
        return result.IsValid && result.IssuerCertificateChain is not null && result.DisclosedPayload!["given_name"]!.GetValue<string>() == "John";
    }

    /// <summary>A v3 certificate for the fixed Ed25519 key: fixed names, serial and validity; filler signature.</summary>
    private static byte[] AssembleCertificate()
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                    writer.WriteInteger(2);
                writer.WriteInteger(46);
                WriteAlgorithm(writer, "1.3.101.112");
                WriteName(writer, "AOT smoke CA");
                using (writer.PushSequence())
                {
                    writer.WriteUtcTime(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
                    writer.WriteUtcTime(new DateTimeOffset(2036, 1, 1, 0, 0, 0, TimeSpan.Zero));
                }
                WriteName(writer, "AOT smoke issuer");
                using (writer.PushSequence())
                {
                    WriteAlgorithm(writer, "1.3.101.112");
                    writer.WriteBitString(Ed.PublicKey);
                }
            }
            WriteAlgorithm(writer, "1.3.101.112");
            writer.WriteBitString(new byte[64]);
        }
        return writer.Encode();
    }

    private static void WriteAlgorithm(AsnWriter writer, string oid)
    {
        using (writer.PushSequence())
            writer.WriteObjectIdentifier(oid);
    }

    private static void WriteName(AsnWriter writer, string commonName)
    {
        using (writer.PushSequence())
        using (writer.PushSetOf())
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier("2.5.4.3");
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, commonName);
        }
    }
}
