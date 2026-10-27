using System.Text;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.Cose;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.Encryption;
using DataProofsDotnet.Jose.Jwt;
using DataProofsDotnet.Jose.SdJwt;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;
using static DataProofsDotnet.Tools.AotSmoke.Fixtures;
using Base64Url = DataProofsDotnet.Jose.Base64Url;

namespace DataProofsDotnet.Tools.AotSmoke;

/// <summary>JWS (compact, Flattened, General, DIDComm kid placement), JWT, and JWE (ECDH-ES, A256KW).</summary>
internal sealed class JosePath : ISmokePath
{
    private const string EdKid = "did:example:issuer#ed25519";
    private const string P256Kid = "did:example:issuer#p256";
    private const string RecipientKid = "did:example:bob#p256-enc";
    // '+', '<', '&' and a non-ASCII character exercise the escaping of the JSON serializations.
    private const string KekKid = "kek+1<é>&";

    private static readonly Jwk EdJwk = JwkConversion.ToPublicJwk(Ed.KeyType, Ed.PublicKey, EdKid);
    private static readonly Jwk P256Jwk = JwkConversion.ToPublicJwk(P256.KeyType, P256.PublicKey, P256Kid);
    private static readonly Jwk RecipientPrivate = JwkConversion.ToPrivateJwk(JweP256, RecipientKid);
    private static readonly Jwk RecipientPublic = JwkConversion.ToPublicJwk(JweP256.KeyType, JweP256.PublicKey, RecipientKid);
    private static readonly Jwk Kek = new() { Kty = "oct", K = Base64Url.Encode(SymKey), Kid = KekKid };

    public string Name => "JOSE — JWS, JWT, JWE";

    private static JwsSigner EdSigner(JwsKidPlacement placement = JwsKidPlacement.Auto) => new(Signer(Ed), EdKid, placement);

    private static Jwk? Resolve(string kid) => kid switch
    {
        EdKid => EdJwk,
        P256Kid => P256Jwk,
        _ => null,
    };

    public async Task EmitAsync(Report report)
    {
        var compact = await JwsBuilder.BuildCompactAsync(Payload, EdSigner(), typ: "application/example+json");
        Gate.Expect(JwsParser.ParseCompact(compact, Resolve, JoseCrypto).PayloadBytes.AsSpan().SequenceEqual(Payload), "compact JWS (EdDSA) verifies");
        report.Det("jose.jws.compact.eddsa", compact);
        report.Det("jose.jws.compact.protectedHeader", compact.Split('.')[0]);

        var flattened = await JwsBuilder.BuildJsonAsync(Payload, [EdSigner()]);
        Gate.Expect(JwsParser.Parse(flattened, Resolve, JoseCrypto).SignerKid == EdKid, "Flattened JSON JWS verifies");
        report.Det("jose.jws.flattened.eddsa", flattened);

        var didcomm = await JwsBuilder.BuildJsonAsync(Payload, [EdSigner()], "application/didcomm-signed+json");
        Gate.Expect(JwsParser.Parse(didcomm, Resolve, JoseCrypto).SignerKid == EdKid, "DIDComm JWS (unprotected kid) verifies");
        report.Det("jose.jws.didcomm.eddsa", didcomm);

        var general = await JwsBuilder.BuildJsonAsync(Payload, [EdSigner(), new JwsSigner(Signer(P256), P256Kid)]);
        Gate.Expect(JwsParser.Parse(general, Resolve, JoseCrypto).PayloadBytes.AsSpan().SequenceEqual(Payload), "General JSON JWS (EdDSA + ES256) verifies");
        report.Artifact("jose.jws.general", new() { ["jws"] = general });

        var claims = new JwtClaims(
            issuer: "did:example:issuer",
            subject: "did:example:subject",
            audiences: ["did:example:verifier"],
            expiresAt: FixedTime.AddMinutes(10),
            issuedAt: FixedTime,
            jwtId: "jti-aot-smoke",
            additionalClaims: new Dictionary<string, JsonNode?> { ["scope"] = "credential:read", ["n"] = 42 });
        var jwt = await JwtHandler.SignAsync(claims, EdSigner());
        Gate.Expect(VerifyJwt(jwt), "JWT (EdDSA) verifies with issuer, audience and time checks");
        report.Det("jose.jwt.eddsa", jwt);

        var ecdhEs = JweBuilder.BuildEcdhEsA256Kw(Plaintext, [RecipientPublic], JoseAlgorithms.A256Gcm, JoseCrypto, typ: "application/example-encrypted");
        Gate.Expect(DecryptsGeneral(ecdhEs, RecipientPrivate), "JWE General JSON (ECDH-ES+A256KW, A256GCM) decrypts");
        var a256kw = JweBuilder.BuildA256Kw(Plaintext, [Kek], JoseAlgorithms.A256CbcHs512, JoseCrypto);
        Gate.Expect(DecryptsGeneral(a256kw, Kek), "JWE General JSON (A256KW, A256CBC-HS512) decrypts");
        Gate.Expect(a256kw.Contains("\\u002B", StringComparison.Ordinal), "the General JSON JWE keeps the default encoder for the unprotected kid");
        var compactJwe = JweBuilder.BuildCompactA256Kw(Plaintext, Kek, JoseAlgorithms.A256Gcm, JoseCrypto);
        Gate.Expect(JweParser.ParseCompact(compactJwe, Kek, senderKeys: null, JoseCrypto).Plaintext.AsSpan().SequenceEqual(Plaintext), "compact JWE (A256KW) decrypts");
        report.Artifact("jose.jwe", new() { ["ecdhEs"] = ecdhEs, ["a256kw"] = a256kw, ["compact"] = compactJwe });
    }

    public Task VerifyAsync(Report report)
    {
        Gate.Expect(JwsParser.ParseCompact(report.Det("jose.jws.compact.eddsa"), Resolve, JoseCrypto).PayloadBytes.AsSpan().SequenceEqual(Payload),
            "compact JWS from the other run verifies");
        Gate.Expect(JwsParser.Parse(report.Det("jose.jws.flattened.eddsa"), Resolve, JoseCrypto).SignerKid == EdKid, "Flattened JWS from the other run verifies");
        Gate.Expect(JwsParser.Parse(report.Det("jose.jws.didcomm.eddsa"), Resolve, JoseCrypto).SignerKid == EdKid, "DIDComm JWS from the other run verifies");
        Gate.Expect(JwsParser.Parse(report.ArtifactString("jose.jws.general", "jws"), Resolve, JoseCrypto).PayloadBytes.AsSpan().SequenceEqual(Payload),
            "General JWS from the other run verifies");
        Gate.Expect(VerifyJwt(report.Det("jose.jwt.eddsa")), "JWT from the other run verifies");
        Gate.Expect(DecryptsGeneral(report.ArtifactString("jose.jwe", "ecdhEs"), RecipientPrivate), "ECDH-ES JWE from the other run decrypts");
        Gate.Expect(DecryptsGeneral(report.ArtifactString("jose.jwe", "a256kw"), Kek), "A256KW JWE from the other run decrypts");
        Gate.Expect(JweParser.ParseCompact(report.ArtifactString("jose.jwe", "compact"), Kek, senderKeys: null, JoseCrypto).Plaintext.AsSpan().SequenceEqual(Plaintext),
            "compact JWE from the other run decrypts");
        return Task.CompletedTask;
    }

    private static bool VerifyJwt(string jwt)
    {
        var result = JwtHandler.Verify(jwt, Resolve, new JwtValidationOptions
        {
            CurrentTime = FixedTime.AddMinutes(1),
            ExpectedIssuer = "did:example:issuer",
            ExpectedAudience = "did:example:verifier",
            ExpectedSubject = "did:example:subject",
            RequireExpirationTime = true,
            AllowedAlgorithms = [JoseAlgorithms.EdDSA],
        }, JoseCrypto);
        return result.IsValid && result.Claims?.AdditionalClaims["scope"]?.GetValue<string>() == "credential:read";
    }

    private static bool DecryptsGeneral(string jwe, Jwk key)
        => JweParser.Parse(jwe, new SingleKeyResolver(key), senderKeys: null, JoseCrypto).Plaintext.AsSpan().SequenceEqual(Plaintext);

    private sealed class SingleKeyResolver(Jwk key) : IJweRecipientKeyResolver
    {
        public Jwk? TryGet(string kid) => kid == key.Kid ? key : null;

        public IReadOnlyList<string> FindPresent(IEnumerable<string> kids) => kids.Where(k => k == key.Kid).ToArray();
    }
}

/// <summary>SD-JWT issuance with decoys, holder presentation with a Key Binding JWT, verification.</summary>
internal sealed class SdJwtPath : ISmokePath
{
    private const string IssuerKid = "did:example:issuer#sd";
    private const string HolderKid = "did:example:holder#kb";
    private static readonly Jwk IssuerJwk = JwkConversion.ToPublicJwk(Ed.KeyType, Ed.PublicKey, IssuerKid);

    public string Name => "SD-JWT — issuance, Key Binding presentation, verification";

    public async Task EmitAsync(Report report)
    {
        var claims = new JsonObject
        {
            ["iss"] = "https://issuer.example",
            ["sub"] = "user-42",
            ["given_name"] = "John",
            ["family_name"] = "Doe",
            ["email"] = "john@example.com",
            ["nationalities"] = new JsonArray("US", "DE", "FR"),
        };
        var frame = new DisclosureFrame().Disclose("given_name").Disclose("family_name").Disclose("email").DiscloseArrayElements("nationalities", 0, 2);
        var options = new SdJwtIssuerOptions
        {
            HashAlgorithm = SdHashAlgorithm.Sha256,
            DecoyDigestCount = 2,
            HolderConfirmationKey = JwkConversion.ToPublicJwk(HolderP256.KeyType, HolderP256.PublicKey, HolderKid),
        };
        var issued = await SdJwtIssuer.IssueAsync(claims, frame, new JwsSigner(Signer(Ed), IssuerKid), options);
        var issuerPayload = JsonNode.Parse(Base64Url.DecodeUtf8(issued.IssuerJwt.Split('.')[1]))!.AsObject();
        report.Det("sdJwt.issuerJwt.sdAlg", issuerPayload["_sd_alg"]!.GetValue<string>());

        var reveal = issued.Disclosures.Where(d => d.ClaimName is "given_name" or "email" || d.ClaimName is null).Select(d => d.Encoded);
        var presentation = await SdJwtHolder.CreatePresentationWithKeyBindingAsync(
            issued.Issuance, reveal, new JwsSigner(Signer(HolderP256), HolderKid), Audience, Nonce, FixedTime);
        var disclosed = Verify(presentation);
        report.Det("sdJwt.disclosedClaims", disclosed);
        report.Artifact("sdJwt", new() { ["presentation"] = presentation });
    }

    public Task VerifyAsync(Report report)
    {
        Gate.Expect(Verify(report.ArtifactString("sdJwt", "presentation")) == report.Det("sdJwt.disclosedClaims"),
            "SD-JWT presentation from the other run verifies and discloses the same claims");
        return Task.CompletedTask;
    }

    private static string Verify(string presentation)
    {
        var result = SdJwtVerifier.Verify(presentation, _ => IssuerJwk, new SdJwtVerificationOptions
        {
            RequireKeyBinding = true,
            ExpectedAudience = Audience,
            ExpectedNonce = Nonce,
            MaxKeyBindingAge = TimeSpan.FromMinutes(5),
            CurrentTime = FixedTime.AddMinutes(1),
        }, JoseCrypto);
        Gate.Expect(result.IsValid && result.KeyBindingVerified, $"SD-JWT with Key Binding verifies{(result.Errors.Count > 0 ? ": " + string.Join("; ", result.Errors) : "")}");
        var payload = result.DisclosedPayload!;
        Gate.Expect(payload["given_name"]?.GetValue<string>() == "John" && !payload.ContainsKey("family_name"),
            "the presented claim is disclosed and the withheld one is not");
        var nationalities = string.Join("|", payload["nationalities"]!.AsArray().Select(n => n!.GetValue<string>()));
        return string.Join(",", payload.Select(p => p.Key).Order(StringComparer.Ordinal)) + ";nationalities=" + nationalities;
    }
}

/// <summary>COSE_Sign1, CWT, and both halves of VC-JOSE-COSE.</summary>
internal sealed class CoseAndVcPath : ISmokePath
{
    private const string VcKid = "did:example:issuer#vc";
    private static readonly byte[] KeyId = "issuer-key"u8.ToArray();
    private static readonly Jwk VcJwk = JwkConversion.ToPublicJwk(Ed.KeyType, Ed.PublicKey, VcKid);

    public string Name => "COSE_Sign1, CWT, VC-JOSE, VC-COSE";

    public async Task EmitAsync(Report report)
    {
        var sign1 = await CoseSign1.SignAsync(Payload, Signer(Ed), new CoseSign1SignOptions
        {
            Algorithm = CoseAlgorithm.EdDsa,
            KeyId = KeyId,
            ContentType = "application/json",
        });
        Gate.Expect(CoseSign1.Verify(sign1, KeyType.Ed25519, Ed.PublicKey).Verified, "COSE_Sign1 (EdDSA) verifies");
        report.Det("cose.sign1.eddsa", Hex(sign1));

        var es256 = await CoseSign1.SignAsync(Payload, Signer(P256), new CoseSign1SignOptions { Algorithm = CoseAlgorithm.ES256, KeyId = KeyId });
        Gate.Expect(CoseSign1.Verify(es256, KeyType.P256, P256.PublicKey).Verified, "COSE_Sign1 (ES256) verifies");
        report.Artifact("cose.sign1.es256", new() { ["hex"] = Hex(es256) });

        var cwt = await Cwt.SignAsync(new CwtClaims
        {
            Issuer = "coap://as.example.com",
            Subject = "device-7",
            Audience = "coap://rs.example.com",
            ExpirationTime = FixedTime.AddHours(1),
            IssuedAt = FixedTime,
            CwtId = new byte[] { 0x0b, 0x71 },
        }, Signer(Ed), new CwtSignOptions { Algorithm = CoseAlgorithm.EdDsa, KeyId = KeyId, IncludeCwtTag = true });
        Gate.Expect(VerifyCwt(cwt), "CWT (EdDSA) verifies with its time checks");
        report.Det("cose.cwt.eddsa", Hex(cwt));

        var vcJose = await VcJose.EnvelopeCredentialAsync(CredentialBytes, new JwsSigner(Signer(Ed), VcKid));
        Gate.Expect(VcJose.VerifyCredential(vcJose, _ => VcJwk, JoseCrypto).AsSpan().SequenceEqual(CredentialBytes), "VC-JOSE envelope verifies");
        report.Det("vc.jose.eddsa", vcJose);

        var vcCose = await VcCose.EnvelopeCredentialAsync(CredentialBytes, Signer(Ed), CoseAlgorithm.EdDsa, keyId: KeyId);
        Gate.Expect(VcCose.Verify(vcCose, KeyType.Ed25519, Ed.PublicKey).Verified, "VC-COSE envelope verifies");
        report.Det("vc.cose.eddsa", Hex(vcCose));
    }

    public Task VerifyAsync(Report report)
    {
        Gate.Expect(CoseSign1.Verify(Convert.FromHexString(report.Det("cose.sign1.eddsa")), KeyType.Ed25519, Ed.PublicKey).Verified,
            "COSE_Sign1 (EdDSA) from the other run verifies");
        Gate.Expect(CoseSign1.Verify(Convert.FromHexString(report.ArtifactString("cose.sign1.es256", "hex")), KeyType.P256, P256.PublicKey).Verified,
            "COSE_Sign1 (ES256) from the other run verifies");
        Gate.Expect(VerifyCwt(Convert.FromHexString(report.Det("cose.cwt.eddsa"))), "CWT from the other run verifies");
        Gate.Expect(VcJose.VerifyCredential(report.Det("vc.jose.eddsa"), _ => VcJwk, JoseCrypto).AsSpan().SequenceEqual(CredentialBytes),
            "VC-JOSE envelope from the other run verifies");
        Gate.Expect(VcCose.Verify(Convert.FromHexString(report.Det("vc.cose.eddsa")), KeyType.Ed25519, Ed.PublicKey).Verified,
            "VC-COSE envelope from the other run verifies");
        return Task.CompletedTask;
    }

    private static bool VerifyCwt(byte[] cwt)
    {
        var result = Cwt.Verify(cwt, KeyType.Ed25519, Ed.PublicKey, new CwtValidationOptions { ValidationTime = FixedTime.AddMinutes(1) });
        return result.Verified && result.Claims?.Subject == "device-7";
    }
}

/// <summary>JWK conversion through Multikey and the Microsoft.IdentityModel JsonWebKey boundary type.</summary>
internal sealed class JwkPath : ISmokePath
{
    public string Name => "JWK — Multikey, IdentityModel JsonWebKey, RFC 7638 thumbprints";

    public Task EmitAsync(Report report)
    {
        foreach (var (label, key) in new[] { ("ed25519", Ed), ("p256", P256) })
        {
            var jwk = JwkConversion.ToPublicJwk(key.KeyType, key.PublicKey, $"{label}-key");
            Gate.Expect(JwkConversion.ToMultikey(jwk) == key.MultibasePublicKey, $"{label}: JWK → Multikey round-trips");
            Gate.Expect(JwkConversion.ToMultikey(JwkConversion.FromMultikey(key.MultibasePublicKey)) == key.MultibasePublicKey,
                $"{label}: Multikey → JWK → Multikey round-trips");
            var ms = JwkConversion.ToJsonWebKey(jwk);
            Gate.Expect(ms.Kty == jwk.Kty && ms.X == jwk.X && ms.Kid == jwk.Kid, $"{label}: converts to Microsoft.IdentityModel JsonWebKey");
            var material = PublicKeyMaterial.FromJsonWebKey(Pk(key).ToJsonWebKey());
            Gate.Expect(material.ToMultikey() == key.MultibasePublicKey, $"{label}: PublicKeyMaterial ↔ JsonWebKey round-trips");
            report.Det($"jwk.{label}.thumbprint", JwkThumbprint.ComputeBase64Url(jwk));
            report.Det($"jwk.{label}.multikey", key.MultibasePublicKey);
        }

        return Task.CompletedTask;
    }

    public Task VerifyAsync(Report report)
    {
        foreach (var (label, key) in new[] { ("ed25519", Ed), ("p256", P256) })
        {
            var jwk = JwkConversion.FromMultikey(report.Det($"jwk.{label}.multikey"));
            Gate.Expect(JwkThumbprint.ComputeBase64Url(jwk) == report.Det($"jwk.{label}.thumbprint"), $"{label}: the other run's thumbprint recomputes");
            Gate.Expect(report.Det($"jwk.{label}.multikey") == key.MultibasePublicKey, $"{label}: the other run used the same seed key");
        }

        return Task.CompletedTask;
    }
}
