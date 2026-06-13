// Generator for the frozen ES256K / XC20P regression vectors required by PRD AC-3 step 1.
// Output: tests/fixtures/generated/es256k-jws.json and xc20p.json (+ see PROVENANCE.md there).
//
// The vectors are FROZEN: this tool refuses to overwrite existing files unless --force is
// passed, so re-running it cannot silently re-pin the regression baseline. Determinism notes:
//   * ES256K — NetCrypto's secp256k1 signing uses RFC 6979 deterministic nonces, so the JWS
//     signature bytes are a pure function of (key, signing input) and can be byte-compared.
//   * XC20P — the AEAD KAT is a pure function of (key, nonce, aad, plaintext). The frozen JWE
//     artifact embeds the ephemeral key chosen at generation time; its DECRYPT direction is
//     deterministic and is what the regression test exercises.
//
// No external oracle exists for either algorithm in the test stack (jose-jwt's closed enums
// exclude ES256K and XC20P) — see tests/fixtures/generated/PROVENANCE.md.

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.Encryption;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;

var force = args.Contains("--force");
var outDir = args.FirstOrDefault(a => !a.StartsWith('-'))
    ?? Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../tests/fixtures/generated"));
Directory.CreateDirectory(outDir);

var keyGen = new DefaultKeyGenerator();
var netCrypto = new DefaultCryptoProvider();
var joseCrypto = new JoseCryptoProvider();

WriteFrozen(Path.Combine(outDir, "es256k-jws.json"), await GenerateEs256k());
WriteFrozen(Path.Combine(outDir, "xc20p.json"), GenerateXc20p());
return;

async Task<JsonObject> GenerateEs256k()
{
    // Fixed private scalar (any valid secp256k1 scalar; chosen arbitrarily and frozen).
    var d = Convert.FromHexString("8f2a559490d4dec22ecde1e3e1b96a8af1f7a4d2c8ea2c9e6a3b6f1f4c8a9d21");
    var pair = keyGen.FromPrivateKey(KeyType.Secp256k1, d);
    var privateJwk = JwkConversion.ToPrivateJwk(pair, kid: "es256k-2026");
    var publicJwk = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, kid: "es256k-2026");

    var payloadText = "Example of ES256K signing (RFC 8812)";
    var payload = Encoding.UTF8.GetBytes(payloadText);
    var signer = new JwsSigner(new KeyPairSigner(pair, netCrypto), kid: "es256k-2026");

    var compact = await JwsBuilder.BuildCompactAsync(payload, signer);
    var flattened = await JwsBuilder.BuildJsonAsync(payload, [signer]);

    // RFC 6979 determinism self-check: a second signing pass must be byte-identical.
    var compact2 = await JwsBuilder.BuildCompactAsync(payload, signer);
    if (!string.Equals(compact, compact2, StringComparison.Ordinal))
        throw new InvalidOperationException("ES256K signing was not deterministic; refusing to freeze.");

    var segments = compact.Split('.');
    return new JsonObject
    {
        ["description"] = "Frozen ES256K (secp256k1, RFC 8812) JWS regression vectors. Deterministic per RFC 6979.",
        ["privateKeyJwk"] = ToJwkNode(privateJwk, includePrivate: true),
        ["publicKeyJwk"] = ToJwkNode(publicJwk, includePrivate: false),
        ["payloadText"] = payloadText,
        ["payloadB64url"] = segments[1],
        ["protectedHeaderB64url"] = segments[0],
        ["jwsSigningInput"] = segments[0] + "." + segments[1],
        ["signatureB64url"] = segments[2],
        ["compactJws"] = compact,
        ["flattenedJws"] = JsonNode.Parse(flattened),
    };
}

JsonObject GenerateXc20p()
{
    // AEAD known-answer inputs (frozen; arbitrary but fixed).
    var key = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    var nonce = Convert.FromHexString("404142434445464748494a4b4c4d4e4f5051525354555657");
    var aad = Encoding.ASCII.GetBytes("eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IlhDMjBQIn0");
    var plaintext = Encoding.UTF8.GetBytes("XChaCha20-Poly1305 frozen vector for DataProofsDotnet.Jose (no external JOSE oracle carries XC20P).");
    var (ciphertext, tag) = XChaCha20Poly1305Cipher.Encrypt(key, nonce, plaintext, aad);

    // Frozen full-JWE artifact: ECDH-ES+A256KW / XC20P, one X25519 recipient with a fixed key.
    var recipientD = Convert.FromHexString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a40");
    var recipientPair = keyGen.FromPrivateKey(KeyType.X25519, recipientD);
    var recipientPrivateJwk = JwkConversion.ToPrivateJwk(recipientPair, kid: "xc20p-recipient-2026");
    var recipientPublicJwk = JwkConversion.ToPublicJwk(recipientPair.KeyType, recipientPair.PublicKey, kid: "xc20p-recipient-2026");

    var jwePlaintextText = "{\"hello\":\"xc20p\"}";
    var packedJwe = JweBuilder.BuildEcdhEsA256Kw(
        Encoding.UTF8.GetBytes(jwePlaintextText), [recipientPublicJwk], JoseAlgorithms.XC20P, joseCrypto);

    return new JsonObject
    {
        ["description"] = "Frozen XC20P (XChaCha20-Poly1305, draft-irtf-cfrg-xchacha-03) regression vectors.",
        ["aeadKat"] = new JsonObject
        {
            ["keyHex"] = Convert.ToHexStringLower(key),
            ["nonceHex"] = Convert.ToHexStringLower(nonce),
            ["aadAscii"] = Encoding.ASCII.GetString(aad),
            ["plaintextUtf8"] = Encoding.UTF8.GetString(plaintext),
            ["ciphertextHex"] = Convert.ToHexStringLower(ciphertext),
            ["tagHex"] = Convert.ToHexStringLower(tag),
        },
        ["frozenJwe"] = new JsonObject
        {
            ["recipientPrivateKeyJwk"] = ToJwkNode(recipientPrivateJwk, includePrivate: true),
            ["plaintextUtf8"] = jwePlaintextText,
            ["jweGeneralJson"] = JsonNode.Parse(packedJwe),
        },
    };
}

static JsonObject ToJwkNode(Jwk jwk, bool includePrivate)
{
    var node = new JsonObject
    {
        ["kty"] = jwk.Kty,
        ["crv"] = jwk.Crv,
        ["x"] = jwk.X,
    };
    if (jwk.Y is not null) node["y"] = jwk.Y;
    if (includePrivate && jwk.D is not null) node["d"] = jwk.D;
    if (jwk.Kid is not null) node["kid"] = jwk.Kid;
    return node;
}

void WriteFrozen(string path, JsonObject content)
{
    if (File.Exists(path) && !force)
    {
        Console.WriteLine($"SKIP (frozen): {path}");
        return;
    }
    File.WriteAllText(path, content.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n");
    Console.WriteLine($"WROTE: {path}");
}
