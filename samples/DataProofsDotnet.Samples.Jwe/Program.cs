using System.Text;
using DataProofsDotnet.Jose;
using DataProofsDotnet.Jose.Encryption;
using NetCrypto;

// ============================================================
// DataProofsDotnet Samples — JWE (JSON Web Encryption)
// ============================================================
// FR-14: JWE with NetCrypto-backed primitives only (none rolled locally).
//   * ECDH-ES+A256KW  — anonymous (no sender authentication); ephemeral-static ECDH derives a
//                       wrapping key per recipient, multi-recipient in one JWE.
//   * ECDH-1PU+A256KW — authenticated (One-Pass Unified Model, draft-madden-jose-ecdh-1pu-04):
//                       Z = Ze‖Zs binds the sender's static key; CBC-HMAC enc only.
//   * A256KW          — a pre-shared symmetric wrapping key (oct JWK).
//   * Content encryption: A256GCM, A256CBC-HS512, XC20P (XChaCha20-Poly1305).
//
// The recipient/sender key lookups are the IJweRecipientKeyResolver / IJweSenderKeyResolver
// contracts — implemented at the bottom of this file (a real app backs them with a key store).
//
// Constructed by hand (no DI package).

var keyGen = new DefaultKeyGenerator();
var crypto = new JoseCryptoProvider();

byte[] Plaintext() => Encoding.UTF8.GetBytes("""{"msg":"the eagle has landed","ts":1717000000}""");

Console.WriteLine("=== JWE — multi-recipient, ECDH-ES / ECDH-1PU / A256KW, A256GCM / CBC-HMAC / XC20P ===");

// Helper to mint an EC/OKP recipient (private + public JWK) for a given curve key type.
(Jwk Private, Jwk Public) Recipient(KeyType keyType, string kid)
{
    KeyPair pair = keyGen.Generate(keyType);
    return (JwkConversion.ToPrivateJwk(pair, kid), JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, kid));
}

// ----------------------------------------------------------- 1. ECDH-ES+A256KW, multi-recipient
Console.WriteLine("--- ECDH-ES+A256KW (anoncrypt), three X25519 recipients, XC20P ---");
var r1 = Recipient(KeyType.X25519, "did:example:bob#1");
var r2 = Recipient(KeyType.X25519, "did:example:carol#1");
var r3 = Recipient(KeyType.X25519, "did:example:dave#1");

string multi = JweBuilder.BuildEcdhEsA256Kw(
    Plaintext(),
    [r1.Public, r2.Public, r3.Public],
    JoseAlgorithms.XC20P,
    crypto,
    typ: "application/example-encrypted");

// Peek (no decryption) reveals the algorithm and the recipient kids in the envelope.
JwePeekResult peek = JweParser.PeekRecipients(multi);
Console.WriteLine($"  peek: alg={peek.Algorithm}, skid={peek.Skid ?? "(none)"}, recipients={string.Join(", ", peek.RecipientKids.Select(k => k.Split('#')[^1]))}");
Check(peek.Algorithm == JoseAlgorithms.EcdhEsA256Kw, "peek reports ECDH-ES+A256KW");
Check(peek.Skid is null, "anoncrypt has no sender kid");
Check(peek.RecipientKids.Count == 3, "the envelope carries three recipient wraps");

// Each recipient decrypts independently with only their own private key.
foreach (var (priv, pub) in new[] { r1, r2, r3 })
{
    var recipientKeys = new DictionaryRecipientResolver(priv);
    JweParseResult result = JweParser.Parse(multi, recipientKeys, senderKeys: null, crypto);
    Console.WriteLine($"  recipient {pub.Kid!.Split('#')[^1]} decrypted: alg={result.Algorithm}, enc={result.ContentEncryption}, authenticated={result.IsAuthenticated}");
    Check(result.Plaintext.AsSpan().SequenceEqual(Plaintext()), "each recipient recovers the plaintext");
    Check(result.RecipientKid == pub.Kid, "the result reports which recipient key was used");
    Check(!result.IsAuthenticated, "ECDH-ES is not sender-authenticated");
    Check(result.ContentEncryption == JoseAlgorithms.XC20P, "the content encryption is XC20P");
    Check(result.AllRecipientKids.Count == 3, "the result lists all recipient kids");
    Check(result.SenderKid.Length == 0, "anoncrypt has an empty sender kid");
}

// The recipient resolver's FindPresent narrows the envelope's kids to the ones we hold.
var holdsR2 = new DictionaryRecipientResolver(r2.Private);
IReadOnlyList<string> present = holdsR2.FindPresent(peek.RecipientKids);
Check(present.Count == 1 && present[0] == r2.Public.Kid, "FindPresent returns only the kids we hold a key for");
Console.WriteLine();

// ----------------------------------------------------------- 2. Compact ECDH-ES (single recipient)
Console.WriteLine("--- ECDH-ES+A256KW compact (single recipient), A256GCM ---");
var pr = Recipient(KeyType.P256, "did:example:bob#p256");
string compactEs = JweBuilder.BuildCompactEcdhEsA256Kw(Plaintext(), pr.Public, JoseAlgorithms.A256Gcm, crypto);
Check(compactEs.Split('.').Length == 5, "compact JWE has five dot-separated segments");
JweParseResult compactEsResult = JweParser.ParseCompact(compactEs, pr.Private, senderKeys: null, crypto);
Console.WriteLine($"  compact decrypted: enc={compactEsResult.ContentEncryption}, recipient={compactEsResult.RecipientKid.Split('#')[^1]}");
Check(compactEsResult.Plaintext.AsSpan().SequenceEqual(Plaintext()), "compact ECDH-ES round-trips");
Console.WriteLine();

// ----------------------------------------------------------- 3. ECDH-1PU+A256KW (authcrypt)
Console.WriteLine("--- ECDH-1PU+A256KW (authcrypt), A256CBC-HS512 ---");
var sender = Recipient(KeyType.X25519, "did:example:alice#1");
var recip = Recipient(KeyType.X25519, "did:example:bob#1pu");

string authcrypt = JweBuilder.BuildEcdh1PuA256Kw(
    Plaintext(),
    [recip.Public],
    sender.Private,
    sender.Public.Kid!,
    JoseAlgorithms.A256CbcHs512,
    crypto);

// Authcrypt requires BOTH a recipient key resolver and a sender key resolver at parse time.
var recipientKeys2 = new DictionaryRecipientResolver(recip.Private);
var senderKeys = new DictionarySenderResolver(sender.Public);
JweParseResult authResult = JweParser.Parse(authcrypt, recipientKeys2, senderKeys, crypto);
Console.WriteLine($"  authcrypt: alg={authResult.Algorithm}, enc={authResult.ContentEncryption}, authenticated={authResult.IsAuthenticated}, sender={authResult.SenderKid.Split('#')[^1]}");
Check(authResult.IsAuthenticated, "ECDH-1PU is sender-authenticated");
Check(authResult.SenderKid == sender.Public.Kid, "the result reports the authenticated sender kid");
Check(authResult.Plaintext.AsSpan().SequenceEqual(Plaintext()), "authcrypt round-trips");

// The protected header's apu/apv bind the sender and recipient identities — show the computers.
string apu = ApuComputer.Compute(sender.Public.Kid!);
string apv = ApvComputer.Compute([recip.Public.Kid!]);
byte[] apvBytes = ApvComputer.ComputeBytes([recip.Public.Kid!]);
Console.WriteLine($"  apu(skid)={apu[..12]}..., apv(recipients)={apv[..12]}... ({apvBytes.Length} raw bytes)");
Check(apu.Length > 0 && apv.Length > 0 && apvBytes.Length > 0, "ApuComputer/ApvComputer produce the KDF binding values");
Console.WriteLine();

// ----------------------------------------------------------- 4. A256KW (pre-shared symmetric key)
Console.WriteLine("--- A256KW (pre-shared 256-bit key) ---");
byte[] sharedKey = new byte[32];
new Random(7).NextBytes(sharedKey); // a sample shared key (use NetCrypto randomness in production)
var symJwk = new Jwk { Kty = "oct", K = Base64Url.Encode(sharedKey), Kid = "shared-2026" };

string kwJson = JweBuilder.BuildA256Kw(Plaintext(), [symJwk], JoseAlgorithms.A256Gcm, crypto, typ: "application/example");
JweParseResult kwResult = JweParser.Parse(kwJson, new DictionaryRecipientResolver(symJwk), senderKeys: null, crypto);
Check(kwResult.Plaintext.AsSpan().SequenceEqual(Plaintext()), "A256KW (JSON) round-trips");

string kwCompact = JweBuilder.BuildCompactA256Kw(Plaintext(), symJwk, JoseAlgorithms.A256CbcHs512, crypto);
JweParseResult kwCompactResult = JweParser.ParseCompact(kwCompact, symJwk, senderKeys: null, crypto);
Console.WriteLine($"  A256KW: JSON enc={kwResult.ContentEncryption}, compact enc={kwCompactResult.ContentEncryption}");
Check(kwCompactResult.Plaintext.AsSpan().SequenceEqual(Plaintext()), "A256KW (compact) round-trips");
Console.WriteLine();

// ----------------------------------------------------------- 5. Algorithm registries
Console.WriteLine("--- supported algorithm registries ---");
Console.WriteLine($"  key-management: {string.Join(", ", JoseAlgorithms.SupportedKeyManagementAlgorithms)}");
Console.WriteLine($"  content-encryption: {string.Join(", ", JoseAlgorithms.SupportedContentEncryptionAlgorithms)}");
Console.WriteLine($"  signatures: {string.Join(", ", JoseAlgorithms.SupportedSignatureAlgorithms)}");
Check(JoseAlgorithms.IsSupportedContentEncryption(JoseAlgorithms.XC20P), "XC20P is a supported content-encryption algorithm");
Check(!JoseAlgorithms.IsSupportedContentEncryption("A128GCM"), "A128GCM is not in the v1 content-encryption set");
Console.WriteLine();

// ----------------------------------------------------------- 6. The IJoseCryptoProvider primitives
// JweBuilder/JweParser compose these NetCrypto-backed primitives; an advanced caller can drive them
// directly. The curve constants (Ed25519 / X25519 / P-256 / P-384 / P-521 / secp256k1 / ES512) name
// the JOSE crv/alg identifiers the provider switches on.
Console.WriteLine("--- IJoseCryptoProvider primitives (the building blocks JweBuilder composes) ---");
IJoseCryptoProvider provider = crypto;
Console.WriteLine($"  JOSE crv/alg identifiers: {JoseAlgorithms.CrvEd25519}, {JoseAlgorithms.CrvX25519}, {JoseAlgorithms.CrvP256}, {JoseAlgorithms.CrvP384}, {JoseAlgorithms.CrvP521}, {JoseAlgorithms.CrvSecp256k1}; sig alg out of v1 scope: {JoseAlgorithms.ES512}");

// Fill: provider-sourced randomness (never System.Random) for a content-encryption key + IV.
byte[] cek = new byte[32];
byte[] iv = new byte[12];
provider.Fill(cek);
provider.Fill(iv);
Check(cek.Any(b => b != 0), "Fill produces random bytes from the provider's CSPRNG");

// AeadEncrypt / AeadDecrypt: A256GCM content encryption directly.
byte[] aadBytes = Encoding.UTF8.GetBytes("aad");
byte[] message = Encoding.UTF8.GetBytes("primitive plaintext");
var (ciphertext, tag) = provider.AeadEncrypt(JoseAlgorithms.A256Gcm, cek, iv, aadBytes, message);
byte[] decrypted = provider.AeadDecrypt(JoseAlgorithms.A256Gcm, cek, iv, aadBytes, ciphertext, tag);
Check(decrypted.AsSpan().SequenceEqual(message), "AeadEncrypt/AeadDecrypt round-trip the plaintext");

// KeyWrap / KeyUnwrap: wrap the CEK under a 256-bit KEK with A256KW.
byte[] kek = new byte[32];
provider.Fill(kek);
byte[] wrapped = provider.KeyWrap(JoseAlgorithms.A256Kw, kek, cek);
byte[] unwrapped = provider.KeyUnwrap(JoseAlgorithms.A256Kw, kek, wrapped);
Check(unwrapped.AsSpan().SequenceEqual(cek), "KeyWrap/KeyUnwrap round-trip the content-encryption key");

// DeriveSharedSecret: raw ECDH Z between an ephemeral and a static X25519 key — what ECDH-ES feeds
// into the Concat-KDF. Both sides derive the same Z.
var ephemeral = Recipient(KeyType.X25519, "eph");
var stat = Recipient(KeyType.X25519, "stat");
byte[] zSender = provider.DeriveSharedSecret(JoseAlgorithms.CrvX25519, Base64Url.Decode(ephemeral.Private.D!), Base64Url.Decode(stat.Public.X!));
byte[] zRecipient = provider.DeriveSharedSecret(JoseAlgorithms.CrvX25519, Base64Url.Decode(stat.Private.D!), Base64Url.Decode(ephemeral.Public.X!));
Console.WriteLine($"  derived ECDH shared secret ({zSender.Length} bytes); both sides agree: {zSender.AsSpan().SequenceEqual(zRecipient)}");
Check(zSender.AsSpan().SequenceEqual(zRecipient), "DeriveSharedSecret yields the same Z on both sides (ECDH)");

Console.WriteLine();
Console.WriteLine("Done! JWE example completed successfully.");
return 0;

static void Check(bool condition, string what)
{
    if (condition) return;
    Console.WriteLine($"  FAILED: {what}");
    Environment.Exit(1);
}

// ------------------------------------------------------------------------------------------
// The two resolver contracts the parser consumes. A real application backs these with a key
// store; here a dictionary keyed by kid is enough to drive the round trips.
// ------------------------------------------------------------------------------------------

internal sealed class DictionaryRecipientResolver : IJweRecipientKeyResolver
{
    private readonly Dictionary<string, Jwk> _byKid;
    public DictionaryRecipientResolver(params Jwk[] privateJwks)
        => _byKid = privateJwks.ToDictionary(j => j.Kid!, StringComparer.Ordinal);

    public Jwk? TryGet(string kid) => _byKid.GetValueOrDefault(kid);

    public IReadOnlyList<string> FindPresent(IEnumerable<string> kids)
        => kids.Where(_byKid.ContainsKey).ToArray();
}

internal sealed class DictionarySenderResolver : IJweSenderKeyResolver
{
    private readonly Dictionary<string, Jwk> _byKid;
    public DictionarySenderResolver(params Jwk[] publicJwks)
        => _byKid = publicJwks.ToDictionary(j => j.Kid!, StringComparer.Ordinal);

    public Jwk? TryGet(string skid) => _byKid.GetValueOrDefault(skid);
}
