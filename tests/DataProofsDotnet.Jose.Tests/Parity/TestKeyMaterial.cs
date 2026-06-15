using DataProofsDotnet.Jose.Encryption;
using DataProofsDotnet.Jose.Signing;
using NetCrypto;

namespace DataProofsDotnet.Jose.Tests.Envelopes;

/// <summary>
/// Round-trip test material: generates fresh keypairs per curve and packs them into the
/// JOSE <see cref="Jwk"/> shape the envelope layer expects. Also implements the two
/// resolver contracts so tests can drive <c>JweParser</c> without standing up a resolver.
/// Rewired from didcomm-dotnet's net-did keygen to NetCrypto (rename-adapted from the port); gains a
/// <see cref="Signer"/> because the dataproofs <c>JwsBuilder</c> signs through NetCrypto
/// <c>ISigner</c> instead of consuming a private JWK's 'd' (AC-8).
/// </summary>
internal sealed class TestKeyMaterial
{
    private static readonly IKeyGenerator _generator = new DefaultKeyGenerator();
    private static readonly NetCrypto.ICryptoProvider _netCrypto = new DefaultCryptoProvider();

    private readonly KeyPair _pair;

    public Jwk PrivateJwk { get; }
    public Jwk PublicJwk { get; }

    /// <summary>A NetCrypto-backed JWS signer over this key (signing-capable key types only).</summary>
    public JwsSigner Signer => new(new KeyPairSigner(_pair, _netCrypto), PrivateJwk.Kid);

    private TestKeyMaterial(KeyPair pair, Jwk privateJwk, Jwk publicJwk)
    {
        _pair = pair;
        PrivateJwk = privateJwk;
        PublicJwk = publicJwk;
    }

    public static TestKeyMaterial Generate(KeyType keyType, string kid)
    {
        var pair = _generator.Generate(keyType);
        var priv = JwkConversion.ToPrivateJwk(pair, kid);
        var pub = JwkConversion.ToPublicJwk(pair.KeyType, pair.PublicKey, kid);
        return new TestKeyMaterial(pair, priv, pub);
    }
}

internal sealed class DictionarySecretsLookup : IJweRecipientKeyResolver
{
    private readonly Dictionary<string, Jwk> _byKid;

    public DictionarySecretsLookup(IEnumerable<Jwk> privateJwks)
    {
        _byKid = privateJwks.ToDictionary(j => j.Kid!, StringComparer.Ordinal);
    }

    public Jwk? TryGet(string kid) => _byKid.GetValueOrDefault(kid);

    public IReadOnlyList<string> FindPresent(IEnumerable<string> kids)
        => kids.Where(k => _byKid.ContainsKey(k)).ToArray();
}

internal sealed class DictionarySenderKeyLookup : IJweSenderKeyResolver
{
    private readonly Dictionary<string, Jwk> _byKid;

    public DictionarySenderKeyLookup(IEnumerable<Jwk> publicJwks)
    {
        _byKid = publicJwks.ToDictionary(j => j.Kid!, StringComparer.Ordinal);
    }

    public Jwk? TryGet(string skid) => _byKid.GetValueOrDefault(skid);
}
