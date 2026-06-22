using NetCrypto;

namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// Per-process decoy private keys used by <see cref="JweParser"/>'s constant-work decrypt defense
/// (issue #12). When a JWE addresses a recipient the holder cannot decrypt — the kid is not held,
/// or it is held but on a curve that does not match the envelope's key-agreement curve — the parser
/// substitutes one of these decoys so the decrypt performs the same ECDH / key-unwrap work and then
/// fails uniformly, instead of fast-failing before any cryptography. That removes the response-time
/// difference an attacker would otherwise use to enumerate which recipient private keys the holder
/// possesses.
/// </summary>
/// <remarks>
/// <para>
/// The decoys are <b>real</b> NetCrypto-generated keys (not faked scalars), so the private-key
/// decode and the ECDH run at full, curve-matching cost. They are generated <b>once per process and
/// cached</b>: a freshly generated decoy per call would add a key-generation cost only to the
/// non-decryptable path — a cost the genuinely-held path never pays — which would re-introduce the
/// very timing oracle this defends against. The cached keys are throwaway and never correspond to a
/// real recipient, so leaving them resident for the process lifetime carries no exposure.
/// </para>
/// <para>
/// Thread-safe: each <see cref="Lazy{T}"/> publishes a single instance under
/// <see cref="LazyThreadSafetyMode.ExecutionAndPublication"/>, matching the documented
/// singleton-safety of <see cref="JoseCryptoProvider"/>.
/// </para>
/// </remarks>
internal static class DecoyKeyCache
{
    private static readonly IKeyGenerator _generator = new DefaultKeyGenerator();

    private static readonly Lazy<Jwk> _x25519 = new(() => Generate(KeyType.X25519));
    private static readonly Lazy<Jwk> _p256 = new(() => Generate(KeyType.P256));
    private static readonly Lazy<Jwk> _p384 = new(() => Generate(KeyType.P384));
    private static readonly Lazy<Jwk> _p521 = new(() => Generate(KeyType.P521));

    // A fixed 32-byte oct KEK for the standalone A256KW constant-work path. Its value is never
    // revealed and only needs to make the AES-KW unwrap of an attacker's ciphertext fail, so an
    // all-zero key is sufficient (and avoids any randomness dependency).
    private static readonly Lazy<Jwk> _octKek = new(() =>
        new Jwk { Kty = "oct", K = Base64Url.Encode(new byte[32]), Kid = "decoy" });

    /// <summary>
    /// The decoy private JWK for an ECDH key-agreement curve. <paramref name="workCurve"/> must be a
    /// supported agreement curve (X25519, P-256, P-384, P-521); callers gate on
    /// <see cref="IsSupportedAgreementCurve"/> first.
    /// </summary>
    public static Jwk ForCurve(string workCurve) => workCurve switch
    {
        JoseAlgorithms.CrvX25519 => _x25519.Value,
        JoseAlgorithms.CrvP256 => _p256.Value,
        JoseAlgorithms.CrvP384 => _p384.Value,
        JoseAlgorithms.CrvP521 => _p521.Value,
        _ => throw new NotSupportedException($"No decoy key for curve '{workCurve}'."),
    };

    /// <summary>The decoy symmetric KEK for the standalone <c>A256KW</c> path.</summary>
    public static Jwk OctKek() => _octKek.Value;

    /// <summary>True when <paramref name="crv"/> is a supported ECDH key-agreement curve.</summary>
    public static bool IsSupportedAgreementCurve(string? crv) =>
        crv is JoseAlgorithms.CrvX25519 or JoseAlgorithms.CrvP256 or JoseAlgorithms.CrvP384 or JoseAlgorithms.CrvP521;

    private static Jwk Generate(KeyType keyType)
    {
        var pair = _generator.Generate(keyType);
        return JwkConversion.ToPrivateJwk(pair, kid: "decoy");
    }
}
