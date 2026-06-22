using System.Reflection;
using DataProofsDotnet.Jose.Encryption;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Envelopes.Encryption;

/// <summary>
/// Tests for the additive async <see cref="IEcdhKey"/> seam (issue #13): an opaque ECDH key drives
/// full authcrypt (ECDH-1PU) and anoncrypt (ECDH-ES) round-trips without exposing its private
/// scalar, the async KDF cores reproduce the (vector-frozen) sync cores byte-for-byte, and
/// <see cref="RawEcdhKey"/> is wire-compatible with the existing synchronous API. The async path
/// also carries the issue #12 constant-work decoy defense.
/// </summary>
public sealed class AsyncEcdhKeyRoundTripTests
{
    private static readonly JoseCryptoProvider _crypto = new();
    private static readonly NetCrypto.ICryptoProvider _netCrypto = new DefaultCryptoProvider();

    [Theory]
    [InlineData(KeyType.X25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    public async Task Opaque_keys_drive_a_full_authcrypt_round_trip(KeyType keyType)
    {
        var alice = TestKeyMaterial.Generate(keyType, "did:example:alice#1");
        var bob = TestKeyMaterial.Generate(keyType, "did:example:bob#1");
        var plaintext = Encoding.UTF8.GetBytes("{\"msg\":\"opaque authcrypt\"}");

        // Sender static key is opaque on the SEND side; ephemeral stays raw and in-package.
        var senderKey = new OpaqueEcdhKey(alice.PrivateJwk, _crypto);
        var packed = await JweBuilder.BuildEcdh1PuA256KwAsync(
            plaintext, new[] { bob.PublicJwk }, senderKey, alice.PublicJwk.Kid!, "A256CBC-HS512", _crypto);

        // Recipient key is opaque on the RECEIVE side.
        var recipientKey = new OpaqueEcdhKey(bob.PrivateJwk, _crypto);
        var senderLookup = new DictionarySenderKeyLookup(new[] { alice.PublicJwk });
        var result = await JweParser.ParseAsync(packed, recipientKey, senderLookup, _crypto);

        result.IsAuthenticated.Should().BeTrue();
        result.Algorithm.Should().Be("ECDH-1PU+A256KW");
        result.SenderKid.Should().Be(alice.PublicJwk.Kid);
        result.RecipientKid.Should().Be(bob.PublicJwk.Kid);
        Encoding.UTF8.GetString(result.Plaintext).Should().Be(Encoding.UTF8.GetString(plaintext));

        senderKey.DeriveCalls.Should().BeGreaterThan(0, "the sender's static ECDH is delegated to the opaque key");
        recipientKey.DeriveCalls.Should().Be(2, "1PU receive derives Ze and Zs through the opaque key");
    }

    [Theory]
    [InlineData(KeyType.X25519)]
    [InlineData(KeyType.P256)]
    [InlineData(KeyType.P384)]
    [InlineData(KeyType.P521)]
    public async Task Opaque_recipient_drives_a_full_anoncrypt_round_trip(KeyType keyType)
    {
        var bob = TestKeyMaterial.Generate(keyType, "did:example:bob#1");
        var plaintext = Encoding.UTF8.GetBytes("{\"msg\":\"opaque anoncrypt\"}");
        var packed = JweBuilder.BuildEcdhEsA256Kw(plaintext, new[] { bob.PublicJwk }, "A256GCM", _crypto);

        var recipientKey = new OpaqueEcdhKey(bob.PrivateJwk, _crypto);
        var result = await JweParser.ParseAsync(packed, recipientKey, senderKeys: null, _crypto);

        result.IsAuthenticated.Should().BeFalse();
        result.Algorithm.Should().Be("ECDH-ES+A256KW");
        Encoding.UTF8.GetString(result.Plaintext).Should().Be(Encoding.UTF8.GetString(plaintext));
        recipientKey.DeriveCalls.Should().Be(1, "ECDH-ES receive derives a single shared secret");
    }

    [Fact]
    public async Task Async_build_output_decrypts_with_the_synchronous_parser_proving_wire_identity()
    {
        var alice = TestKeyMaterial.Generate(KeyType.X25519, "did:example:alice#1");
        var bob = TestKeyMaterial.Generate(KeyType.X25519, "did:example:bob#1");
        var plaintext = Encoding.UTF8.GetBytes("{\"wire\":\"identical\"}");

        var packed = await JweBuilder.BuildEcdh1PuA256KwAsync(
            plaintext, new[] { bob.PublicJwk }, new OpaqueEcdhKey(alice.PrivateJwk, _crypto),
            alice.PublicJwk.Kid!, "A256CBC-HS512", _crypto);

        var result = JweParser.Parse(
            packed,
            new DictionarySecretsLookup(new[] { bob.PrivateJwk }),
            new DictionarySenderKeyLookup(new[] { alice.PublicJwk }),
            _crypto);

        result.IsAuthenticated.Should().BeTrue();
        Encoding.UTF8.GetString(result.Plaintext).Should().Be(Encoding.UTF8.GetString(plaintext));
    }

    [Fact]
    public async Task RawEcdhKey_drives_an_anoncrypt_round_trip()
    {
        var bob = TestKeyMaterial.Generate(KeyType.X25519, "did:example:bob#1");
        var plaintext = Encoding.UTF8.GetBytes("{\"raw\":true}");
        var packed = JweBuilder.BuildEcdhEsA256Kw(plaintext, new[] { bob.PublicJwk }, "A256GCM", _crypto);

        var rawKey = new RawEcdhKey(bob.PrivateJwk.Crv!, Base64Url.Decode(bob.PrivateJwk.D!), _crypto);
        var result = await JweParser.ParseAsync(packed, rawKey, senderKeys: null, _crypto);

        Encoding.UTF8.GetString(result.Plaintext).Should().Be(Encoding.UTF8.GetString(plaintext));
    }

    [Fact]
    public async Task ParseCompactAsync_round_trips_anoncrypt()
    {
        var bob = TestKeyMaterial.Generate(KeyType.P256, "did:example:bob#1");
        var plaintext = Encoding.UTF8.GetBytes("{\"compact\":true}");
        var packed = JweBuilder.BuildCompactEcdhEsA256Kw(plaintext, bob.PublicJwk, "A256GCM", _crypto);

        var result = await JweParser.ParseCompactAsync(packed, new OpaqueEcdhKey(bob.PrivateJwk, _crypto), senderKeys: null, _crypto);

        Encoding.UTF8.GetString(result.Plaintext).Should().Be(Encoding.UTF8.GetString(plaintext));
    }

    [Fact]
    public async Task ParseAsync_decrypts_a_multi_recipient_same_curve_envelope_for_the_matching_recipient()
    {
        var alice = TestKeyMaterial.Generate(KeyType.X25519, "did:example:alice#1");
        var bob = TestKeyMaterial.Generate(KeyType.X25519, "did:example:bob#1");
        var plaintext = Encoding.UTF8.GetBytes("{\"to\":\"both\"}");
        var packed = JweBuilder.BuildEcdhEsA256Kw(plaintext, new[] { alice.PublicJwk, bob.PublicJwk }, "A256GCM", _crypto);

        var result = await JweParser.ParseAsync(packed, new OpaqueEcdhKey(bob.PrivateJwk, _crypto), senderKeys: null, _crypto);

        result.RecipientKid.Should().Be(bob.PublicJwk.Kid);
        Encoding.UTF8.GetString(result.Plaintext).Should().Be(Encoding.UTF8.GetString(plaintext));
    }

    [Fact]
    public async Task ParseAsync_with_a_wrong_curve_key_uses_the_decoy_and_never_invokes_the_real_key()
    {
        // Envelope is ECDH-ES on P-256; the supplied opaque key is X25519 — it cannot decrypt.
        var bobP256 = TestKeyMaterial.Generate(KeyType.P256, "did:example:bob#1");
        var packed = JweBuilder.BuildEcdhEsA256Kw(Encoding.UTF8.GetBytes("{}"), new[] { bobP256.PublicJwk }, "A256GCM", _crypto);
        var wrongCurve = new OpaqueEcdhKey(TestKeyMaterial.Generate(KeyType.X25519, "did:example:eve#1").PrivateJwk, _crypto);

        Func<Task> act = async () => await JweParser.ParseAsync(packed, wrongCurve, senderKeys: null, _crypto);

        await act.Should().ThrowAsync<JoseCryptoException>();
        wrongCurve.DeriveCalls.Should().Be(0, "the wrong-curve key is replaced by a decoy ECDH; the real opaque key is never used");
    }

    [Fact]
    public async Task RawEcdhKey_async_core_matches_the_sync_core_byte_for_byte_es()
    {
        var gen = new DefaultKeyGenerator();
        var recipient = gen.Generate(KeyType.X25519);
        var ephemeral = gen.Generate(KeyType.X25519);
        var algId = Encoding.ASCII.GetBytes(JoseAlgorithms.EcdhEsA256Kw);
        var apv = Encoding.ASCII.GetBytes("apv-data");

        var sync = EcdhEsKdf.DeriveKeyForReceiver(
            _netCrypto, KeyType.X25519, recipient.PrivateKey, ephemeral.PublicKey, algId, apv, keyDataLen: 32);
        var async = await EcdhEsKdf.DeriveKeyForReceiverAsync(
            new RawEcdhKey("X25519", recipient.PrivateKey, _crypto), ephemeral.PublicKey, algId,
            ReadOnlyMemory<byte>.Empty, apv, keyDataLen: 32);

        async.Should().Equal(sync);
    }

    [Fact]
    public async Task RawEcdhKey_async_core_matches_the_sync_core_byte_for_byte_1pu()
    {
        var gen = new DefaultKeyGenerator();
        var recipient = gen.Generate(KeyType.X25519);
        var ephemeral = gen.Generate(KeyType.X25519);
        var sender = gen.Generate(KeyType.X25519);
        var algId = Encoding.ASCII.GetBytes(JoseAlgorithms.Ecdh1PuA256Kw);
        var apu = Encoding.UTF8.GetBytes("did:example:alice#1");
        var apv = Encoding.ASCII.GetBytes("apv-data");
        var tag = Enumerable.Repeat((byte)0xAA, 16).ToArray();

        var sync = Ecdh1PuKdf.DeriveKeyForReceiver(
            _netCrypto, KeyType.X25519, recipient.PrivateKey, ephemeral.PublicKey, sender.PublicKey,
            algId, apu, apv, tag, keyDataLen: 32);
        var async = await Ecdh1PuKdf.DeriveKeyForReceiverAsync(
            new RawEcdhKey("X25519", recipient.PrivateKey, _crypto), ephemeral.PublicKey, sender.PublicKey,
            algId, apu, apv, tag, keyDataLen: 32);

        async.Should().Equal(sync);
    }

    [Fact]
    public void IEcdhKey_surface_exposes_no_private_scalar()
    {
        // The opaqueness guarantee is structural: the seam exposes only a self-describing curve and a
        // derive callback. There is no member through which the parser could read the private scalar.
        typeof(IEcdhKey).GetProperties().Select(p => p.Name).Should().Equal("Crv");
        typeof(IEcdhKey).GetMethods().Where(m => !m.IsSpecialName).Select(m => m.Name).Should().Equal("DeriveAsync");

        typeof(RawEcdhKey).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name).Should().Equal("Crv");
        typeof(RawEcdhKey).GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m => !m.IsSpecialName).Select(m => m.Name).Should().Equal("DeriveAsync");
    }

    /// <summary>
    /// A stand-in for an opaque (HSM/keystore-backed) ECDH key: it agrees correctly via
    /// <see cref="DeriveAsync"/> but exposes <b>no</b> member returning the private scalar — modelling
    /// "private keys never leave the keystore". The private bytes live in a field reachable only from
    /// inside <see cref="DeriveAsync"/>; <see cref="DeriveCalls"/> proves the parser used the seam.
    /// </summary>
    private sealed class OpaqueEcdhKey : IEcdhKey
    {
        private readonly byte[] _privateKey;
        private readonly JoseCryptoProvider _provider;

        public OpaqueEcdhKey(Jwk privateJwk, JoseCryptoProvider provider)
        {
            Crv = privateJwk.Crv ?? throw new InvalidOperationException("private JWK is missing 'crv'.");
            _privateKey = Base64Url.Decode(privateJwk.D ?? throw new InvalidOperationException("private JWK is missing 'd'."));
            _provider = provider;
        }

        public string Crv { get; }

        public int DeriveCalls { get; private set; }

        public ValueTask<byte[]> DeriveAsync(ReadOnlyMemory<byte> peerPublicKey, CancellationToken ct = default)
        {
            DeriveCalls++;
            return new ValueTask<byte[]>(_provider.DeriveSharedSecret(Crv, _privateKey, peerPublicKey.Span));
        }
    }
}
