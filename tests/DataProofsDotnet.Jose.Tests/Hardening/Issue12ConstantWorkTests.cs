using DataProofsDotnet.Jose.Encryption;
using DataProofsDotnet.Jose.Tests.Envelopes;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.Hardening;

/// <summary>
/// Regression tests for issue #12 — the recipient-key enumeration timing oracle. Before the fix,
/// <see cref="JweParser.Parse"/> fast-failed (no ECDH) when no recipient kid matched a held key,
/// so held vs. unheld was observable as a response-time difference. The fix routes the
/// non-decryptable path through a per-process decoy key so the same ECDH / key-unwrap work runs and
/// the call then fails uniformly.
///
/// The load-bearing assertion is a <see cref="CountingCryptoProvider">call-count</see> invariant
/// (CI-stable, unlike wall-clock timing): for a fixed alg/enc/epk-curve the parser performs the same
/// number of <c>DeriveSharedSecret</c> calls whether or not the holder can decrypt.
/// </summary>
public sealed class Issue12ConstantWorkTests
{
    private static readonly JoseCryptoProvider _crypto = new();

    [Fact]
    public void Unheld_recipient_performs_the_same_ecdh_work_as_a_held_recipient_es()
    {
        var bob = TestKeyMaterial.Generate(KeyType.P256, "did:example:bob#k");
        var eve = TestKeyMaterial.Generate(KeyType.P256, "did:example:eve#k");
        var packed = JweBuilder.BuildEcdhEsA256Kw(
            Encoding.UTF8.GetBytes("{}"), new[] { bob.PublicJwk }, "A256GCM", _crypto);

        var held = new CountingCryptoProvider();
        JweParser.Parse(packed, new DictionarySecretsLookup(new[] { bob.PrivateJwk }), senderKeys: null, new JoseCryptoProvider(held));

        var unheld = new CountingCryptoProvider();
        Action act = () => JweParser.Parse(packed, new DictionarySecretsLookup(new[] { eve.PrivateJwk }), senderKeys: null, new JoseCryptoProvider(unheld));

        act.Should().Throw<JoseCryptoException>();
        held.DeriveSharedSecretCalls.Should().Be(1, "ECDH-ES derives one shared secret");
        unheld.DeriveSharedSecretCalls.Should().Be(held.DeriveSharedSecretCalls,
            "the unheld path runs the decoy ECDH so its work is indistinguishable from the held path");
    }

    [Fact]
    public void Unheld_recipient_performs_the_same_ecdh_work_as_a_held_recipient_1pu()
    {
        var alice = TestKeyMaterial.Generate(KeyType.P256, "did:example:alice#k");
        var bob = TestKeyMaterial.Generate(KeyType.P256, "did:example:bob#k");
        var eve = TestKeyMaterial.Generate(KeyType.P256, "did:example:eve#k");
        var packed = JweBuilder.BuildEcdh1PuA256Kw(
            Encoding.UTF8.GetBytes("{}"), new[] { bob.PublicJwk },
            alice.PrivateJwk, alice.PublicJwk.Kid!, "A256CBC-HS512", _crypto);
        var sender = new DictionarySenderKeyLookup(new[] { alice.PublicJwk });

        var held = new CountingCryptoProvider();
        JweParser.Parse(packed, new DictionarySecretsLookup(new[] { bob.PrivateJwk }), sender, new JoseCryptoProvider(held));

        var unheld = new CountingCryptoProvider();
        Action act = () => JweParser.Parse(packed, new DictionarySecretsLookup(new[] { eve.PrivateJwk }), sender, new JoseCryptoProvider(unheld));

        act.Should().Throw<JoseCryptoException>();
        held.DeriveSharedSecretCalls.Should().Be(2, "ECDH-1PU derives Ze and Zs");
        unheld.DeriveSharedSecretCalls.Should().Be(held.DeriveSharedSecretCalls,
            "the unheld 1PU path runs both decoy ECDH derivations");
    }

    [Fact]
    public void Unheld_recipient_no_longer_fast_fails_with_the_no_matching_kid_message()
    {
        var bob = TestKeyMaterial.Generate(KeyType.X25519, "did:example:bob#x");
        var eve = TestKeyMaterial.Generate(KeyType.X25519, "did:example:eve#x");
        var packed = JweBuilder.BuildEcdhEsA256Kw(
            Encoding.UTF8.GetBytes("{}"), new[] { bob.PublicJwk }, "A256GCM", _crypto);

        Action act = () => JweParser.Parse(packed, new DictionarySecretsLookup(new[] { eve.PrivateJwk }), senderKeys: null, _crypto);

        // The early possession-revealing throw is gone; failure is now the uniform decrypt message.
        act.Should().Throw<JoseCryptoException>()
            .Which.Message.Should().NotContain("matches a held private key");
    }

    [Fact]
    public void Held_and_unheld_throw_the_same_exception_for_a_length_corrupted_envelope()
    {
        // Adversarial review (issue #12): a captured envelope whose iv/tag *length* is corrupted lets
        // a HELD key reach the AEAD stage (its real key-unwrap succeeds) while an UNHELD key dies at
        // unwrap. If the two stages threw different exception types/messages, that would re-leak
        // possession through the exception channel even though the timing is now equal. They must be
        // identical.
        var bob = TestKeyMaterial.Generate(KeyType.P256, "did:example:bob#k");
        var eve = TestKeyMaterial.Generate(KeyType.P256, "did:example:eve#k");
        var packed = JweBuilder.BuildEcdhEsA256Kw(
            Encoding.UTF8.GetBytes("{\"v\":1}"), new[] { bob.PublicJwk }, "A256GCM", _crypto);
        // Truncate the 'iv' to an invalid length, leaving 'encrypted_key' intact so a held key's
        // unwrap still succeeds and reaches the AEAD length check.
        var tampered = TruncateIv(packed);

        var heldEx = Record.Exception(() =>
            JweParser.Parse(tampered, new DictionarySecretsLookup(new[] { bob.PrivateJwk }), senderKeys: null, _crypto));
        var unheldEx = Record.Exception(() =>
            JweParser.Parse(tampered, new DictionarySecretsLookup(new[] { eve.PrivateJwk }), senderKeys: null, _crypto));

        heldEx.Should().BeOfType<JoseCryptoException>();
        unheldEx.Should().BeOfType<JoseCryptoException>();
        heldEx!.Message.Should().Be(unheldEx!.Message);
    }

    [Fact]
    public void Held_public_only_key_takes_the_decoy_path_like_an_unheld_key()
    {
        // A curve-matching but private-keyless (public-only) JWK registered under the recipient kid
        // cannot decrypt; it must fail with the same uniform exception as a wholly-unheld key, not a
        // distinct "missing 'd'" error.
        var bob = TestKeyMaterial.Generate(KeyType.P256, "did:example:bob#k");
        var eve = TestKeyMaterial.Generate(KeyType.P256, "did:example:eve#k");
        var packed = JweBuilder.BuildEcdhEsA256Kw(Encoding.UTF8.GetBytes("{}"), new[] { bob.PublicJwk }, "A256GCM", _crypto);

        var publicOnly = Record.Exception(() =>
            JweParser.Parse(packed, new DictionarySecretsLookup(new[] { bob.PublicJwk }), senderKeys: null, _crypto));
        var unheld = Record.Exception(() =>
            JweParser.Parse(packed, new DictionarySecretsLookup(new[] { eve.PrivateJwk }), senderKeys: null, _crypto));

        publicOnly.Should().BeOfType<JoseCryptoException>();
        publicOnly!.Message.Should().Be(unheld!.Message);
    }

    private static string TruncateIv(string packedGeneralJson)
    {
        using var doc = System.Text.Json.JsonDocument.Parse(packedGeneralJson);
        var root = doc.RootElement;
        var ivBytes = Base64Url.Decode(root.GetProperty("iv").GetString()!);
        var shortIv = Base64Url.Encode(ivBytes.AsSpan(0, ivBytes.Length - 1)); // wrong length for any enc
        var rebuilt = new System.Text.Json.Nodes.JsonObject();
        foreach (var prop in root.EnumerateObject())
            rebuilt[prop.Name] = prop.Name == "iv" ? shortIv : System.Text.Json.Nodes.JsonNode.Parse(prop.Value.GetRawText());
        return rebuilt.ToJsonString();
    }

    [Fact]
    public void Held_key_on_the_wrong_curve_takes_the_decoy_path_not_a_fast_curve_mismatch_throw()
    {
        // Envelope addressed to a P-256 recipient. The holder has a key under that SAME kid but on
        // X25519 — it cannot decrypt. Before the fix this fast-threw at the recipient/epk curve check
        // (before any ECDH), which is faster than a real decrypt and so still leaked possession.
        var bobP256 = TestKeyMaterial.Generate(KeyType.P256, "did:example:bob#k");
        var wrongCurve = TestKeyMaterial.Generate(KeyType.X25519, "did:example:bob#k");
        var packed = JweBuilder.BuildEcdhEsA256Kw(
            Encoding.UTF8.GetBytes("{}"), new[] { bobP256.PublicJwk }, "A256GCM", _crypto);

        var counter = new CountingCryptoProvider();
        Action act = () => JweParser.Parse(packed, new DictionarySecretsLookup(new[] { wrongCurve.PrivateJwk }), senderKeys: null, new JoseCryptoProvider(counter));

        act.Should().Throw<JoseCryptoException>()
            .Which.Message.Should().NotContain("does not match JWE 'epk' curve");
        counter.DeriveSharedSecretCalls.Should().Be(1,
            "the decoy ECDH on the epk curve runs instead of a fast curve-mismatch throw");
    }

    [Fact]
    public void Decoy_runs_on_the_envelope_epk_curve_even_when_the_holder_holds_other_curves()
    {
        var targetP384 = TestKeyMaterial.Generate(KeyType.P384, "did:example:target#k"); // held by nobody
        var heldP256 = TestKeyMaterial.Generate(KeyType.P256, "did:example:me#p256");
        var heldX = TestKeyMaterial.Generate(KeyType.X25519, "did:example:me#x");
        var packed = JweBuilder.BuildEcdhEsA256Kw(
            Encoding.UTF8.GetBytes("{}"), new[] { targetP384.PublicJwk }, "A256GCM", _crypto);

        var counter = new CountingCryptoProvider();
        Action act = () => JweParser.Parse(packed,
            new DictionarySecretsLookup(new[] { heldP256.PrivateJwk, heldX.PrivateJwk }), senderKeys: null, new JoseCryptoProvider(counter));

        act.Should().Throw<JoseCryptoException>();
        counter.DeriveSharedSecretCalls.Should().Be(1,
            "a decoy ECDH runs on the P-384 epk curve taken from the envelope, not from a held key");
    }

    [Fact]
    public void Holder_as_a_non_first_recipient_still_decrypts()
    {
        var alice = TestKeyMaterial.Generate(KeyType.X25519, "did:example:alice#x");
        var bob = TestKeyMaterial.Generate(KeyType.X25519, "did:example:bob#x");
        var carol = TestKeyMaterial.Generate(KeyType.X25519, "did:example:carol#x");
        var plaintext = Encoding.UTF8.GetBytes("{\"hello\":\"world\"}");
        var packed = JweBuilder.BuildEcdhEsA256Kw(
            plaintext, new[] { alice.PublicJwk, bob.PublicJwk, carol.PublicJwk }, "A256GCM", _crypto);

        // The full-list scan must still find a held key that is not the first recipient.
        var result = JweParser.Parse(packed, new DictionarySecretsLookup(new[] { carol.PrivateJwk }), senderKeys: null, _crypto);

        result.RecipientKid.Should().Be(carol.PublicJwk.Kid);
        Encoding.UTF8.GetString(result.Plaintext).Should().Be(Encoding.UTF8.GetString(plaintext));
    }

    /// <summary>An <see cref="ICryptoProvider"/> that counts raw-ECDH calls; everything else delegates.</summary>
    private sealed class CountingCryptoProvider : ICryptoProvider
    {
        private readonly ICryptoProvider _inner = new DefaultCryptoProvider();

        public int DeriveSharedSecretCalls { get; private set; }

        public byte[] DeriveSharedSecret(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
        {
            DeriveSharedSecretCalls++;
            return _inner.DeriveSharedSecret(keyType, privateKey, publicKey);
        }

        public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data)
            => _inner.Sign(keyType, privateKey, data);
        public byte[] Sign(KeyType keyType, ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> data, EcdsaSignatureFormat format)
            => _inner.Sign(keyType, privateKey, data, format);
        public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
            => _inner.Verify(keyType, publicKey, data, signature);
        public bool Verify(KeyType keyType, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, EcdsaSignatureFormat format)
            => _inner.Verify(keyType, publicKey, data, signature, format);
        public byte[] KeyAgreement(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey)
            => _inner.KeyAgreement(privateKey, publicKey);
    }
}
