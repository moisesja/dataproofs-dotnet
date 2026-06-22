using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DataProofsDotnet.Jose.Encryption;

/// <summary>
/// Builds JWE envelopes (PRD FR-14): General JSON serialization (multi-recipient) and compact
/// serialization (single recipient). Key management: <c>ECDH-ES+A256KW</c>,
/// <c>ECDH-1PU+A256KW</c> (draft-madden-jose-ecdh-1pu-04), and standalone <c>A256KW</c>;
/// content encryption: <c>A256CBC-HS512</c>, <c>A256GCM</c>, <c>XC20P</c>. Every primitive is
/// NetCrypto-backed; this layer owns only the JOSE composition.
/// </summary>
/// <remarks>
/// Ported from didcomm-dotnet <c>DidComm.Jose.Encryption.JweBuilder</c> (PRD §1.4 item 2),
/// preserving the load-bearing mechanics: single-curve recipient rule, decode-sender-key-before-
/// ephemeral ordering, the DIDComm-compatible <c>apv</c>/<c>apu</c> recipes on the JSON ECDH
/// paths, encrypt-then-derive-KEK so the AEAD tag binds into the 1PU KDF, AAD =
/// <c>ASCII(protectedB64u)</c>, and the zeroization <c>finally</c> blocks. Standalone
/// <c>A256KW</c> and the compact serialization are new work the porting source lacked.
/// </remarks>
public static class JweBuilder
{
    /// <summary>
    /// Build a multi-recipient General-JSON JWE with anonymous-sender key agreement
    /// (<c>ECDH-ES+A256KW</c>).
    /// </summary>
    /// <param name="plaintext">Bytes to encrypt.</param>
    /// <param name="recipients">Recipient public JWKs; ALL must share the same curve, each with a <c>kid</c>.</param>
    /// <param name="contentEncryption">JWE <c>enc</c> (<c>A256CBC-HS512</c>, <c>A256GCM</c>, or <c>XC20P</c>).</param>
    /// <param name="cryptoProvider">The JOSE crypto provider (NetCrypto-backed).</param>
    /// <param name="typ">Optional <c>typ</c> protected-header value.</param>
    public static string BuildEcdhEsA256Kw(
        ReadOnlySpan<byte> plaintext,
        IReadOnlyList<Jwk> recipients,
        string contentEncryption,
        JoseCryptoProvider cryptoProvider,
        string? typ = null)
    {
        ArgumentNullException.ThrowIfNull(recipients);
        ArgumentNullException.ThrowIfNull(cryptoProvider);
        if (recipients.Count == 0)
            throw new ArgumentException("At least one recipient is required.", nameof(recipients));

        EnsureRecipientsShareCurve(recipients, out var curve);

        var ephemeral = EphemeralKeyPair.Generate(curve);
        try
        {
            var apvBytes = ApvComputer.ComputeBytes(recipients.Select(r => r.Kid ?? throw new MalformedJoseException("Recipient JWK is missing 'kid'.")));
            var apvB64u = Base64Url.Encode(apvBytes);

            var header = new JweProtectedHeader
            {
                Typ = typ,
                Alg = JoseAlgorithms.EcdhEsA256Kw,
                Enc = contentEncryption,
                Epk = ephemeral.ToPublicEpkJwk(),
                Apv = apvB64u,
            };

            return EncryptAndAssemble(
                plaintext, header, contentEncryption, cryptoProvider,
                wrapPerRecipient: (recipient, _) => EcdhEsKdf.DeriveKey(
                    cryptoProvider.UnderlyingProvider,
                    KeyTypeMapper.FromCurveForKeyAgreement(curve),
                    ephemeral.PrivateKey,
                    ExtractRecipientPublicKey(recipient),
                    Encoding.ASCII.GetBytes(header.Alg),
                    apvBytes,
                    keyDataLen: 32),
                recipients);
        }
        finally
        {
            ephemeral.Clear();
        }
    }

    /// <summary>
    /// Build a multi-recipient General-JSON JWE with authenticated-sender key agreement
    /// (<c>ECDH-1PU+A256KW</c>, draft-madden-jose-ecdh-1pu-04). The key-wrap mode is pinned to
    /// <c>A256CBC-HS512</c> content encryption — draft-04 §2.1 restricts non-direct 1PU to the
    /// key-committing CBC-HMAC family (the didcomm FR-ENC-09 rule, deliberately retained).
    /// </summary>
    /// <param name="plaintext">Bytes to encrypt.</param>
    /// <param name="recipients">Recipient public JWKs; ALL must share the sender's curve, each with a <c>kid</c>.</param>
    /// <param name="senderPrivateJwk">Sender's static private JWK (matches <paramref name="skid"/>).</param>
    /// <param name="skid">Sender key identifier written to the protected header.</param>
    /// <param name="contentEncryption">JWE <c>enc</c> — MUST be <c>A256CBC-HS512</c>.</param>
    /// <param name="cryptoProvider">The JOSE crypto provider.</param>
    /// <param name="typ">Optional <c>typ</c> protected-header value.</param>
    /// <exception cref="ArgumentException">When <paramref name="contentEncryption"/> is not <c>A256CBC-HS512</c>.</exception>
    public static string BuildEcdh1PuA256Kw(
        ReadOnlySpan<byte> plaintext,
        IReadOnlyList<Jwk> recipients,
        Jwk senderPrivateJwk,
        string skid,
        string contentEncryption,
        JoseCryptoProvider cryptoProvider,
        string? typ = null)
    {
        ArgumentNullException.ThrowIfNull(recipients);
        ArgumentNullException.ThrowIfNull(senderPrivateJwk);
        ArgumentException.ThrowIfNullOrEmpty(skid);
        ArgumentNullException.ThrowIfNull(cryptoProvider);
        if (recipients.Count == 0)
            throw new ArgumentException("At least one recipient is required.", nameof(recipients));
        if (contentEncryption != JoseAlgorithms.A256CbcHs512)
            throw new ArgumentException(
                $"ECDH-1PU key wrap MUST use A256CBC-HS512 content encryption (draft-madden-04 §2.1 / didcomm FR-ENC-09). Got '{contentEncryption}'.",
                nameof(contentEncryption));
        if (string.IsNullOrEmpty(senderPrivateJwk.Crv) || string.IsNullOrEmpty(senderPrivateJwk.D))
            throw new MalformedJoseException("Sender JWK is missing 'crv' or 'd'.");

        EnsureRecipientsShareCurve(recipients, out var curve);
        if (!string.Equals(curve, senderPrivateJwk.Crv, StringComparison.Ordinal))
            throw new ArgumentException(
                $"ECDH-1PU requires the sender key and all recipients on the same curve. Sender='{senderPrivateJwk.Crv}', recipients='{curve}'.",
                nameof(senderPrivateJwk));

        // Decode the sender's static private key BEFORE generating the ephemeral key, so a malformed
        // 'd' throws with no freshly-generated ephemeral secret left un-zeroed (the finally below only
        // runs once the try is entered).
        var senderPrivBytes = Base64Url.Decode(senderPrivateJwk.D!);
        var ephemeral = EphemeralKeyPair.Generate(curve);
        try
        {
            var apvBytes = ApvComputer.ComputeBytes(recipients.Select(r => r.Kid ?? throw new MalformedJoseException("Recipient JWK is missing 'kid'.")));
            var apvB64u = Base64Url.Encode(apvBytes);
            var apuB64u = ApuComputer.Compute(skid);
            // 1PU draft-04 §2.3: PartyUInfo passed to ConcatKDF is the base64url-DECODED apu,
            // i.e. the raw UTF-8 bytes of the skid string — NOT the ASCII bytes of the b64u form.
            var apuBytes = Encoding.UTF8.GetBytes(skid);

            var header = new JweProtectedHeader
            {
                Typ = typ,
                Alg = JoseAlgorithms.Ecdh1PuA256Kw,
                Enc = contentEncryption,
                Epk = ephemeral.ToPublicEpkJwk(),
                Apv = apvB64u,
                Apu = apuB64u,
                Skid = skid,
            };

            return EncryptAndAssemble(
                plaintext, header, contentEncryption, cryptoProvider,
                wrapPerRecipient: (recipient, tag) => Ecdh1PuKdf.DeriveKey(
                    cryptoProvider.UnderlyingProvider,
                    KeyTypeMapper.FromCurveForKeyAgreement(curve),
                    senderPrivBytes,
                    ephemeral.PrivateKey,
                    ExtractRecipientPublicKey(recipient),
                    Encoding.ASCII.GetBytes(header.Alg),
                    apuBytes,
                    apvBytes,
                    tag,
                    keyDataLen: 32),
                recipients);
        }
        finally
        {
            ephemeral.Clear();
            CryptographicOperations.ZeroMemory(senderPrivBytes);
        }
    }

    /// <summary>
    /// Build a multi-recipient General-JSON JWE with authenticated-sender key agreement
    /// (<c>ECDH-1PU+A256KW</c>) where the sender's static key is <b>opaque</b> (issue #13) — held in
    /// an HSM/KMS/keychain and never exposing its scalar. Identical wire output to
    /// <see cref="BuildEcdh1PuA256Kw"/>; only the sender ECDH is delegated to <paramref name="senderKey"/>.
    /// The per-message ephemeral key stays raw and in-package.
    /// </summary>
    /// <param name="plaintext">Bytes to encrypt.</param>
    /// <param name="recipients">Recipient public JWKs; ALL must share the sender's curve, each with a <c>kid</c>.</param>
    /// <param name="senderKey">Sender's static opaque ECDH key (matches <paramref name="skid"/>).</param>
    /// <param name="skid">Sender key identifier written to the protected header.</param>
    /// <param name="contentEncryption">JWE <c>enc</c> — MUST be <c>A256CBC-HS512</c>.</param>
    /// <param name="cryptoProvider">The JOSE crypto provider.</param>
    /// <param name="typ">Optional <c>typ</c> protected-header value.</param>
    /// <param name="ct">Cancellation token for the (possibly I/O-bound) sender key agreement.</param>
    /// <exception cref="ArgumentException">When <paramref name="contentEncryption"/> is not <c>A256CBC-HS512</c>.</exception>
    public static async Task<string> BuildEcdh1PuA256KwAsync(
        ReadOnlyMemory<byte> plaintext,
        IReadOnlyList<Jwk> recipients,
        IEcdhKey senderKey,
        string skid,
        string contentEncryption,
        JoseCryptoProvider cryptoProvider,
        string? typ = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(recipients);
        ArgumentNullException.ThrowIfNull(senderKey);
        ArgumentException.ThrowIfNullOrEmpty(skid);
        ArgumentNullException.ThrowIfNull(cryptoProvider);
        if (recipients.Count == 0)
            throw new ArgumentException("At least one recipient is required.", nameof(recipients));
        if (contentEncryption != JoseAlgorithms.A256CbcHs512)
            throw new ArgumentException(
                $"ECDH-1PU key wrap MUST use A256CBC-HS512 content encryption (draft-madden-04 §2.1 / didcomm FR-ENC-09). Got '{contentEncryption}'.",
                nameof(contentEncryption));

        EnsureRecipientsShareCurve(recipients, out var curve);
        if (!string.Equals(curve, senderKey.Crv, StringComparison.Ordinal))
            throw new ArgumentException(
                $"ECDH-1PU requires the sender key and all recipients on the same curve. Sender='{senderKey.Crv}', recipients='{curve}'.",
                nameof(senderKey));

        var ephemeral = EphemeralKeyPair.Generate(curve);
        try
        {
            var apvBytes = ApvComputer.ComputeBytes(recipients.Select(r => r.Kid ?? throw new MalformedJoseException("Recipient JWK is missing 'kid'.")));
            var apvB64u = Base64Url.Encode(apvBytes);
            var apuB64u = ApuComputer.Compute(skid);
            // 1PU draft-04 §2.3: PartyUInfo passed to ConcatKDF is the raw UTF-8 bytes of the skid.
            var apuBytes = Encoding.UTF8.GetBytes(skid);

            var header = new JweProtectedHeader
            {
                Typ = typ,
                Alg = JoseAlgorithms.Ecdh1PuA256Kw,
                Enc = contentEncryption,
                Epk = ephemeral.ToPublicEpkJwk(),
                Apv = apvB64u,
                Apu = apuB64u,
                Skid = skid,
            };

            return await EncryptAndAssembleAsync(
                plaintext, header, contentEncryption, cryptoProvider,
                wrapPerRecipientAsync: (recipient, tag) => Ecdh1PuKdf.DeriveKeyAsync(
                    cryptoProvider.UnderlyingProvider,
                    KeyTypeMapper.FromCurveForKeyAgreement(curve),
                    senderKey,
                    ephemeral.PrivateKey,
                    ExtractRecipientPublicKey(recipient),
                    Encoding.ASCII.GetBytes(header.Alg),
                    apuBytes,
                    apvBytes,
                    tag,
                    32,
                    ct),
                recipients).ConfigureAwait(false);
        }
        finally
        {
            ephemeral.Clear();
        }
    }

    /// <summary>
    /// Build a General-JSON JWE whose CEK is wrapped under one or more pre-shared symmetric
    /// keys (standalone <c>A256KW</c>, RFC 7518 §4.4).
    /// </summary>
    /// <param name="plaintext">Bytes to encrypt.</param>
    /// <param name="keyEncryptionKeys">Symmetric KEK JWKs (<c>kty="oct"</c>, 32-byte <c>k</c>, each with a <c>kid</c>).</param>
    /// <param name="contentEncryption">JWE <c>enc</c> (<c>A256CBC-HS512</c>, <c>A256GCM</c>, or <c>XC20P</c>).</param>
    /// <param name="cryptoProvider">The JOSE crypto provider.</param>
    /// <param name="typ">Optional <c>typ</c> protected-header value.</param>
    public static string BuildA256Kw(
        ReadOnlySpan<byte> plaintext,
        IReadOnlyList<Jwk> keyEncryptionKeys,
        string contentEncryption,
        JoseCryptoProvider cryptoProvider,
        string? typ = null)
    {
        ArgumentNullException.ThrowIfNull(keyEncryptionKeys);
        ArgumentNullException.ThrowIfNull(cryptoProvider);
        if (keyEncryptionKeys.Count == 0)
            throw new ArgumentException("At least one key-encryption key is required.", nameof(keyEncryptionKeys));

        var header = new JweProtectedHeader
        {
            Typ = typ,
            Alg = JoseAlgorithms.A256Kw,
            Enc = contentEncryption,
        };

        return EncryptAndAssemble(
            plaintext, header, contentEncryption, cryptoProvider,
            wrapPerRecipient: (kekJwk, _) => DecodeOctKey(kekJwk),
            keyEncryptionKeys);
    }

    /// <summary>
    /// Build a compact-serialization JWE (<c>header.encryptedKey.iv.ciphertext.tag</c>) for a
    /// single recipient using <c>ECDH-ES+A256KW</c>. No <c>apu</c>/<c>apv</c> is set (the
    /// generic-JOSE flavor); the recipient's <c>kid</c>, when present, is carried in the
    /// protected header.
    /// </summary>
    /// <param name="plaintext">Bytes to encrypt.</param>
    /// <param name="recipient">Recipient public JWK.</param>
    /// <param name="contentEncryption">JWE <c>enc</c>.</param>
    /// <param name="cryptoProvider">The JOSE crypto provider.</param>
    public static string BuildCompactEcdhEsA256Kw(
        ReadOnlySpan<byte> plaintext,
        Jwk recipient,
        string contentEncryption,
        JoseCryptoProvider cryptoProvider)
    {
        ArgumentNullException.ThrowIfNull(recipient);
        ArgumentNullException.ThrowIfNull(cryptoProvider);
        if (string.IsNullOrEmpty(recipient.Crv))
            throw new MalformedJoseException("Recipient JWK is missing 'crv'.");

        var ephemeral = EphemeralKeyPair.Generate(recipient.Crv);
        try
        {
            var header = new JweProtectedHeader
            {
                Alg = JoseAlgorithms.EcdhEsA256Kw,
                Enc = contentEncryption,
                Epk = ephemeral.ToPublicEpkJwk(),
                Kid = recipient.Kid,
            };

            return EncryptCompact(
                plaintext, header, contentEncryption, cryptoProvider,
                deriveKek: _ => EcdhEsKdf.DeriveKey(
                    cryptoProvider.UnderlyingProvider,
                    KeyTypeMapper.FromCurveForKeyAgreement(recipient.Crv),
                    ephemeral.PrivateKey,
                    ExtractRecipientPublicKey(recipient),
                    Encoding.ASCII.GetBytes(JoseAlgorithms.EcdhEsA256Kw),
                    apv: ReadOnlySpan<byte>.Empty,
                    keyDataLen: 32));
        }
        finally
        {
            ephemeral.Clear();
        }
    }

    /// <summary>
    /// Build a compact-serialization JWE for a single pre-shared symmetric KEK
    /// (standalone <c>A256KW</c>).
    /// </summary>
    /// <param name="plaintext">Bytes to encrypt.</param>
    /// <param name="keyEncryptionKey">Symmetric KEK JWK (<c>kty="oct"</c>, 32-byte <c>k</c>).</param>
    /// <param name="contentEncryption">JWE <c>enc</c>.</param>
    /// <param name="cryptoProvider">The JOSE crypto provider.</param>
    public static string BuildCompactA256Kw(
        ReadOnlySpan<byte> plaintext,
        Jwk keyEncryptionKey,
        string contentEncryption,
        JoseCryptoProvider cryptoProvider)
    {
        ArgumentNullException.ThrowIfNull(keyEncryptionKey);
        ArgumentNullException.ThrowIfNull(cryptoProvider);

        var header = new JweProtectedHeader
        {
            Alg = JoseAlgorithms.A256Kw,
            Enc = contentEncryption,
            Kid = keyEncryptionKey.Kid,
        };

        return EncryptCompact(
            plaintext, header, contentEncryption, cryptoProvider,
            deriveKek: _ => DecodeOctKey(keyEncryptionKey));
    }

    private static string EncryptAndAssemble(
        ReadOnlySpan<byte> plaintext,
        JweProtectedHeader header,
        string contentEncryption,
        JoseCryptoProvider cryptoProvider,
        Func<Jwk, byte[], byte[]> wrapPerRecipient,
        IReadOnlyList<Jwk> recipients)
    {
        var cekLen = KeyTypeMapper.ContentEncryptionKeySizeBytes(contentEncryption);
        var ivLen = KeyTypeMapper.IvSizeBytes(contentEncryption);
        var cek = new byte[cekLen];
        var iv = new byte[ivLen];
        cryptoProvider.Fill(cek);
        cryptoProvider.Fill(iv);

        try
        {
            var protectedB64u = header.EncodeBase64Url();
            var aad = Encoding.ASCII.GetBytes(protectedB64u);

            var (ciphertext, tag) = cryptoProvider.AeadEncrypt(contentEncryption, cek, iv, aad, plaintext);

            var wraps = new List<RecipientWrap>(recipients.Count);
            foreach (var recipient in recipients)
            {
                if (string.IsNullOrEmpty(recipient.Kid))
                    throw new MalformedJoseException("Recipient JWK is missing 'kid'.");
                var kek = wrapPerRecipient(recipient, tag);
                try
                {
                    var wrapped = cryptoProvider.KeyWrap(JoseAlgorithms.A256Kw, kek, cek);
                    wraps.Add(new RecipientWrap(recipient.Kid!, wrapped));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(kek);
                }
            }

            return RenderJwe(protectedB64u, wraps, iv, ciphertext, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }
    }

    private static async Task<string> EncryptAndAssembleAsync(
        ReadOnlyMemory<byte> plaintext,
        JweProtectedHeader header,
        string contentEncryption,
        JoseCryptoProvider cryptoProvider,
        Func<Jwk, byte[], ValueTask<byte[]>> wrapPerRecipientAsync,
        IReadOnlyList<Jwk> recipients)
    {
        var cekLen = KeyTypeMapper.ContentEncryptionKeySizeBytes(contentEncryption);
        var ivLen = KeyTypeMapper.IvSizeBytes(contentEncryption);
        var cek = new byte[cekLen];
        var iv = new byte[ivLen];
        cryptoProvider.Fill(cek);
        cryptoProvider.Fill(iv);

        try
        {
            var protectedB64u = header.EncodeBase64Url();
            var aad = Encoding.ASCII.GetBytes(protectedB64u);

            var (ciphertext, tag) = cryptoProvider.AeadEncrypt(contentEncryption, cek, iv, aad, plaintext.Span);

            var wraps = new List<RecipientWrap>(recipients.Count);
            foreach (var recipient in recipients)
            {
                if (string.IsNullOrEmpty(recipient.Kid))
                    throw new MalformedJoseException("Recipient JWK is missing 'kid'.");
                var kek = await wrapPerRecipientAsync(recipient, tag).ConfigureAwait(false);
                try
                {
                    var wrapped = cryptoProvider.KeyWrap(JoseAlgorithms.A256Kw, kek, cek);
                    wraps.Add(new RecipientWrap(recipient.Kid!, wrapped));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(kek);
                }
            }

            return RenderJwe(protectedB64u, wraps, iv, ciphertext, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }
    }

    private static string EncryptCompact(
        ReadOnlySpan<byte> plaintext,
        JweProtectedHeader header,
        string contentEncryption,
        JoseCryptoProvider cryptoProvider,
        Func<byte[], byte[]> deriveKek)
    {
        var cekLen = KeyTypeMapper.ContentEncryptionKeySizeBytes(contentEncryption);
        var ivLen = KeyTypeMapper.IvSizeBytes(contentEncryption);
        var cek = new byte[cekLen];
        var iv = new byte[ivLen];
        cryptoProvider.Fill(cek);
        cryptoProvider.Fill(iv);

        try
        {
            var protectedB64u = header.EncodeBase64Url();
            var aad = Encoding.ASCII.GetBytes(protectedB64u);
            var (ciphertext, tag) = cryptoProvider.AeadEncrypt(contentEncryption, cek, iv, aad, plaintext);

            var kek = deriveKek(tag);
            byte[] wrapped;
            try
            {
                wrapped = cryptoProvider.KeyWrap(JoseAlgorithms.A256Kw, kek, cek);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kek);
            }

            return string.Join('.',
                protectedB64u,
                Base64Url.Encode(wrapped),
                Base64Url.Encode(iv),
                Base64Url.Encode(ciphertext),
                Base64Url.Encode(tag));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cek);
        }
    }

    private static byte[] ExtractRecipientPublicKey(Jwk recipient)
    {
        var (_, bytes) = JwkConversion.ExtractPublicKey(recipient);
        return bytes;
    }

    private static byte[] DecodeOctKey(Jwk kekJwk)
    {
        if (!string.Equals(kekJwk.Kty, "oct", StringComparison.Ordinal) || string.IsNullOrEmpty(kekJwk.K))
            throw new MalformedJoseException("A256KW key-encryption key must be a kty=\"oct\" JWK with 'k'.");
        byte[] kek;
        try
        {
            kek = Base64Url.Decode(kekJwk.K);
        }
        catch (FormatException ex)
        {
            throw new MalformedJoseException("A256KW key-encryption key 'k' is not valid base64url.", ex);
        }
        if (kek.Length != 32)
            throw new MalformedJoseException($"A256KW key-encryption key must be 32 bytes; got {kek.Length}.");
        return kek;
    }

    private static string RenderJwe(string protectedB64u, IReadOnlyList<RecipientWrap> wraps, byte[] iv, byte[] ciphertext, byte[] tag)
    {
        var recipientArr = wraps.Select(w => new
        {
            header = new { kid = w.Kid },
            encrypted_key = Base64Url.Encode(w.EncryptedKey),
        }).ToArray();

        return JsonSerializer.Serialize(new
        {
            @protected = protectedB64u,
            recipients = recipientArr,
            iv = Base64Url.Encode(iv),
            ciphertext = Base64Url.Encode(ciphertext),
            tag = Base64Url.Encode(tag),
        });
    }

    private static void EnsureRecipientsShareCurve(IReadOnlyList<Jwk> recipients, out string curve)
    {
        curve = recipients[0].Crv ?? throw new MalformedJoseException("Recipient JWK is missing 'crv'.");
        for (var i = 1; i < recipients.Count; i++)
        {
            var c = recipients[i].Crv;
            if (!string.Equals(curve, c, StringComparison.Ordinal))
                throw new ArgumentException(
                    $"All recipients of a single JWE MUST share a curve (didcomm parity rule FR-ENC-04 / FR-ENC-11). Got {curve} and {c}.",
                    nameof(recipients));
        }
    }
}
