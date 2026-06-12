using System.Text.Json;
using NetCrypto;

namespace DataProofsDotnet.Cose.Tests.TestSupport;

/// <summary>
/// A parsed cose-wg/Examples COSE_Sign1 fixture (<c>tests/fixtures/cose-wg/</c>). Each fixture
/// is self-contained: key material (JSON COSE_Key), the expected wire bytes, the
/// <c>ToBeSign_hex</c> Sig_structure intermediate, and optional external AAD.
/// </summary>
internal sealed class CoseWgExample
{
    private CoseWgExample(
        string title,
        bool expectFail,
        KeyType keyType,
        byte[] publicKey,
        byte[] privateKey,
        byte[] cbor,
        byte[]? toBeSign,
        byte[] externalData)
    {
        Title = title;
        ExpectFail = expectFail;
        KeyType = keyType;
        PublicKey = publicKey;
        PrivateKey = privateKey;
        Cbor = cbor;
        ToBeSign = toBeSign;
        ExternalData = externalData;
    }

    internal string Title { get; }

    /// <summary>Whether the upstream fixture is a negative case (<c>"fail": true</c>).</summary>
    internal bool ExpectFail { get; }

    internal KeyType KeyType { get; }

    /// <summary>Raw public key: Ed25519 32 bytes, or uncompressed SEC1 (0x04‖X‖Y) for EC curves.</summary>
    internal byte[] PublicKey { get; }

    /// <summary>Raw private key (Ed25519 seed or EC scalar) — used for creation-direction tests.</summary>
    internal byte[] PrivateKey { get; }

    /// <summary>The expected encoded message (<c>output.cbor</c>).</summary>
    internal byte[] Cbor { get; }

    /// <summary>The Sig_structure signing input (<c>intermediates.ToBeSign_hex</c>), when provided.</summary>
    internal byte[]? ToBeSign { get; }

    /// <summary>External AAD (<c>input.sign0.external</c>); empty when the fixture has none.</summary>
    internal byte[] ExternalData { get; }

    internal static CoseWgExample Load(string relativePath)
    {
        string json = File.ReadAllText(Fixtures.PathOf("cose-wg", Path.Combine(relativePath.Split('/'))));
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        JsonElement sign0 = root.GetProperty("input").GetProperty("sign0");
        JsonElement key = sign0.GetProperty("key");

        (KeyType keyType, byte[] publicKey, byte[] privateKey) = ParseKey(key);

        byte[] externalData = sign0.TryGetProperty("external", out JsonElement external)
            ? Fixtures.Hex(external.GetString()!)
            : [];

        byte[]? toBeSign = root.TryGetProperty("intermediates", out JsonElement intermediates)
            && intermediates.TryGetProperty("ToBeSign_hex", out JsonElement tbs)
                ? Fixtures.Hex(tbs.GetString()!)
                : null;

        return new CoseWgExample(
            root.GetProperty("title").GetString()!,
            root.TryGetProperty("fail", out JsonElement fail) && fail.GetBoolean(),
            keyType,
            publicKey,
            privateKey,
            Fixtures.Hex(root.GetProperty("output").GetProperty("cbor").GetString()!),
            toBeSign,
            externalData);
    }

    private static (KeyType KeyType, byte[] PublicKey, byte[] PrivateKey) ParseKey(JsonElement key)
    {
        string kty = key.GetProperty("kty").GetString()!;
        string crv = key.GetProperty("crv").GetString()!;
        switch (kty, crv)
        {
            case ("OKP", "Ed25519"):
                return (
                    KeyType.Ed25519,
                    Fixtures.Hex(key.GetProperty("x_hex").GetString()!),
                    Fixtures.Hex(key.GetProperty("d_hex").GetString()!));

            case ("EC", "P-256") or ("EC", "P-384"):
                byte[] x = Fixtures.Base64Url(key.GetProperty("x").GetString()!);
                byte[] y = Fixtures.Base64Url(key.GetProperty("y").GetString()!);
                byte[] uncompressed = [0x04, .. x, .. y];
                return (
                    crv == "P-256" ? KeyType.P256 : KeyType.P384,
                    uncompressed,
                    Fixtures.Base64Url(key.GetProperty("d").GetString()!));

            default:
                throw new InvalidOperationException($"Unsupported fixture key: kty={kty}, crv={crv}.");
        }
    }
}
