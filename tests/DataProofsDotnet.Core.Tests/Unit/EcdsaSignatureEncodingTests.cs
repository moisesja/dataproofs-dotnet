using DataProofsDotnet.Internal;
using FluentAssertions;
using NetCrypto;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>
/// The internal DER → IEEE P1363 transcoder that lets a non-exporting key-store signer
/// (DER-emitting for NIST curves) satisfy the W3C P1363 wire requirement (AC-8 enabler).
/// </summary>
public class EcdsaSignatureEncodingTests
{
    private static byte[] Der(byte[] r, byte[] s)
    {
        var rEncoded = EncodeInteger(r);
        var sEncoded = EncodeInteger(s);
        var content = rEncoded.Concat(sEncoded).ToArray();
        return [0x30, (byte)content.Length, .. content];

        static byte[] EncodeInteger(byte[] value)
        {
            // Strip leading zeros, then re-pad one zero if the sign bit is set.
            var trimmed = value.SkipWhile(b => b == 0).ToArray();
            if (trimmed.Length == 0)
            {
                trimmed = [0];
            }

            if ((trimmed[0] & 0x80) != 0)
            {
                trimmed = [0, .. trimmed];
            }

            return [0x02, (byte)trimmed.Length, .. trimmed];
        }
    }

    [Fact]
    public void Der_WithShortAndPaddedIntegers_NormalizesToFixedWidth()
    {
        // r small (1 byte), s with high bit set (DER pads a 0x00).
        byte[] r = [0x7F];
        var s = Enumerable.Repeat((byte)0xAB, 32).ToArray();

        EcdsaSignatureEncoding.TryNormalizeToP1363(Der(r, s), 32, out var p1363).Should().BeTrue();

        p1363.Should().HaveCount(64);
        p1363[..31].Should().OnlyContain(b => b == 0);
        p1363[31].Should().Be(0x7F);
        p1363[32..].Should().Equal(s);
    }

    [Fact]
    public void NativeP1363Signature_PassesThroughUnchanged()
    {
        var signature = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();

        EcdsaSignatureEncoding.TryNormalizeToP1363(signature, 32, out var p1363).Should().BeTrue();

        p1363.Should().Equal(signature);
    }

    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0x30 })]
    [InlineData(new byte[] { 0x01, 0x02, 0x03 })]
    public void Garbage_IsRejected(byte[] signature)
        => EcdsaSignatureEncoding.TryNormalizeToP1363(signature, 32, out _).Should().BeFalse();

    [Fact]
    public void IntegerWiderThanTheField_IsRejected()
    {
        var tooWide = Enumerable.Repeat((byte)0x55, 33).ToArray(); // 33 > 32 field width
        var s = Enumerable.Repeat((byte)0x01, 32).ToArray();

        EcdsaSignatureEncoding.TryNormalizeToP1363(Der(tooWide, s), 32, out _).Should().BeFalse();
    }

    [Fact]
    public void NonMinimalIntegerPadding_IsRejected()
    {
        // 0x00 prefix on a value whose sign bit is NOT set violates DER minimality.
        byte[] nonMinimal = [0x30, 0x08, 0x02, 0x02, 0x00, 0x7F, 0x02, 0x02, 0x00, 0x7F];

        EcdsaSignatureEncoding.TryNormalizeToP1363(nonMinimal, 32, out _).Should().BeFalse();
    }

    [Fact]
    public void TrailingBytesAfterTheSequence_AreRejected()
    {
        var valid = Der([0x01], [0x02]);
        byte[] withTrailer = [.. valid, 0x00];

        EcdsaSignatureEncoding.TryNormalizeToP1363(withTrailer, 32, out _).Should().BeFalse();
    }

    [Theory]
    [InlineData(KeyType.P256, 32)]
    [InlineData(KeyType.P384, 48)]
    public void NetCryptoDerSignatures_TranscodeAndVerifyAsP1363(KeyType keyType, int fieldWidth)
    {
        var crypto = new DefaultCryptoProvider();
        var keyGen = new DefaultKeyGenerator();
        var keyPair = keyGen.FromPrivateKey(keyType, Enumerable.Repeat((byte)0x42, fieldWidth).ToArray());
        var data = "transcoding round-trip"u8.ToArray();

        // NetCrypto's default Sign emits DER for NIST curves (the key-store path).
        var der = crypto.Sign(keyType, keyPair.PrivateKey, data);

        EcdsaSignatureEncoding.TryNormalizeToP1363(der, fieldWidth, out var p1363).Should().BeTrue();
        p1363.Length.Should().Be(2 * fieldWidth);
        crypto.Verify(keyType, keyPair.PublicKey, data, p1363, EcdsaSignatureFormat.IeeeP1363).Should().BeTrue();
    }
}
