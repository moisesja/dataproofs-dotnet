using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.SdJwt;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// Issue #45: the internal <see cref="ValidityWindow"/> reads a NumericDate the same way whether the member is parsed
/// JSON (every payload the verifier sees) or a <see cref="JsonValue"/> wrapping a .NET number, which only converts to
/// <see cref="decimal"/> when it is one. A .NET-backed value is read as the JSON text it serializes to, the bytes that
/// would be signed. Found by the issue #45 adversarial pass: before, a <see cref="long"/> or <see cref="double"/> value
/// was refused as <c>SD_JWT_EXP_INVALID</c>.
/// </summary>
public sealed class ValidityWindowTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 19, 12, 0, 0, TimeSpan.Zero);
    private static readonly long NowSeconds = Now.ToUnixTimeSeconds();

    private static string[] Codes(JsonNode? exp)
        => ValidityWindow.Check(new JsonObject { ["exp"] = exp }, Now, TimeSpan.Zero, ValidityWindow.SdJwt)
            .Select(e => e.Split(':')[0]).ToArray();

    public static TheoryData<string, JsonNode> NetBackedFuture => new()
    {
        { "long", JsonValue.Create(NowSeconds + 1) },
        { "int", JsonValue.Create((int)(NowSeconds + 1)) },
        { "uint", JsonValue.Create((uint)(NowSeconds + 1)) },
        { "double", JsonValue.Create(NowSeconds + 0.5) },
        { "decimal", JsonValue.Create(NowSeconds + 0.5m) },
        { "parsed", JsonNode.Parse((NowSeconds + 1).ToString())! },
    };

    [Theory]
    [MemberData(nameof(NetBackedFuture))]
    public void A_NET_backed_number_is_read_as_its_JSON_text(string kind, JsonNode exp)
    {
        Codes(exp).Should().BeEmpty(kind);
        Codes(JsonValue.Create(NowSeconds)).Should().Equal("SD_JWT_EXPIRED");
    }

    [Theory]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    [InlineData(1e300)]
    [InlineData(-1e300)]
    public void A_non_finite_or_out_of_range_double_is_not_a_NumericDate(double value)
        => Codes(JsonValue.Create(value)).Should().Equal("SD_JWT_EXP_INVALID");

    [Fact]
    public void The_Key_Binding_JWT_codes_carry_their_own_prefix()
    {
        var payload = new JsonObject { ["nbf"] = NowSeconds + 60, ["exp"] = "later" };
        ValidityWindow.Check(payload, Now, TimeSpan.Zero, ValidityWindow.KeyBindingJwt)
            .Select(e => e.Split(':')[0]).Should().Equal("KB_JWT_NOT_YET_VALID", "KB_JWT_EXP_INVALID");
        ValidityWindow.ShapeViolation(payload).Should().StartWith("SD_JWT_EXP_INVALID:");
    }
}
