using System.Text.Json.Nodes;
using DataProofsDotnet.Jose.SdJwt;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Jose.Tests.SdJwt;

/// <summary>
/// Issue #45: the internal <see cref="ValidityWindow"/> reads a NumericDate the same way whether the member is parsed
/// JSON (every payload the verifier sees) or a <see cref="JsonValue"/> wrapping a .NET number, which only converts to
/// <see cref="decimal"/> when it is one. A .NET-backed value is read as the JSON text it serializes to, and one that
/// cannot be serialized is not a NumericDate. Found by the issue #45 adversarial passes: a <see cref="long"/> or
/// <see cref="double"/> value was refused, and a throwing converter escaped.
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

    /// <summary>A converter that throws when it writes, as a stand-in for any .NET value that cannot be serialized.</summary>
    private sealed class ThrowingConverter : System.Text.Json.Serialization.JsonConverter<long>
    {
        public override long Read(ref System.Text.Json.Utf8JsonReader reader, Type typeToConvert, System.Text.Json.JsonSerializerOptions options)
            => throw new FormatException("read");

        public override void Write(System.Text.Json.Utf8JsonWriter writer, long value, System.Text.Json.JsonSerializerOptions options)
            => throw new FormatException("write");
    }

    [Fact]
    public void A_value_that_cannot_be_serialized_is_not_a_NumericDate_and_does_not_throw()
    {
        var options = new System.Text.Json.JsonSerializerOptions
        {
            TypeInfoResolver = new System.Text.Json.Serialization.Metadata.DefaultJsonTypeInfoResolver(),
            Converters = { new ThrowingConverter() },
        };
        var typeInfo = (System.Text.Json.Serialization.Metadata.JsonTypeInfo<long>)options.GetTypeInfo(typeof(long));
        var exp = JsonValue.Create(NowSeconds + 60, typeInfo);

        Codes(exp).Should().Equal("SD_JWT_EXP_INVALID");
    }

    [Fact]
    public void Parsed_JSON_that_decimal_cannot_hold_is_refused_without_a_second_parse()
    {
        Codes(JsonNode.Parse("1e400")).Should().Equal("SD_JWT_EXP_INVALID");
        Codes(JsonNode.Parse("\"1795089700\"")).Should().Equal("SD_JWT_EXP_INVALID");
    }

    [Fact]
    public void The_Key_Binding_JWT_has_its_own_codes()
    {
        var payload = new JsonObject { ["nbf"] = NowSeconds + 60, ["exp"] = "later" };
        ValidityWindow.Check(payload, Now, TimeSpan.Zero, ValidityWindow.KeyBindingJwt)
            .Select(e => e.Split(':')[0]).Should().Equal("KB_JWT_NOT_YET_VALID", "KB_JWT_EXP_INVALID");
        ValidityWindow.Check(new JsonObject { ["exp"] = NowSeconds }, Now, TimeSpan.Zero, ValidityWindow.KeyBindingJwt)
            .Select(e => e.Split(':')[0]).Should().Equal("KB_JWT_EXP_PASSED");
        ValidityWindow.ShapeViolation(payload).Should().StartWith("SD_JWT_EXP_INVALID:");
    }
}
