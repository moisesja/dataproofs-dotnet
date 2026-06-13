using DataProofsDotnet.Internal;
using FluentAssertions;
using Xunit;

namespace DataProofsDotnet.Core.Tests.Unit;

/// <summary>
/// XML Schema 1.1 <c>dateTimeStamp</c> lexical validation — VC Data Integrity requires
/// an explicit timezone on <c>created</c>/<c>expires</c>.
/// </summary>
public class XmlDateTimeStampTests
{
    [Theory]
    [InlineData("2026-01-01T00:00:00Z")]
    [InlineData("2023-02-24T23:36:38Z")]
    [InlineData("2026-01-01T00:00:00.123Z")]
    [InlineData("2026-01-01T00:00:00+02:00")]
    [InlineData("2026-01-01T23:59:59.999999-05:30")]
    public void ValidDateTimeStamps_Parse(string value)
    {
        XmlDateTimeStamp.TryParse(value, out var parsed).Should().BeTrue();
        parsed.Should().NotBe(default(DateTimeOffset));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("2026-01-01T00:00:00")] // no timezone designator
    [InlineData("2026-01-01")] // date only
    [InlineData("2026-01-01 00:00:00Z")] // space separator
    [InlineData("2026-13-01T00:00:00Z")] // month out of range (lexically OK, value invalid)
    [InlineData("2026-01-01T25:00:00Z")] // hour out of range
    [InlineData("not-a-date")]
    [InlineData("2026-01-01T00:00:00+0200")] // timezone without colon
    public void InvalidValues_AreRejected(string? value)
        => XmlDateTimeStamp.TryParse(value, out _).Should().BeFalse();

    [Fact]
    public void ParsedValue_PreservesOffsetInstant()
    {
        XmlDateTimeStamp.TryParse("2026-01-01T12:00:00+02:00", out var parsed).Should().BeTrue();

        parsed.Should().Be(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.FromHours(2)));
    }
}
