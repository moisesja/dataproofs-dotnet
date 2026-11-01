using System.Text;

namespace DataProofsDotnet.Rdfc.Internal;

/// <summary>RDFC orders text by Unicode scalar value, not UTF-16 code unit.</summary>
internal sealed class UnicodeCodePointComparer : IComparer<string>
{
    public static UnicodeCodePointComparer Instance { get; } = new();

    public int Compare(string? x, string? y)
    {
        if (ReferenceEquals(x, y)) return 0;
        if (x is null) return -1;
        if (y is null) return 1;

        var left = x.EnumerateRunes().GetEnumerator();
        var right = y.EnumerateRunes().GetEnumerator();
        while (left.MoveNext())
        {
            if (!right.MoveNext()) return 1;
            var order = left.Current.Value.CompareTo(right.Current.Value);
            if (order != 0) return order;
        }
        return right.MoveNext() ? -1 : 0;
    }
}
