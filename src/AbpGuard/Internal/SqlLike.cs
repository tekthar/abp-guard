namespace AbpGuard;

/// <summary>
/// Someone's text as a LIKE or ILIKE pattern (Postgres, whose escape character is the backslash), so the %, _ and \ in
/// it match themselves instead of acting as wildcards. Guard's own copy, so Guard references
/// nothing else.
/// </summary>
internal static class SqlLike
{
    /// <summary>A pattern that matches exactly this text (with ILIKE, in any case).</summary>
    public static string Exactly(string text) =>
        text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal);

    /// <summary>A pattern that matches text containing this text anywhere.</summary>
    public static string Containing(string text) => "%" + Exactly(text) + "%";
}
