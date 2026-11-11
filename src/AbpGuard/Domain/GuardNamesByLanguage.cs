namespace AbpGuard;

/// <summary>Names by language as people send them: codes and names trimmed, blank ones dropped.</summary>
public static class GuardNamesByLanguage
{
    public static Dictionary<string, string> Clean(IReadOnlyDictionary<string, string>? names, int maxLength = 256) =>
        (names ?? new Dictionary<string, string>())
            .Where(n => !string.IsNullOrWhiteSpace(n.Key) && n.Key.Trim().Length <= 35 && !string.IsNullOrWhiteSpace(n.Value))
            .ToDictionary(n => n.Key.Trim(), n => n.Value.Trim().Length > maxLength ? n.Value.Trim()[..maxLength] : n.Value.Trim(), StringComparer.Ordinal);
}
