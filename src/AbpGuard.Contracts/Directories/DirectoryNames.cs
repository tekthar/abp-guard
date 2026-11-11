using System.Text.RegularExpressions;

namespace AbpGuard.Directories;

/// <summary>Names by language from a directory: what a language code may be.</summary>
public static partial class DirectoryNames
{
    private const int TimeoutMilliseconds = 1000;

    /// <summary>A BCP 47-like code: "ar", "en-GB", "zh-Hant", "pt-BR".</summary>
    public static bool IsLanguageCode(string? code) => code is { Length: > 0 and <= 35 } && LanguageCode().IsMatch(code);

    /// <summary>
    /// "ar=displayName;lang-ar, fr=nameFr" as language codes to attribute names: which attribute holds each language's
    /// name. Commas or new lines separate entries (an LDAP option such as ";lang-ar" belongs to its attribute); an entry
    /// that isn't language=attribute is left out (<see cref="NameAttributeProblems"/> says which when the setting is saved).
    /// </summary>
    public static Dictionary<string, string> ParseNameAttributes(string? text)
    {
        Dictionary<string, string> map = new(StringComparer.OrdinalIgnoreCase);
        foreach (string part in Entries(text))
        {
            if (Split(part) is { } entry)
            {
                map[entry.Language] = entry.Attribute;
            }
        }

        return map;
    }

    /// <summary>What's wrong in such a setting, each entry that isn't language=attribute named: empty when it's right.</summary>
    public static IReadOnlyList<string> NameAttributeProblems(string? text, string label) =>
        [.. Entries(text).Where(part => Split(part) is null)
            .Select(part => $"'{label}' needs language=attribute entries, such as ar=displayName;lang-ar; '{part}' isn't one.")];

    private static IEnumerable<string> Entries(string? text) =>
        (text ?? "").Split([',', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static (string Language, string Attribute)? Split(string part)
    {
        int at = part.IndexOf('=');
        if (at <= 0)
        {
            return null;
        }

        string language = part[..at].Trim();
        string attribute = part[(at + 1)..].Trim();
        return IsLanguageCode(language) && AttributeName().IsMatch(attribute) ? (language, attribute) : null;
    }

    [GeneratedRegex("^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$", RegexOptions.None, TimeoutMilliseconds)]
    private static partial Regex LanguageCode();

    /// <summary>An attribute name, with LDAP options after ";" (displayName;lang-ar), or an Active Directory extension attribute.</summary>
    [GeneratedRegex("^[A-Za-z][A-Za-z0-9-]*(;[A-Za-z0-9-]+)*$", RegexOptions.None, TimeoutMilliseconds)]
    private static partial Regex AttributeName();
}

/// <summary>
/// A connector that checks a directory's settings when an admin saves them: each problem a
/// sentence; any problem refuses the save. Optional: a connector without it saves what the definitions allow.
/// </summary>
public interface IDirectorySettingsValidator
{
    IReadOnlyList<string> ProblemsIn(IReadOnlyDictionary<string, string> settings);
}
