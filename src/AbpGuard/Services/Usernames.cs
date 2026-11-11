using System.Text.RegularExpressions;

namespace AbpGuard.Services;

/// <summary>What a username looks like, for a user in an internal directory and for a service account alike.</summary>
public static partial class Usernames
{
    /// <summary>How long a match may run (the SDK's value).</summary>
    private const int TimeoutMilliseconds = 1000;

    /// <summary>The rule as people read it, for when a username doesn't match <see cref="Pattern"/>.</summary>
    public const string Rule = "Usernames are 2–64 letters, digits, dots, dashes, underscores or @.";

    /// <summary>2 to 64 letters, digits, dots, dashes, underscores or @.</summary>
    [GeneratedRegex(@"^[A-Za-z0-9._@-]{2,64}$", RegexOptions.None, TimeoutMilliseconds)]
    public static partial Regex Pattern();

    /// <summary>Why a name kept for erased accounts is refused; its code is <see cref="ReservedCode"/>.</summary>
    public const string ReservedRule = "\"former-person-…\" and \"Former person …\" are kept for erased accounts: choose another name.";

    public const string ReservedCode = "reserved_name";

    /// <summary>An erased account's username: no one else gets one, so an erasure's is always free.</summary>
    [GeneratedRegex(@"^former-person-[0-9]+(-[0-9]+)?$", RegexOptions.IgnoreCase, TimeoutMilliseconds)]
    private static partial Regex Erased();

    /// <summary>An erased account's display name: no one poses as an erased person.</summary>
    [GeneratedRegex(@"^former\s+person\s+[0-9]+$", RegexOptions.IgnoreCase, TimeoutMilliseconds)]
    private static partial Regex ErasedName();

    /// <summary>The username of an erased account's pseudonym: "Former person 7" is "former-person-7".</summary>
    public static string ErasedOf(string pseudonym) => pseudonym.Trim().ToLowerInvariant().Replace(' ', '-');

    public static bool IsReserved(string? username) => username is not null && Erased().IsMatch(username.Trim());

    public static bool IsReservedName(string? displayName) => displayName is not null && ErasedName().IsMatch(displayName.Trim());

    /// <summary>Refuses a username or display name kept for erased accounts, when a person or an admin chooses one.</summary>
    public static void EnsureNotReserved(string? username, string? displayName)
    {
        if (IsReserved(username) || IsReservedName(displayName))
        {
            throw new Volo.Abp.UserFriendlyException(ReservedRule, ReservedCode);
        }
    }
}
