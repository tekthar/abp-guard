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
}
