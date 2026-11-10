using Volo.Abp;

namespace AbpGuard.Services;

/// <summary>What a display name may hold: one line, with no control characters, since it goes into mails' headers.</summary>
public static class DisplayNames
{
    /// <summary>Refuses a name with a line break, a control character, or Unicode's line or paragraph separator.</summary>
    public static string Check(string name) =>
        name.Any(c => char.IsControl(c) || c is '\u2028' or '\u2029')
            ? throw new UserFriendlyException("A name is one line, with no control characters.")
            : name;
}
