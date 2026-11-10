using System.Globalization;
using Microsoft.Extensions.Options;

namespace AbpGuard;

/// <summary>
/// What a site says for people who haven't: its time zone and the day its weeks start on, the language of the
/// request being served, and which languages people may choose. The default reads <see cref="GuardOptions.Site"/>; a host
/// may give its own.
/// </summary>
public interface IGuardSiteDefaults
{
    /// <summary>The site's time zone, an IANA name.</summary>
    string TimeZone { get; }

    DayOfWeek FirstDayOfWeek { get; }

    /// <summary>The language the request is served in: mail to an address goes out in it.</summary>
    string RequestLanguage { get; }

    /// <summary>The site's code for a language people may choose (as the site writes it), or null when it isn't one.</summary>
    Task<string?> ChoosableLanguageAsync(string code, CancellationToken cancellationToken);
}

/// <summary>The default site: <see cref="GuardOptions.Site"/>, and the request's UI culture.</summary>
public sealed class OptionsGuardSiteDefaults(IOptions<GuardOptions> options) : IGuardSiteDefaults
{
    public string TimeZone => options.Value.Site.TimeZone is { Length: > 0 } zone && TimeZoneInfo.TryFindSystemTimeZoneById(zone, out _) ? zone : "UTC";

    public DayOfWeek FirstDayOfWeek => options.Value.Site.FirstDayOfWeek;

    public string RequestLanguage => CultureInfo.CurrentUICulture.Name is { Length: > 0 } name ? name : options.Value.Site.Languages.FirstOrDefault() ?? "en";

    public Task<string?> ChoosableLanguageAsync(string code, CancellationToken cancellationToken) =>
        Task.FromResult(options.Value.Site.Languages.FirstOrDefault(l => string.Equals(l, code, StringComparison.OrdinalIgnoreCase)));
}
