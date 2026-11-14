using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Domain;
using AbpGuard.Services;

namespace AbpGuard.Controllers;

/// <summary>
/// The person's language and time zone; null follows the site's. Weeks start on the site's first day for
/// everyone: sunday, monday… Motion is how much the interface moves for them: system (as their
/// device says), reduced or full.
/// </summary>
public sealed record PreferencesDto(string? Language, string? TimeZone, string SiteTimeZone, string FirstDayOfWeek, string Motion)
{
    public static PreferencesDto For(Account account, IGuardSiteDefaults site) =>
        new(account.Language, account.TimeZone, site.TimeZone, site.FirstDayOfWeek.ToString().ToLowerInvariant(), account.Motion ?? "system");
}

public sealed record PreferencesInput(string? Language, string? TimeZone);

/// <summary>system (or nothing), reduced or full.</summary>
public sealed record MotionInput(string? Motion);

[Route("api/guard")]
public class AuthController(GuardDb guardDb, MembershipGraph graph, IGuardSiteDefaults siteDefaults) : GuardControllerBase
{
    /// <summary>Sets the person's language and time zone; null (or empty) goes back to the site's.</summary>
    [HttpPut("me/preferences")]
    [Authorize]
    public async Task<PreferencesDto> SavePreferences([FromBody] PreferencesInput input, CancellationToken cancellationToken)
    {
        string? language = string.IsNullOrWhiteSpace(input.Language) ? null : input.Language.Trim();
        string? zone = string.IsNullOrWhiteSpace(input.TimeZone) ? null : input.TimeZone.Trim();
        if (language is not null)
        {
            language = await siteDefaults.ChoosableLanguageAsync(language, cancellationToken)
                ?? throw new Volo.Abp.UserFriendlyException($"'{language}' isn't one of the site's languages.");
        }

        if (zone is not null && !TimeZoneInfo.TryFindSystemTimeZoneById(zone, out _))
        {
            throw new Volo.Abp.UserFriendlyException($"'{zone}' isn't a time zone.");
        }

        return await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.FirstAsync(a => a.Id == CurrentAccountId, cancellationToken);
            account.Language = language;
            account.TimeZone = zone;
            await db.SaveChangesAsync(cancellationToken);
            return Preferences(account);
        }, requiresNew: true, cancellationToken: cancellationToken);
    }

    private PreferencesDto Preferences(Account account) => PreferencesDto.For(account, siteDefaults);

    /// <summary>
    /// How much the interface moves for the person: system follows their device's setting, reduced keeps
    /// movement out, full plays it anyway. Its own call, so saving the language and time zone never touches it.
    /// </summary>
    [HttpPut("me/motion")]
    [Authorize]
    public async Task<PreferencesDto> SaveMotion([FromBody] MotionInput input, CancellationToken cancellationToken)
    {
        string? motion = input.Motion?.Trim().ToLowerInvariant() switch
        {
            null or "" or "system" => null,
            "reduced" => "reduced",
            "full" => "full",
            var other => throw new Volo.Abp.UserFriendlyException($"Motion is system, reduced or full, not '{other}'."),
        };

        return await guardDb.RunAsync(async db =>
        {
            Account account = await db.Accounts.FirstAsync(a => a.Id == CurrentAccountId, cancellationToken);
            account.Motion = motion;
            await db.SaveChangesAsync(cancellationToken);
            return Preferences(account);
        }, requiresNew: true, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// The person signed in: their account, groups, rights (CASL's rules), preferences, whose rights the request uses, and
    /// their strong factor: whether they have one, its kinds (<c>passkey</c>, <c>app</c>), and by when the site admins' rule
    /// asks for one (the grace starts here the first time Guard sees a site admin without one) and whether that's past.
    /// </summary>
    [HttpGet("me")]
    [Authorize]
    public async Task<object> Me([FromServices] Services.TwoFactor.AdminsStrongFactor admins, CancellationToken cancellationToken)
    {
        Casl.Ability ability = await AbilityAsync(cancellationToken);
        Services.TwoFactor.StrongFactorDue due = await admins.CheckAsync(CurrentAccountId, ClientIp, cancellationToken);
        return await guardDb.RunAsync<object>(async db =>
    {
        Account account = await db.Accounts.FirstAsync(a => a.Id == CurrentAccountId, cancellationToken);
        Dictionary<Guid, string> directories = await db.Directories.ToDictionaryAsync(d => d.Id, d => d.Name, cancellationToken);
        List<EffectiveGroup> groups = await graph.GetEffectiveGroupsAsync(db, account, cancellationToken);
        List<string> strong = [.. (await Services.TwoFactor.SecondFactors.KindsAsync(db, account.Id, cancellationToken)).Where(SecondFactorKinds.IsStrong)];
        return new
        {
            account = AccountDto.From(account, directories.GetValueOrDefault(account.DirectoryId, "?")),
            groups = groups.Select(g => new EffectiveGroupDto(g.Group.Id, g.Group.Name, g.Group.DirectoryId, directories.GetValueOrDefault(g.Group.DirectoryId, "?"), g.Direct, g.Path)),
            isAdmin = ability.Can("manage", "all"),
            // Whose rights the session uses and who is acting: only a subject unless someone acts for them.
            acting = new
            {
                accountId = Acting.SubjectId, actingAccountId = Acting.ActorId, mode = Acting.Mode, sessionId = Acting.SessionId,
                tokenId = Acting.TokenId, readOnly = Acting.ReadOnly, projectIds = Acting.TokenProjects,
            },
            preferences = Preferences(account),
            // CASL raw rules for the browser (casl-net): the UI hides what the server would refuse.
            rules = ability.ToCaslRules(),
            // Their strong factor, and the site admins' rule's date for them.
            strongFactor = new { has = strong.Count > 0, methods = strong, requiredBy = due.RequiredBy, overdue = due.Overdue },
        };
    }, cancellationToken: cancellationToken);
    }

    private static object Error(string code, string message) => new { error = new { code, message } };
}
