using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Data;
using AbpGuard.Domain;
using AbpGuard.Services;
using AbpGuard.Acting;
using Volo.Abp;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Controllers;

/// <summary>
/// The site's security settings, with their limits: how long the security audit keeps events, how
/// recently a person must have signed in or stepped up to do something sensitive, and the longest a personal access
/// token may live.
/// </summary>
public sealed record SecuritySettingsDto(int RetentionDays, int MinRetentionDays, int MaxRetentionDays, int StepUpMinutes, int MinStepUpMinutes, int MaxStepUpMinutes,
    int TokenMaxDays, int MinTokenMaxDays, int MaxTokenMaxDays, bool AppsMayRegister = false);

/// <summary>The settings to save; TokenMaxDays left out keeps what's saved.</summary>
public sealed record SecuritySettingsInput([property: JsonRequired] int RetentionDays, [property: JsonRequired] int StepUpMinutes, int? TokenMaxDays = null,
    bool? AppsMayRegister = null);

/// <summary>
/// Security settings, for site admins. Changing them is sensitive (a shorter retention removes older events, a longer
/// window weakens step-up), so it needs a step-up itself and goes in the audit.
/// </summary>
[Route("api/guard/security/settings")]
[Authorize(Policy = GuardPolicies.Admin)]
public class SecuritySettingsController(GuardDb guardDb, SecurityLog audit) : GuardControllerBase
{
    [HttpGet]
    public Task<SecuritySettingsDto> Get(CancellationToken cancellationToken) =>
        guardDb.RunAsync(async db => ToDto(await LoadAsync(db, cancellationToken)), cancellationToken: cancellationToken);

    [HttpPut]
    [StepUp]
    public Task<SecuritySettingsDto> Save([FromBody] SecuritySettingsInput input, CancellationToken cancellationToken)
    {
        if (input.RetentionDays is < SecuritySettings.MinRetentionDays or > SecuritySettings.MaxRetentionDays)
        {
            throw new UserFriendlyException($"Keep security events between {SecuritySettings.MinRetentionDays} and {SecuritySettings.MaxRetentionDays} days.");
        }

        if (input.StepUpMinutes is < SecuritySettings.MinStepUpMinutes or > SecuritySettings.MaxStepUpMinutes)
        {
            throw new UserFriendlyException($"Ask for the password again after {SecuritySettings.MinStepUpMinutes} to {SecuritySettings.MaxStepUpMinutes} minutes.");
        }

        if (input.TokenMaxDays is < SecuritySettings.MinTokenMaxDays or > SecuritySettings.MaxTokenMaxDays)
        {
            throw new UserFriendlyException($"Tokens may live at most {SecuritySettings.MinTokenMaxDays} to {SecuritySettings.MaxTokenMaxDays} days.");
        }

        return guardDb.RunAsync(async db =>
        {
            SecuritySettings settings = await LoadAsync(db, cancellationToken);
            if (input.TokenMaxDays is { } days && settings.TokenMaxDays != days)
            {
                // Tokens made before keep their expiry; only new ones are held to it.
                audit.Add(db, SecurityAuditTypes.TokenSettingsChanged, null, new { tokenMaxDays = new { before = settings.TokenMaxDays, after = days } });
                settings.TokenMaxDays = days;
            }

            if (settings.RetentionDays != input.RetentionDays)
            {
                audit.Add(db, SecurityAuditTypes.RetentionChanged, null, new { retentionDays = new { before = settings.RetentionDays, after = input.RetentionDays } });
                settings.RetentionDays = input.RetentionDays;
            }

            if (input.AppsMayRegister is { } register && settings.AppsMayRegister != register)
            {
                audit.Add(db, SecurityAuditTypes.AppsMayRegister, null, new { appsMayRegister = new { before = settings.AppsMayRegister, after = register } });
                settings.AppsMayRegister = register;
            }

            if (settings.StepUpMinutes != input.StepUpMinutes)
            {
                audit.Add(db, SecurityAuditTypes.StepUpChanged, null, new { stepUpMinutes = new { before = settings.StepUpMinutes, after = input.StepUpMinutes } });
                settings.StepUpMinutes = input.StepUpMinutes;
            }

            await db.SaveChangesAsync(cancellationToken);
            return ToDto(settings);
        }, requiresNew: true, cancellationToken);
    }

    /// <summary>The site's security settings, made with the defaults the first time they're asked for.</summary>
    public static async Task<SecuritySettings> LoadAsync(GuardDbContext db, CancellationToken cancellationToken)
    {
        SecuritySettings? settings = await db.SecuritySettings.FirstOrDefaultAsync(s => s.Id == SecuritySettings.SingletonId, cancellationToken);
        if (settings is null)
        {
            settings = new SecuritySettings(SecuritySettings.SingletonId);
            db.SecuritySettings.Add(settings);
            await db.SaveChangesAsync(cancellationToken);
        }

        return settings;
    }

    private static SecuritySettingsDto ToDto(SecuritySettings s) => new(
        s.RetentionDays, SecuritySettings.MinRetentionDays, SecuritySettings.MaxRetentionDays,
        s.StepUpMinutes, SecuritySettings.MinStepUpMinutes, SecuritySettings.MaxStepUpMinutes,
        s.TokenMaxDays, SecuritySettings.MinTokenMaxDays, SecuritySettings.MaxTokenMaxDays, s.AppsMayRegister);
}

/// <summary>The step-up window as the site sets it: ten minutes unless changed, never more than thirty.</summary>
[ExposeServices(typeof(IStepUpPolicy))]
public class GuardStepUpPolicy(GuardDb guardDb) : IStepUpPolicy, ITransientDependency
{
    public async Task<TimeSpan> WindowAsync(CancellationToken cancellationToken = default)
    {
        int minutes = await guardDb.RunAsync(db => db.SecuritySettings.AsNoTracking().Where(s => s.Id == SecuritySettings.SingletonId)
            .Select(s => (int?)s.StepUpMinutes).FirstOrDefaultAsync(cancellationToken), cancellationToken: cancellationToken) ?? SecuritySettings.DefaultStepUpMinutes;
        return TimeSpan.FromMinutes(Math.Clamp(minutes, SecuritySettings.MinStepUpMinutes, SecuritySettings.MaxStepUpMinutes));
    }
}

/// <summary>A way the site can send a second step's code: email, or a channel that reaches people one by one; Ready when it's set up.</summary>
public sealed record SecondFactorMethodOptionDto(string Method, string Name, bool Ready);

/// <summary>The sent codes a second step may use (none: only the authenticator app), and every way the site has.</summary>
public sealed record SecondFactorSettingsDto(List<string> Methods, List<SecondFactorMethodOptionDto> Available);

public sealed record SecondFactorSettingsInput(List<string>? Methods);

/// <summary>
/// Which codes a second step may be sent by: by email, SMS, WhatsApp or another channel, besides the
/// authenticator app. A group set to strong still asks for the app. Changing it needs a step-up and is audited.
/// </summary>
[Route("api/guard/security/second-factor")]
[Authorize(Policy = GuardPolicies.Admin)]
[GuardFeature(nameof(GuardFeatures.TwoFactor))]
public class SecondFactorSettingsController(GuardDb guardDb, SecurityLog audit, IGuardMessenger messenger) : GuardControllerBase
{
    [HttpGet]
    public async Task<SecondFactorSettingsDto> Get(CancellationToken cancellationToken)
    {
        List<SecondFactorMethodOptionDto> available = await AvailableAsync(cancellationToken);
        return await guardDb.RunAsync(async db => new SecondFactorSettingsDto((await SecuritySettingsController.LoadAsync(db, cancellationToken)).SecondFactorMethods, available),
            cancellationToken: cancellationToken);
    }

    [HttpPut]
    [StepUp]
    public async Task<SecondFactorSettingsDto> Save([FromBody] SecondFactorSettingsInput input, CancellationToken cancellationToken)
    {
        List<SecondFactorMethodOptionDto> available = await AvailableAsync(cancellationToken);
        List<string> methods = [.. (input.Methods ?? []).Distinct(StringComparer.Ordinal)];
        if (methods.FirstOrDefault(m => available.TrueForAll(a => a.Method != m)) is { } unknown)
        {
            throw new UserFriendlyException($"'{unknown}' isn't a way this site can send a code.");
        }

        return await guardDb.RunAsync(async db =>
        {
            SecuritySettings settings = await SecuritySettingsController.LoadAsync(db, cancellationToken);
            if (!settings.SecondFactorMethods.SequenceEqual(methods))
            {
                audit.Add(db, SecurityAuditTypes.SecondFactorMethods, null, new { methods = new { before = settings.SecondFactorMethods, after = methods } });
                settings.SecondFactorMethods = methods;
                await db.SaveChangesAsync(cancellationToken);
            }

            return new SecondFactorSettingsDto(settings.SecondFactorMethods, available);
        }, requiresNew: true, cancellationToken);
    }

    /// <summary>The ways the site has of sending a code (the messenger's): email, then each channel that reaches people one by one.</summary>
    private async Task<List<SecondFactorMethodOptionDto>> AvailableAsync(CancellationToken cancellationToken) =>
        [.. (await messenger.MethodsAsync(cancellationToken)).Select(m => new SecondFactorMethodOptionDto(m.Method, m.Name, m.Ready))];
}
