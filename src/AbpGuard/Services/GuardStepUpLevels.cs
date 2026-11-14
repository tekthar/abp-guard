using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using AbpGuard.Acting;
using AbpGuard.Services.TwoFactor;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>
/// Guard's step-up levels: the categories <c>Guard:StepUp:Strong</c> names (the operator's, never a page's) ask for a
/// strong proof, and a person's ways are their passkeys, the app, the password and the codes the site sends them. With
/// second factors switched off (<c>Guard:TwoFactor:Disabled</c>, the emergency switch) no category is strong, or a site
/// whose admins lost their devices couldn't be run at all.
/// </summary>
[ExposeServices(typeof(IStepUpLevels), typeof(GuardStepUpLevels))]
public class GuardStepUpLevels(IOptions<GuardOptions> options, IConfiguration configuration, SecondFactors secondFactors) : IStepUpLevels, ITransientDependency
{
    /// <summary>The strong categories as the site's settings say.</summary>
    public StepUpStrongCategories Strong => Read(options.Value, configuration);

    /// <summary>
    /// <c>Guard:StepUp:Strong</c>: one value, comma-separated (an environment variable's), or a list's entries (a JSON array
    /// in appsettings).
    /// </summary>
    public static StepUpStrongCategories Read(GuardOptions guard, IConfiguration? configuration = null)
    {
        IConfigurationSection? section = configuration?.GetSection("Guard:StepUp:Strong");
        List<string?> listed = section is null ? [] : [.. section.GetChildren().Select(c => c.Value)];
        return listed.Count > 0 ? StepUpStrongCategories.Parse(listed) : StepUpStrongCategories.Parse(guard.StepUp.Strong);
    }

    public bool IsStrong(string? category) => !secondFactors.Disabled && Strong.Includes(category);

    public Task<StepUpMethods> MethodsAsync(Guid accountId, string level, CancellationToken cancellationToken = default) =>
        secondFactors.StepUpMethodsAsync(accountId, level == StepUpLevels.Strong, cancellationToken);
}
