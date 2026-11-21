using AbpGuard;
using AbpGuard.Acting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Volo.Abp;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Modularity;

namespace AbpNotify;

/// <summary>
/// Notices over HTTP (<c>api/notify</c>): <c>[DependsOn(typeof(AbpNotifyHttpApiModule))]</c> in the host's module, which
/// brings <see cref="AbpNotifyModule"/>. Who may manage the site's sending settings, its channels and a scope's teams'
/// channels is the host's <see cref="INotifyRights"/>; by default site admins (<see cref="GuardPolicies.Admin"/>) manage
/// the site's, and a scope's need the host's own.
/// </summary>
[DependsOn(typeof(AbpNotifyModule), typeof(AbpGuardActingModule))]
public class AbpNotifyHttpApiModule : AbpModule
{
    public override void PreConfigureServices(ServiceConfigurationContext context) =>
        PreConfigure<IMvcBuilder>(mvc => mvc.AddApplicationPartIfNotExists(typeof(AbpNotifyHttpApiModule).Assembly));

    public override void ConfigureServices(ServiceConfigurationContext context) =>
        context.Services.TryAddTransient<INotifyRights, AdminNotifyRights>();
}

/// <summary>Who may manage how notices are sent and where teams' channels post.</summary>
public interface INotifyRights
{
    /// <summary>Refuses (403) unless the caller may manage the scope's teams' channels (null: the site's, and its sending settings).</summary>
    Task EnsureMayManageAsync(Guid? scopeId, CancellationToken cancellationToken);
}

/// <summary>
/// The default: site admins (<see cref="GuardPolicies.Admin"/>) manage the site's; a scope's need the host's own rights.
/// Without that policy (an application without <c>AbpGuardModule</c>), no one does until the host registers its own
/// <see cref="INotifyRights"/>.
/// </summary>
public sealed class AdminNotifyRights(
    IAuthorizationService authorization, IAuthorizationPolicyProvider policies, Microsoft.AspNetCore.Http.IHttpContextAccessor http) : INotifyRights
{
    public async Task EnsureMayManageAsync(Guid? scopeId, CancellationToken cancellationToken)
    {
        if (scopeId is not null)
        {
            throw new UserFriendlyException("This application doesn't manage a scope's channels here.", GuardErrorCodes.Forbidden);
        }

        if (await policies.GetPolicyAsync(GuardPolicies.Admin) is not { } admins)
        {
            throw new UserFriendlyException(
                "No one manages notices here yet: the application registers an INotifyRights, or uses AbpGuard for its site admins.",
                GuardErrorCodes.Forbidden);
        }

        if (http.HttpContext?.User is not { } user || !(await authorization.AuthorizeAsync(user, admins)).Succeeded)
        {
            throw new UserFriendlyException("Only a site admin manages how the site's notices are sent.", GuardErrorCodes.Forbidden);
        }
    }
}
