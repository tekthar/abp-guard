using AbpGuard;
using AbpGuard.Acting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Volo.Abp;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Modularity;

namespace AbpConnections;

/// <summary>
/// Connections over HTTP (<c>api/connections</c>): <c>[DependsOn(typeof(AbpConnectionsHttpApiModule))]</c> in the host's
/// module, which brings <see cref="AbpConnectionsModule"/>. Who may manage a scope's connections is the host's
/// <see cref="IConnectionRights"/>; by default site admins (<see cref="GuardPolicies.Admin"/>) manage the site's, and a
/// scope's need the host's own.
/// </summary>
[DependsOn(typeof(AbpConnectionsModule), typeof(AbpGuardActingModule))]
public class AbpConnectionsHttpApiModule : AbpModule
{
    public override void PreConfigureServices(ServiceConfigurationContext context) =>
        PreConfigure<IMvcBuilder>(mvc => mvc.AddApplicationPartIfNotExists(typeof(AbpConnectionsHttpApiModule).Assembly));

    public override void ConfigureServices(ServiceConfigurationContext context) =>
        context.Services.TryAddTransient<IConnectionRights, AdminConnectionRights>();
}

/// <summary>Who may manage connections, and which scopes' connections a person signs in to themselves.</summary>
public interface IConnectionRights
{
    /// <summary>Refuses (403) unless the caller may manage the connections of the scope (null: the site's).</summary>
    Task EnsureMayManageAsync(Guid? scopeId, CancellationToken cancellationToken);

    /// <summary>The scopes whose connections each person signs in to the person may use, besides the site's.</summary>
    Task<IReadOnlyCollection<Guid>> ScopesOfAsync(Guid accountId, CancellationToken cancellationToken);
}

/// <summary>The default: site admins manage the site's connections; a scope's need the host's own rights.</summary>
public sealed class AdminConnectionRights(IAuthorizationService authorization, Microsoft.AspNetCore.Http.IHttpContextAccessor http) : IConnectionRights
{
    public async Task EnsureMayManageAsync(Guid? scopeId, CancellationToken cancellationToken)
    {
        if (scopeId is not null)
        {
            throw new UserFriendlyException("This application doesn't manage a scope's connections here.", GuardErrorCodes.Forbidden);
        }

        if (http.HttpContext?.User is not { } user || !(await authorization.AuthorizeAsync(user, GuardPolicies.Admin)).Succeeded)
        {
            throw new UserFriendlyException("Only a site admin manages the site's connections.", GuardErrorCodes.Forbidden);
        }
    }

    public Task<IReadOnlyCollection<Guid>> ScopesOfAsync(Guid accountId, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyCollection<Guid>>([]);
}
