using System.Security.Claims;
using AbpGuard;
using AbpGuard.Acting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Volo.Abp;

namespace AbpConnections.Tests;

/// <summary>
/// Who manages connections by default, with and without Guard's site admins, and which of the API's actions take the
/// secrets step-up.
/// </summary>
public class RightsTests
{
    private static readonly ClaimsPrincipal Admin = new(new ClaimsIdentity([new Claim("role", "admin")], "test"));
    private static readonly ClaimsPrincipal Someone = new(new ClaimsIdentity([new Claim("role", "user")], "test"));

    [Fact]
    public async Task Without_Guards_admins_no_one_manages_connections_and_the_refusal_says_what_to_do()
    {
        UserFriendlyException refused = await Assert.ThrowsAsync<UserFriendlyException>(() => Rights(null, Admin).EnsureMayManageAsync(null, default));
        Assert.Equal(GuardErrorCodes.Forbidden, refused.Code);
        Assert.Equal("No one manages connections here yet: the application registers an IConnectionRights, or uses AbpGuard for its site admins.", refused.Message);
    }

    [Fact]
    public async Task With_the_admins_policy_only_admins_manage_the_sites_connections()
    {
        static void Admins(AuthorizationOptions o) => o.AddPolicy(GuardPolicies.Admin, p => p.RequireClaim("role", "admin"));

        await Rights(Admins, Admin).EnsureMayManageAsync(null, default);
        UserFriendlyException someone = await Assert.ThrowsAsync<UserFriendlyException>(() => Rights(Admins, Someone).EnsureMayManageAsync(null, default));
        Assert.Equal((GuardErrorCodes.Forbidden, "Only a site admin manages the site's connections."), (someone.Code, someone.Message));
        UserFriendlyException scope = await Assert.ThrowsAsync<UserFriendlyException>(() => Rights(Admins, Admin).EnsureMayManageAsync(Guid.NewGuid(), default));
        Assert.Equal("This application doesn't manage a scope's connections here.", scope.Message);
    }

    [Fact]
    public void Signing_in_for_everyone_and_removing_take_the_secrets_step_up_and_ones_own_sign_in_none()
    {
        static IEnumerable<StepUpAttribute> Marks(string action) =>
            typeof(ConnectionsController).GetMethod(action)!.GetCustomAttributes(typeof(StepUpAttribute), false).Cast<StepUpAttribute>();

        Assert.Equal([StepUpCategories.Secrets], Marks(nameof(ConnectionsController.Authorize)).Select(m => m.Category));
        Assert.Equal([StepUpCategories.Secrets], Marks(nameof(ConnectionsController.Delete)).Select(m => m.Category));
        Assert.Empty(Marks(nameof(ConnectionsController.AuthorizeMine)));
        Assert.Empty(Marks(nameof(ConnectionsController.SignOutMine)));
    }

    private static AdminConnectionRights Rights(Action<AuthorizationOptions>? policies, ClaimsPrincipal user)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddAuthorization(o => policies?.Invoke(o));
        ServiceProvider provider = services.BuildServiceProvider();
        return new AdminConnectionRights(provider.GetRequiredService<IAuthorizationService>(), provider.GetRequiredService<IAuthorizationPolicyProvider>(),
            new HttpContextAccessor { HttpContext = new DefaultHttpContext { User = user } });
    }
}
