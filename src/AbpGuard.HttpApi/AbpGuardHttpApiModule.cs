using Microsoft.Extensions.DependencyInjection;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Modularity;

namespace AbpGuard;

/// <summary>
/// AbpGuard's API over HTTP: <c>[DependsOn(typeof(AbpGuardHttpApiModule))]</c> in the host's module, beside or instead
/// of <see cref="AbpGuardModule"/>, which it brings. Without it a host has Guard's services and tables but no endpoints:
/// no sign-in pages' API, no <c>/connect/*</c> handling of its own and no <c>api/guard/*</c>.
/// </summary>
[DependsOn(typeof(AbpGuardModule))]
public class AbpGuardHttpApiModule : AbpModule
{
    public override void PreConfigureServices(ServiceConfigurationContext context) =>
        PreConfigure<IMvcBuilder>(mvc => mvc.AddApplicationPartIfNotExists(typeof(AbpGuardHttpApiModule).Assembly));
}
