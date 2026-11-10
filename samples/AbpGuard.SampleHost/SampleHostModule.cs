using Volo.Abp;
using Volo.Abp.AspNetCore.Mvc;
using Volo.Abp.Autofac;
using Volo.Abp.Modularity;

namespace AbpGuard.SampleHost;

/// <summary>Guard's module and ABP's, and Guard's controllers: all a host needs.</summary>
[DependsOn(typeof(AbpAutofacModule), typeof(AbpGuardModule))]
public class SampleHostModule : AbpModule
{
    public override void ConfigureServices(ServiceConfigurationContext context) =>
        Configure<AbpAspNetCoreMvcOptions>(options => options.ConventionalControllers.Create(typeof(AbpGuardModule).Assembly));

    public override void OnApplicationInitialization(ApplicationInitializationContext context)
    {
        IApplicationBuilder app = context.GetApplicationBuilder();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        // A read-only token reads only.
        app.UseMiddleware<AbpGuard.Acting.ReadOnlyRequests>();
        app.UseConfiguredEndpoints();
    }
}
