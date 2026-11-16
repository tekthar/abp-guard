using Volo.Abp;
using Volo.Abp.Autofac;
using Volo.Abp.Modularity;

namespace AbpGuard.SampleHost;

/// <summary>
/// Guard's module and ABP's, and Guard's controllers: all a host needs. <see cref="AbpGuardHttpApiModule"/> adds its
/// controllers to MVC itself, so a host calls no <c>ConventionalControllers.Create</c> for them.
/// </summary>
[DependsOn(typeof(AbpAutofacModule), typeof(AbpGuardHttpApiModule))]
public class SampleHostModule : AbpModule
{
    // Guard's API as its own document: /openapi/abpguard.json, kept in docs/openapi/abpguard.json (OpenApiContractTests),
    // and what a host's screens generate their types from (@abpjs/ui's guard area).
    public override void ConfigureServices(ServiceConfigurationContext context) =>
        context.Services.AddOpenApi(OpenApiDocument.Name, OpenApiDocument.Configure);

    public override void OnApplicationInitialization(ApplicationInitializationContext context)
    {
        IApplicationBuilder app = context.GetApplicationBuilder();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        // A read-only token reads only.
        app.UseMiddleware<AbpGuard.Acting.ReadOnlyRequests>();
        app.UseConfiguredEndpoints(endpoints => endpoints.MapOpenApi());
    }
}

/// <summary>Guard's API document: AbpGuard.HttpApi's actions alone, under their own routes, with no servers.</summary>
public static class OpenApiDocument
{
    public const string Name = "abpguard";

    public static void Configure(Microsoft.AspNetCore.OpenApi.OpenApiOptions options)
    {
        System.Reflection.Assembly guard = typeof(AbpGuardHttpApiModule).Assembly;
        options.ShouldInclude = description =>
            description.ActionDescriptor is Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor action && action.ControllerTypeInfo.Assembly == guard;
        options.AddDocumentTransformer((document, _, _) =>
        {
            document.Servers?.Clear(); // the kept copy doesn't depend on where it was made
            document.Info.Title = "AbpGuard API";
            document.Info.Version = AbpGuardModule.Version;
            document.Info.Description = "AbpGuard.HttpApi's actions under api/guard (the token endpoint, OpenIddict's, isn't here). "
                + "Errors are ABP's: { \"error\": { \"code\", \"message\", \"details\", \"data\", \"validationErrors\" } }; "
                + "a step-up asked is 403 step_up_required with data { level, category, methods, appCodeAlone, maxAgeSeconds }.";
            return Task.CompletedTask;
        });
    }
}
