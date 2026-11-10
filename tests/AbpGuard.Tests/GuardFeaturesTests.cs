using System.Reflection;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.Configuration;
using AbpGuard.Controllers;

namespace AbpGuard.Tests;

/// <summary>Guard's feature switches: one that's off removes its controllers and actions; all are on by default.</summary>
public class GuardFeaturesTests
{
    private static ApplicationModel Model(params Type[] controllers)
    {
        ApplicationModel application = new();
        foreach (Type type in controllers)
        {
            ControllerModel controller = new(type.GetTypeInfo(), type.GetCustomAttributes(inherit: true));
            foreach (MethodInfo method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                controller.Actions.Add(new ActionModel(method, method.GetCustomAttributes(inherit: true)) { ActionName = method.Name });
            }

            application.Controllers.Add(controller);
        }

        return application;
    }

    [Fact]
    public void Every_feature_is_on_unless_the_host_says_otherwise()
    {
        GuardFeatures features = new();
        Assert.All(typeof(GuardFeatures).GetProperties().Where(p => p.PropertyType == typeof(bool)), p => Assert.True(features.IsOn(p.Name), p.Name));

        GuardOptions bound = new();
        new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Guard:Features:SignUp"] = "false" }).Build()
            .GetSection(GuardOptions.Section).Bind(bound);
        Assert.False(bound.Features.SignUp);
        Assert.True(bound.Features.TwoFactor);
    }

    [Fact]
    public void A_feature_switched_off_loses_its_controllers_and_actions()
    {
        ApplicationModel application = Model(typeof(DirectoriesController), typeof(SelfServiceController), typeof(SessionController), typeof(GroupsController));

        new GuardFeatureConvention(new GuardFeatures { Directories = false, SignUp = false, Handoff = false }).Apply(application);

        Assert.DoesNotContain(application.Controllers, c => c.ControllerType == typeof(DirectoriesController));
        ControllerModel self = Assert.Single(application.Controllers, c => c.ControllerType == typeof(SelfServiceController));
        Assert.DoesNotContain(self.Actions, a => a.ActionName is nameof(SelfServiceController.SignUp));
        Assert.Contains(self.Actions, a => a.ActionName is nameof(SelfServiceController.TestAccounts));
        ControllerModel session = Assert.Single(application.Controllers, c => c.ControllerType == typeof(SessionController));
        Assert.DoesNotContain(session.Actions, a => a.Attributes.OfType<GuardFeatureAttribute>().Any(f => f.Feature == nameof(GuardFeatures.Handoff)));
        Assert.Contains(application.Controllers, c => c.ControllerType == typeof(GroupsController));
    }
}
