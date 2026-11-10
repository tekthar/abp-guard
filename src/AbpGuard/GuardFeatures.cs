using System.Reflection;
using Microsoft.AspNetCore.Mvc.ApplicationModels;

namespace AbpGuard;

/// <summary>
/// What a host uses of Guard, from Guard:Features: each switch that's off removes that feature's endpoints, so
/// a host that doesn't sync directories or take sign-ups answers 404 there. All on by default.
/// Accounts, groups, roles, sessions and the security log are always there.
/// </summary>
public sealed class GuardFeatures
{
    /// <summary>Directories other than the internal one, their connectors and syncs.</summary>
    public bool Directories { get; set; } = true;

    /// <summary>Personal access tokens, a person's own and a service account's.</summary>
    public bool PersonalTokens { get; set; } = true;

    /// <summary>Apps that sign people in (OAuth with consent), and the apps people allowed.</summary>
    public bool OAuthApps { get; set; } = true;

    /// <summary>Apps registering themselves (RFC 7591); a site setting may still turn it off.</summary>
    public bool ClientRegistration { get; set; } = true;

    /// <summary>Merging two accounts into one.</summary>
    public bool Merges { get; set; } = true;

    /// <summary>A phone app handing its sign-in to a web view.</summary>
    public bool Handoff { get; set; } = true;

    /// <summary>People signing up for themselves.</summary>
    public bool SignUp { get; set; } = true;

    /// <summary>A second step at sign-in; off, no one is asked for one, as with Guard:TwoFactor:Disabled.</summary>
    public bool TwoFactor { get; set; } = true;

    /// <summary>
    /// Exporting a person's data (PDPL): their own, and admins' exports of an account or of someone outside.
    /// </summary>
    public bool DataExport { get; set; } = true;

    /// <summary>Whether the feature of this name is on; an unknown name is.</summary>
    public bool IsOn(string feature) =>
        typeof(GuardFeatures).GetProperty(feature, BindingFlags.Public | BindingFlags.Instance)?.GetValue(this) is not false;
}

/// <summary>Marks a controller, or an action, as part of a Guard feature (a <see cref="GuardFeatures"/> property's name).</summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class GuardFeatureAttribute(string feature) : Attribute
{
    public string Feature { get; } = feature;
}

/// <summary>Removes the controllers and actions of the Guard features that are off.</summary>
public sealed class GuardFeatureConvention(GuardFeatures features) : IApplicationModelConvention
{
    public void Apply(ApplicationModel application)
    {
        foreach (ControllerModel controller in application.Controllers.ToList())
        {
            if (Off(controller.Attributes))
            {
                application.Controllers.Remove(controller);
                continue;
            }

            foreach (ActionModel action in controller.Actions.Where(a => Off(a.Attributes)).ToList())
            {
                controller.Actions.Remove(action);
            }
        }
    }

    private bool Off(IEnumerable<object> attributes) =>
        attributes.OfType<GuardFeatureAttribute>().Any(a => !features.IsOn(a.Feature));
}
