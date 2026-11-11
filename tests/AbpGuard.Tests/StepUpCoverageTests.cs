using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Routing;
using AbpGuard.Acting;
using AbpGuard.Controllers;

namespace AbpGuard.Tests;

/// <summary>
/// An admin's changes ask for the password again: every action that changes something, behind the Admin
/// policy or on accounts, has [StepUp], unless it's one of the few below and says why.
/// </summary>
public class StepUpCoverageTests
{
    /// <summary>The actions that change something without a step-up, and why that's right.</summary>
    private static readonly Dictionary<string, string> Without = new()
    {
        ["AccountsController.PreviewMerge"] = "reads only: what a merge would move",
        ["RolesController.Validate"] = "reads only: whether a rule is valid",
        ["DirectoriesController.Sync"] = "brings a directory's own users in, as its schedule does",
        ["DirectoriesController.Test"] = "tries the connection, changes nothing",
        ["DirectoriesController.TestLogin"] = "tries a sign-in against the directory, changes nothing",
        ["TokensController.Revoke"] = "takes access away: an admin stopping a leaked token mustn't be slowed",
        ["ServiceAccountsController.RevokeToken"] = "takes access away, as above",
        ["OAuthAppsController.Delete"] = "takes access away, as above",
        ["ErasuresController.PreviewOutside"] = "reads only: what erasing an address would do",
        ["SecurityFeedController.Send"] = "sends what's waiting to the address already set, as the feed's worker does each minute",
        ["SecurityAlertsController.Check"] = "checks the log for alerts, as its worker does every five minutes",
    };

    private static readonly Type[] AlwaysChecked = [typeof(AccountsController), typeof(MergesController)];

    [Fact]
    public void Every_admin_change_asks_for_a_step_up_or_says_why_not()
    {
        List<string> missing = [];
        List<string> seen = [];
        foreach (Type controller in typeof(AbpGuardModule).Assembly.GetTypes().Where(t => t.IsClass && !t.IsAbstract && t.Name.EndsWith("Controller", StringComparison.Ordinal)))
        {
            bool adminClass = IsAdmin(controller);
            foreach (MethodInfo action in controller.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly))
            {
                bool changes = action.GetCustomAttributes<HttpMethodAttribute>().Any(h => h.HttpMethods.Any(m => m is not "GET" and not "HEAD"));
                if (!changes || !(adminClass || IsAdmin(action) || AlwaysChecked.Contains(controller)))
                {
                    continue;
                }

                string name = $"{controller.Name}.{action.Name}";
                seen.Add(name);
                if (action.GetCustomAttribute<StepUpAttribute>() is null && !Without.ContainsKey(name))
                {
                    missing.Add(name);
                }
            }
        }

        Assert.True(missing.Count == 0, "No [StepUp] and not in the list of exceptions: " + string.Join(", ", missing));
        Assert.Empty(Without.Keys.Except(seen)); // an exception for an action that's gone or renamed goes too
    }

    private static bool IsAdmin(MemberInfo member) => member.GetCustomAttributes<AuthorizeAttribute>().Any(a => a.Policy == GuardPolicies.Admin);
}
