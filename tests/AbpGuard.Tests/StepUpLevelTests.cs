using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using AbpGuard.Acting;
using Volo.Abp;

namespace AbpGuard.Tests;

/// <summary>
/// Step-up by category: a password-level mark passes on <c>auth_time</c>, a strong one on <c>strong_auth_time</c> alone,
/// with the 403's data saying how to pass; someone with no strong factor is told to set one up; a recovery code's sign-in
/// counts only where the caller says (adding a factor); and a token passes only where the host's policy names its category.
/// </summary>
public class StepUpLevelTests
{
    private static readonly Guid Person = Guid.NewGuid();

    private sealed class Window : IStepUpPolicy
    {
        public Task<TimeSpan> WindowAsync(CancellationToken cancellationToken = default) => Task.FromResult(TimeSpan.FromMinutes(10));
    }

    private sealed class Levels(StepUpStrongCategories strong, bool hasStrong) : IStepUpLevels
    {
        public bool IsStrong(string? category) => strong.Includes(category);

        public Task<StepUpMethods> MethodsAsync(Guid accountId, string level, CancellationToken cancellationToken = default) =>
            Task.FromResult(new StepUpMethods(level == StepUpLevels.Strong ? (hasStrong ? ["passkey"] : []) : hasStrong ? ["passkey", "password"] : ["password"], hasStrong));
    }

    private sealed class Publishing : IStepUpTokenPolicy
    {
        public Task<bool> AllowsAsync(string? category, ActingContext acting, CancellationToken cancellationToken = default) => Task.FromResult(category == "publishing");
    }

    private static StepUpGuard Guard(TimeSpan? proved = null, TimeSpan? strongly = null, TimeSpan? recovered = null, bool hasStrong = true, string? strong = null,
        bool token = false, IStepUpTokenPolicy? tokens = null)
    {
        List<Claim> claims = [new("sub", Person.ToString())];
        string At(TimeSpan ago) => DateTimeOffset.UtcNow.Subtract(ago).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (proved is { } p)
        {
            claims.Add(new Claim(ActingContext.AuthTimeClaim, At(p)));
        }

        if (strongly is { } s)
        {
            claims.Add(new Claim(ActingContext.StrongAuthTimeClaim, At(s)));
        }

        if (recovered is { } r)
        {
            claims.Add(new Claim(ActingContext.RecoveryAuthTimeClaim, At(r)));
        }

        if (token)
        {
            claims.Add(new Claim(new GuardNames().TokenClaim, Guid.NewGuid().ToString()));
        }

        ActingContext acting = new(new HttpContextAccessor { HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")) } });
        return new StepUpGuard(acting, new Window(), new Levels(StepUpStrongCategories.Parse(strong), hasStrong), tokens);
    }

    private static async Task<UserFriendlyException> RefusedAsync(Func<Task> step) => await Assert.ThrowsAsync<UserFriendlyException>(step);

    [Fact]
    public void An_admins_changes_to_someones_account_are_strong_by_default()
    {
        // Resetting someone's password or address is how an account is taken over (the user's decision, 14 Nov).
        Assert.Contains(StepUpCategories.Accounts, StepUpCategories.DefaultStrong);
        Assert.True(StepUpStrongCategories.Default.Includes(StepUpCategories.Accounts));
        Assert.False(StepUpStrongCategories.Default.Includes(StepUpCategories.Privacy));
    }

    [Fact]
    public async Task A_password_level_mark_passes_on_a_recent_sign_in_or_step_up()
    {
        await Guard(proved: TimeSpan.FromMinutes(3)).EnsureAsync(StepUpCategories.Privacy);
        await Guard(proved: TimeSpan.FromMinutes(3)).EnsureAsync();

        UserFriendlyException refused = await RefusedAsync(() => Guard(proved: TimeSpan.FromMinutes(30)).EnsureAsync(StepUpCategories.Privacy));
        Assert.Equal(GuardErrorCodes.StepUpRequired, refused.Code);
        Assert.Equal(StepUpLevels.Password, refused.Data["level"]);
        Assert.Equal(StepUpCategories.Privacy, refused.Data["category"]);
        Assert.Equal(["passkey", "password"], (string[])refused.Data["methods"]!);
        Assert.Equal(600, refused.Data["maxAgeSeconds"]);
    }

    [Fact]
    public async Task A_strong_mark_passes_only_on_a_recent_strong_proof()
    {
        await Guard(proved: TimeSpan.FromMinutes(1), strongly: TimeSpan.FromMinutes(5)).EnsureAsync(StepUpCategories.Roles);

        // The password just now isn't enough for a strong category, nor a strong proof past the window.
        foreach (StepUpGuard guard in new[] { Guard(proved: TimeSpan.FromSeconds(5)), Guard(proved: TimeSpan.FromSeconds(5), strongly: TimeSpan.FromMinutes(11)) })
        {
            UserFriendlyException refused = await RefusedAsync(() => guard.EnsureAsync(StepUpCategories.Roles));
            Assert.Equal(GuardErrorCodes.StepUpRequired, refused.Code);
            Assert.Equal(StepUpLevels.Strong, refused.Data["level"]);
            Assert.Equal(StepUpCategories.Roles, refused.Data["category"]);
            Assert.Equal(["passkey"], (string[])refused.Data["methods"]!);
        }

        // Someone with no strong factor is told to set one up, not asked for what they don't have.
        UserFriendlyException none = await RefusedAsync(() => Guard(proved: TimeSpan.FromSeconds(5), hasStrong: false).EnsureAsync(StepUpCategories.Security));
        Assert.Equal(GuardErrorCodes.StrongFactorRequired, none.Code);
        Assert.Equal(StepUpCategories.Security, none.Data["category"]);
    }

    [Fact]
    public async Task The_operator_chooses_the_strong_categories_and_a_mark_without_one_is_strong_only_under_a_star()
    {
        await Guard(proved: TimeSpan.FromMinutes(1), strong: "none").EnsureAsync(StepUpCategories.Roles);
        await Guard(proved: TimeSpan.FromMinutes(1), strong: "publishing").EnsureAsync(StepUpCategories.Roles);
        await RefusedAsync(() => Guard(proved: TimeSpan.FromMinutes(1), strong: "publishing").EnsureAsync("publishing"));
        await Guard(proved: TimeSpan.FromMinutes(1)).EnsureAsync();
        await RefusedAsync(() => Guard(proved: TimeSpan.FromMinutes(1), strong: "*").EnsureAsync());
    }

    [Fact]
    public async Task A_recovery_codes_sign_in_counts_as_strong_only_where_the_caller_says()
    {
        StepUpGuard recovered = Guard(proved: TimeSpan.FromMinutes(1), recovered: TimeSpan.FromMinutes(1));
        await recovered.EnsureAtAsync(StepUpCategories.Factors, StepUpLevels.Strong, recoverySignInCounts: true);
        await RefusedAsync(() => recovered.EnsureAtAsync(StepUpCategories.Factors, StepUpLevels.Strong));
        await RefusedAsync(() => recovered.EnsureAsync(StepUpCategories.Roles));

        // A level the caller gives wins over the setting: a person's first factor at the password level.
        await Guard(proved: TimeSpan.FromMinutes(1), strong: "factors").EnsureAtAsync(StepUpCategories.Factors, StepUpLevels.Password);
    }

    [Fact]
    public async Task A_token_never_steps_up_unless_the_hosts_policy_names_the_category()
    {
        UserFriendlyException refused = await RefusedAsync(() => Guard(proved: TimeSpan.Zero, strongly: TimeSpan.Zero, token: true).EnsureAsync(StepUpCategories.Tokens));
        Assert.Equal(GuardErrorCodes.Forbidden, refused.Code);

        await Guard(token: true, tokens: new Publishing()).EnsureAsync("publishing");
        await RefusedAsync(() => Guard(token: true, tokens: new Publishing()).EnsureAsync(StepUpCategories.Roles));
        await RefusedAsync(() => Guard(token: true, tokens: new Publishing()).EnsureAsync());
    }
}
