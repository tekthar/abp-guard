using System.Security.Claims;
using AbpGuard;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Volo.Abp;

namespace AbpNotify.Tests;

/// <summary>
/// The rules without a database: quiet hours and digests in the person's time zone, a chat address, Slack's own
/// Markdown, and who manages notices by default.
/// </summary>
public class RuleTests
{
    private static readonly TimeZoneInfo Riyadh = TimeZoneInfo.FindSystemTimeZoneById("Asia/Riyadh"); // UTC+3, no daylight saving

    [Fact]
    public void Quiet_hours_are_kept_in_the_persons_time_zone_and_may_span_midnight()
    {
        NotificationSettings night = new() { QuietFrom = 22 * 60, QuietTo = 7 * 60 };
        Assert.True(night.Quiet(new DateTime(2026, 10, 11, 20, 0, 0, DateTimeKind.Utc), Riyadh)); // 23:00 there
        Assert.True(night.Quiet(new DateTime(2026, 10, 11, 3, 59, 0, DateTimeKind.Utc), Riyadh)); // 06:59
        Assert.False(night.Quiet(new DateTime(2026, 10, 11, 4, 0, 0, DateTimeKind.Utc), Riyadh)); // 07:00
        Assert.False(night.Quiet(new DateTime(2026, 10, 11, 12, 0, 0, DateTimeKind.Utc), Riyadh));

        NotificationSettings lunch = new() { QuietFrom = 12 * 60, QuietTo = 13 * 60 };
        Assert.True(lunch.Quiet(new DateTime(2026, 10, 11, 9, 30, 0, DateTimeKind.Utc), Riyadh));
        Assert.False(lunch.Quiet(new DateTime(2026, 10, 11, 10, 0, 0, DateTimeKind.Utc), Riyadh));
        Assert.False(new NotificationSettings().Quiet(DateTime.UtcNow, Riyadh));
    }

    [Fact]
    public void A_daily_digest_comes_once_its_hour_has_come_there_and_an_hourly_one_an_hour_apart()
    {
        DateTime before = new(2026, 10, 11, 4, 59, 0, DateTimeKind.Utc), after = new(2026, 10, 11, 5, 0, 0, DateTimeKind.Utc); // 07:59 and 08:00 in Riyadh
        NotificationSettings daily = new() { DigestEvery = DigestFrequencies.Daily, DigestHour = 8 };
        Assert.False(daily.DigestDue(before, Riyadh));
        Assert.True(daily.DigestDue(after, Riyadh));
        daily.LastDigestAt = after;
        Assert.False(daily.DigestDue(after.AddHours(10), Riyadh));
        Assert.True(daily.DigestDue(after.AddDays(1), Riyadh));

        NotificationSettings hourly = new() { DigestEvery = DigestFrequencies.Hourly };
        Assert.True(hourly.DigestDue(before, Riyadh));
        hourly.LastDigestAt = before;
        Assert.False(hourly.DigestDue(before.AddMinutes(59), Riyadh));
        Assert.True(hourly.DigestDue(before.AddHours(1), Riyadh));
    }

    [Fact]
    public void Quiet_hours_are_written_as_times_of_day()
    {
        Assert.Equal(22 * 60 + 30, NotificationSettings.Minutes("22:30"));
        Assert.Null(NotificationSettings.Minutes(" "));
        Assert.Equal("07:05", NotificationSettings.Clock(7 * 60 + 5));
        Assert.Throws<UserFriendlyException>(() => NotificationSettings.Minutes("25:00"));
    }

    [Fact]
    public void A_chat_address_names_its_connection_and_where()
    {
        Guid connection = Guid.NewGuid();
        Assert.True(ChatAddress.TryParse(ChatAddress.Of(connection, "C123"), out Guid id, out string where));
        Assert.Equal((connection, "C123"), (id, where));
        Assert.True(ChatAddress.TryParse(ChatAddress.Of(connection, ""), out _, out string none));
        Assert.Equal("", none);
        Assert.False(ChatAddress.TryParse("C123", out _, out _));
        Assert.False(ChatAddress.TryParse("not-a-guid|C123", out _, out _));
    }

    [Fact]
    public void Markdown_becomes_Slacks_own() =>
        Assert.Equal("<https://app.example/browse/PAY-1|PAY-1> *Refund*: moved", SlackChannel.Slack("[PAY-1](https://app.example/browse/PAY-1) **Refund**: moved"));

    [Fact]
    public void A_teams_test_says_what_the_application_calls_itself()
    {
        Assert.Equal("this server", new NotifyOptions().ApplicationName);
        Assert.Equal(["slack", "teams", "fcm"], [SlackConnectionKind.Key, TeamsConnectionKind.Key, FcmConnectionKind.Key]);
    }

    [Fact]
    public void The_api_has_these_routes()
    {
        static string Verb(System.Reflection.MethodInfo m) => m.GetCustomAttributes(true).OfType<Microsoft.AspNetCore.Mvc.Routing.HttpMethodAttribute>().Single() switch
        {
            var a => $"{a.HttpMethods.Single()} {a.Template}".TrimEnd(),
        };

        List<string> routes = [.. typeof(AbpNotifyHttpApiModule).Assembly.GetTypes()
            .Where(t => typeof(Microsoft.AspNetCore.Mvc.ControllerBase).IsAssignableFrom(t))
            .SelectMany(t => t.GetMethods().Where(m => m.GetCustomAttributes(true).OfType<Microsoft.AspNetCore.Mvc.Routing.HttpMethodAttribute>().Any())
                .Select(m => (Prefix: t.GetCustomAttributes(true).OfType<Microsoft.AspNetCore.Mvc.RouteAttribute>().Single().Template, Route: Verb(m))))
            .Select(r => r.Route.Split(' ', 2) is [var verb, var path] ? $"{verb} {r.Prefix}/{path}" : $"{r.Route} {r.Prefix}")
            .Order(StringComparer.Ordinal)];
        Assert.Equal(
        [
            "DELETE api/notify/me/channels/{channel}", "DELETE api/notify/me/devices", "DELETE api/notify/me/devices/{id:guid}", "DELETE api/notify/targets/{id:guid}",
            "GET api/notify/channels", "GET api/notify/me/channels", "GET api/notify/me/devices", "GET api/notify/me/notices", "GET api/notify/me/notices/unread",
            "GET api/notify/me/settings", "GET api/notify/settings", "GET api/notify/targets", "GET api/notify/targets/connections",
            "POST api/notify/me/channels/{channel}/find", "POST api/notify/me/channels/{channel}/verify", "POST api/notify/me/notices/read",
            "POST api/notify/me/notices/{id:guid}/unread", "POST api/notify/targets",
            "PUT api/notify/me/channels/{channel}", "PUT api/notify/me/devices", "PUT api/notify/me/settings", "PUT api/notify/settings",
        ], routes);
    }

    private static readonly ClaimsPrincipal Admin = new(new ClaimsIdentity([new Claim("role", "admin")], "test"));
    private static readonly ClaimsPrincipal Someone = new(new ClaimsIdentity([new Claim("role", "user")], "test"));

    private static AdminNotifyRights Rights(Action<AuthorizationOptions>? policies, ClaimsPrincipal user)
    {
        ServiceCollection services = new();
        services.AddLogging();
        services.AddAuthorization(o => policies?.Invoke(o));
        ServiceProvider provider = services.BuildServiceProvider();
        return new AdminNotifyRights(provider.GetRequiredService<IAuthorizationService>(), provider.GetRequiredService<IAuthorizationPolicyProvider>(),
            new HttpContextAccessor { HttpContext = new DefaultHttpContext { User = user } });
    }

    [Fact]
    public async Task Without_Guards_admins_no_one_manages_notices_and_the_refusal_says_what_to_do()
    {
        UserFriendlyException refused = await Assert.ThrowsAsync<UserFriendlyException>(() => Rights(null, Admin).EnsureMayManageAsync(null, default));
        Assert.Equal(GuardErrorCodes.Forbidden, refused.Code);
        Assert.Equal("No one manages notices here yet: the application registers an INotifyRights, or uses AbpGuard for its site admins.", refused.Message);
    }

    [Fact]
    public async Task With_the_admins_policy_only_admins_manage_the_sites_notices()
    {
        static void Admins(AuthorizationOptions o) => o.AddPolicy(GuardPolicies.Admin, p => p.RequireClaim("role", "admin"));

        await Rights(Admins, Admin).EnsureMayManageAsync(null, default);
        UserFriendlyException someone = await Assert.ThrowsAsync<UserFriendlyException>(() => Rights(Admins, Someone).EnsureMayManageAsync(null, default));
        Assert.Equal((GuardErrorCodes.Forbidden, "Only a site admin manages how the site's notices are sent."), (someone.Code, someone.Message));
        UserFriendlyException scope = await Assert.ThrowsAsync<UserFriendlyException>(() => Rights(Admins, Admin).EnsureMayManageAsync(Guid.NewGuid(), default));
        Assert.Equal("This application doesn't manage a scope's channels here.", scope.Message);
    }
}
