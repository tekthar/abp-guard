using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using AbpGuard.Acting;

namespace AbpGuard.Tests;

/// <summary>
/// Tokens made under the names a site used before it renamed them (GuardNames.Former): read as made under today's, with
/// their limits, and refused when they carry such a claim under a name Guard doesn't know.
/// </summary>
public class FormerTokenNamesTests
{
    private const string Scope = "oi_scp";
    private static readonly Guid Token = Guid.NewGuid(), Project = Guid.NewGuid(), Session = Guid.NewGuid();

    private static GuardNames Renamed() => new()
    {
        Former = new FormerTokenNames
        {
            SessionClaim = "old_session",
            ModeClaim = "old_mode",
            TokenClaim = "old_token",
            TokenAccessClaim = "old_token_access",
            TokenProjectClaim = "old_token_project",
            TokenToolClaim = "old_token_tool",
            Scopes = { ["old.api"] = "api", ["old.read"] = "api.read" },
        },
    };

    private static ClaimsPrincipal Principal(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(c => new Claim(c.Type, c.Value)).Prepend(new Claim("sub", Guid.NewGuid().ToString())), "Bearer"));

    private static ActingContext Acting(ClaimsPrincipal user, GuardNames names) =>
        new(new HttpContextAccessor { HttpContext = new DefaultHttpContext { User = user } }, Options.Create(names));

    [Fact]
    public void An_old_access_token_keeps_its_project_limit_and_stays_read_only()
    {
        GuardNames names = Renamed();
        ClaimsPrincipal old = Principal(("old_token", Token.ToString()), ("old_token_access", "read"), ("old_token_project", Project.ToString()),
            ("old_token_tool", "search"), (Scope, "old.api"));

        ClaimsPrincipal current = names.Current(old, Scope)!;
        ActingContext acting = Acting(current, names);

        Assert.Equal(Token, acting.TokenId);
        Assert.Equal([Project], acting.TokenProjects!);
        Assert.Equal(["search"], acting.TokenTools!);
        Assert.Equal(["api"], current.FindAll(Scope).Select(c => c.Value));
        Assert.DoesNotContain(current.Claims, c => c.Type.StartsWith("old_", StringComparison.Ordinal));
    }

    [Fact]
    public void Read_untranslated_the_same_token_would_have_no_limit_at_all()
    {
        // Why the translation matters: today's names alone find no token claim, so no limit.
        GuardNames names = Renamed();
        ClaimsPrincipal old = Principal(("old_token", Token.ToString()), ("old_token_project", Project.ToString()));
        Assert.Null(Acting(old, names).TokenProjects);
        Assert.Equal([Project], Acting(names.Current(old, Scope)!, names).TokenProjects!);
    }

    [Fact]
    public void An_old_refresh_token_comes_back_with_todays_names_the_same_limit_and_todays_scopes()
    {
        GuardNames names = Renamed();
        ClaimsPrincipal refresh = Principal(("old_token", Token.ToString()), ("old_token_access", "write"), ("old_token_project", Project.ToString()),
            (Scope, "old.api"), (Scope, "offline_access"), ("oi_tkn_id", "t1"));

        ClaimsPrincipal current = names.Current(refresh, Scope)!;

        Assert.Equal(Token.ToString(), current.FindFirstValue(names.TokenClaim));
        Assert.Equal("write", current.FindFirstValue(names.TokenAccessClaim));
        Assert.Equal(Project.ToString(), current.FindFirstValue(names.TokenProjectClaim));
        Assert.Equal(["api", "offline_access"], current.FindAll(Scope).Select(c => c.Value));
        Assert.Equal("t1", current.FindFirstValue("oi_tkn_id"));
    }

    [Fact]
    public void An_old_impersonation_keeps_its_session_and_mode()
    {
        GuardNames names = Renamed();
        ClaimsPrincipal old = Principal(("old_session", Session.ToString()), ("old_mode", "support"));
        ClaimsPrincipal current = names.Current(old, Scope)!;
        Assert.Equal(Session.ToString(), current.FindFirstValue(names.SessionClaim));
        Assert.Equal("support", current.FindFirstValue(names.ModeClaim));
    }

    [Theory]
    [InlineData("old_token_project")]
    [InlineData("old_token")]
    [InlineData("old_token_access")]
    [InlineData("old_token_tool")]
    [InlineData("old_session")]
    [InlineData("old_mode")]
    [InlineData("other_token_project")]
    public void A_claim_under_a_name_Guard_doesnt_know_is_refused(string type)
    {
        // A site that never named its former names, and one that did, but not this one.
        Assert.Null(new GuardNames().Current(Principal((type, Project.ToString())), Scope));
        if (type.StartsWith("other_", StringComparison.Ordinal))
        {
            Assert.Null(Renamed().Current(Principal((type, Project.ToString())), Scope));
        }
    }

    [Fact]
    public void A_token_under_todays_names_is_left_as_it_is()
    {
        GuardNames names = Renamed();
        ClaimsPrincipal today = Principal(("guard_token", Token.ToString()), ("guard_token_project", Project.ToString()), (Scope, "api"),
            ("id_token", "x"));
        Assert.Same(today, names.Current(today, Scope));
        Assert.Same(today, new GuardNames().Current(today, Scope));
    }
}
