using Microsoft.Extensions.Configuration;
using Volo.Abp.DependencyInjection;

namespace AbpGuard.Services;

/// <summary>An account a test site shows on its sign-in page: its username, its password, and a word on who it is.</summary>
public sealed record TestAccountDto(string Username, string Password, string? Note);

/// <summary>
/// Accounts a test site lists on its sign-in page, so the people trying it can sign in as each kind of person
/// (<c>Guard:SignIn:TestAccounts</c>, each with Username, Password and Note). None unless the server's configuration
/// lists them: a site people use shows none. The accounts themselves are made as any are; this only shows them.
/// </summary>
public sealed class TestAccounts(IConfiguration configuration) : ISingletonDependency
{
    public const string Section = "Guard:SignIn:TestAccounts";

    public IReadOnlyList<TestAccountDto> List() =>
        [.. configuration.GetSection(Section).GetChildren()
            .Select(a => new TestAccountDto(a["Username"]?.Trim() ?? "", a["Password"] ?? "", a["Note"] is { Length: > 0 } note ? note : null))
            .Where(a => a.Username.Length > 0 && a.Password.Length > 0)];
}
