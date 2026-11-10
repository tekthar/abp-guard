using Microsoft.Extensions.Configuration;
using AbpGuard.Services;

namespace AbpGuard.Tests;

/// <summary>The accounts a test site shows on its sign-in page: none unless the server's settings list them.</summary>
public class TestAccountsTests
{
    private static TestAccounts From(Dictionary<string, string?> settings) =>
        new(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());

    [Fact]
    public void A_site_shows_none_unless_its_settings_list_them() => Assert.Empty(From([]).List());

    [Fact]
    public void Each_listed_account_is_shown_with_its_password_and_note_and_half_ones_are_left_out()
    {
        IReadOnlyList<TestAccountDto> shown = From(new()
        {
            ["Guard:SignIn:TestAccounts:0:Username"] = " tester ",
            ["Guard:SignIn:TestAccounts:0:Password"] = "Test-Pass-1",
            ["Guard:SignIn:TestAccounts:0:Note"] = "An agent",
            ["Guard:SignIn:TestAccounts:1:Username"] = "viewer",
            ["Guard:SignIn:TestAccounts:1:Password"] = "Test-Pass-2",
            ["Guard:SignIn:TestAccounts:2:Username"] = "no-password",
        }).List();

        Assert.Equal([new TestAccountDto("tester", "Test-Pass-1", "An agent"), new TestAccountDto("viewer", "Test-Pass-2", null)], shown);
    }
}
