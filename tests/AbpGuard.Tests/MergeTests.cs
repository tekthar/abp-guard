using AbpGuard.Domain;
using AbpGuard.Services;

namespace AbpGuard.Tests;

/// <summary>Addresses as matched, and merged accounts staying where they went.</summary>
public class MergeTests
{
    private static readonly UserDirectory Corp = new(Guid.NewGuid(), "Corp", "ldap", order: 1);

    [Theory]
    [InlineData("  Jane.Left@Example.TEST ", "jane.left@example.test")]
    [InlineData("pat@example.test", "pat@example.test")]
    public void Addresses_are_compared_trimmed_and_in_lower_case(string given, string expected) =>
        Assert.Equal(expected, Addresses.Normalize(given));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not an address")]
    [InlineData("nobody@")]
    [InlineData("@example.test")]
    public void Anything_else_is_no_address(string? given) => Assert.Null(Addresses.Normalize(given));

    [Fact]
    public void An_address_longer_than_mail_allows_is_refused() =>
        Assert.Null(Addresses.Normalize(new string('a', 250) + "@example.test"));

    [Fact]
    public void A_directory_that_still_reports_a_merged_account_never_brings_it_back()
    {
        DirectoryUser record = new(Guid.NewGuid(), Corp.Id, "corp:jdoe", "jdoe") { IsActive = true, Email = "jdoe@corp.test" };
        Account merged = new(Guid.NewGuid(), "jdoe") { MergedIntoId = Guid.NewGuid(), Status = AccountStatus.Inactive, StatusReason = "Merged into jsmith" };

        AccountProjector.Apply(merged, record, Corp);

        Assert.Equal(AccountStatus.Inactive, merged.Status);
        Assert.Equal("Merged into jsmith", merged.StatusReason);
        Assert.Equal("jdoe@corp.test", merged.Email); // what the directory says is still shown
    }

    [Fact]
    public void An_account_that_wasnt_merged_follows_its_directory()
    {
        DirectoryUser record = new(Guid.NewGuid(), Corp.Id, "corp:jsmith", "jsmith") { IsActive = true };
        Account account = new(Guid.NewGuid(), "jsmith") { Status = AccountStatus.Inactive };

        AccountProjector.Apply(account, record, Corp);

        Assert.Equal(AccountStatus.Active, account.Status);
        Assert.Null(account.StatusReason);
    }

    [Fact]
    public void Mail_goes_to_the_chosen_address_else_the_directorys()
    {
        Account account = new(Guid.NewGuid(), "jsmith") { Email = "jsmith@corp.test" };
        Assert.Equal("jsmith@corp.test", account.MailAddress);
        account.MailTo = "john@home.test";
        Assert.Equal("john@home.test", account.MailAddress);
    }
}
