using AbpGuard.Domain;
using AbpGuard.Services;

namespace AbpGuard.Tests;

/// <summary>Directory precedence: the first active directory (lowest Order) that knows a username owns the account.</summary>
public class PrecedenceTests
{
    private static readonly UserDirectory Internal = new(Guid.NewGuid(), "Internal", "internal", order: 0);
    private static readonly UserDirectory Corp = new(Guid.NewGuid(), "Corp", "ldap", order: 1);
    private static readonly UserDirectory Partners = new(Guid.NewGuid(), "Partners", "ldap", order: 2);

    private static DirectoryUser User(UserDirectory directory, string username, bool active = true) =>
        new(Guid.NewGuid(), directory.Id, $"{directory.Name}:{username}", username) { IsActive = active };

    [Fact]
    public void Earlier_directory_owns_the_username()
    {
        DirectoryUser corp = User(Corp, "jsmith");
        DirectoryUser partner = User(Partners, "JSmith");

        var owners = AccountProjector.ResolveOwners([Internal, Corp, Partners], [partner, corp]);

        Assert.Single(owners);
        Assert.Same(corp, owners["jsmith"]);
    }

    [Fact]
    public void Reordering_directories_changes_the_owner()
    {
        DirectoryUser corp = User(Corp, "jsmith");
        DirectoryUser partner = User(Partners, "jsmith");
        UserDirectory partnersFirst = new(Partners.Id, "Partners", "ldap", order: 1);
        UserDirectory corpSecond = new(Corp.Id, "Corp", "ldap", order: 2);

        var owners = AccountProjector.ResolveOwners([partnersFirst, corpSecond], [corp, partner]);

        Assert.Same(partner, owners["jsmith"]);
    }

    [Fact]
    public void Inactive_directories_are_skipped()
    {
        UserDirectory corpOff = new(Guid.NewGuid(), "Corp", "ldap", order: 1) { IsActive = false };
        DirectoryUser corp = new(Guid.NewGuid(), corpOff.Id, "c:jsmith", "jsmith");
        DirectoryUser partner = User(Partners, "jsmith");

        var owners = AccountProjector.ResolveOwners([corpOff, Partners], [corp, partner]);

        Assert.Same(partner, owners["jsmith"]);
    }

    [Fact]
    public void A_disabled_record_still_owns_the_username()
    {
        // Otherwise disabling jsmith in Corp would hand the account to whoever is "jsmith" in Partners.
        DirectoryUser disabled = User(Corp, "jsmith", active: false);
        DirectoryUser partner = User(Partners, "jsmith");

        var owners = AccountProjector.ResolveOwners([Corp, Partners], [partner, disabled]);

        Assert.Same(disabled, owners["jsmith"]);
    }
}
