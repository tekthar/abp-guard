using Microsoft.EntityFrameworkCore;
using AbpGuard.Data;
using AbpGuard.Services;
using Xunit;

namespace AbpGuard.Tests;

/// <summary>
/// Who has an address, as Postgres runs it: the directory's address matched without regard to case (ILIKE, its
/// wildcards escaped), a verified one of the account's own by its normalized form. Only translated, no database.
/// </summary>
public class AddressQueryTests
{
    [Fact]
    public void An_address_matches_the_directorys_in_any_case_and_a_verified_one_as_normalized()
    {
        using GuardDbContext db = new(new DbContextOptionsBuilder<GuardDbContext>().UseNpgsql("Host=localhost;Database=none").Options);
        string sql = Addresses.WithAddress(db, "first_last@example.com").ToQueryString();
        Assert.Contains("ILIKE", sql);
        Assert.Contains(@"'first\_last@example.com'", sql);
        Assert.Contains("'first_last@example.com'", sql);
    }
}
