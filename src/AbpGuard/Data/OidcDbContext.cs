using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace AbpGuard.Data;

/// <summary>
/// OpenIddict's applications, authorizations, scopes and tokens, in guard's schema. A plain EF Core
/// context, separate from GuardDbContext, because OpenIddict manages its own units of work.
/// </summary>
public class OidcDbContext(DbContextOptions<OidcDbContext> options) : DbContext(options)
{
    public const string HistoryTable = "__EFMigrationsHistory_oidc";

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.HasDefaultSchema(GuardDbContext.Schema);
        builder.UseOpenIddict<Guid>();

        foreach (var entity in builder.Model.GetEntityTypes())
        {
            string? table = entity.GetTableName();
            if (table is not null && table.StartsWith("OpenIddict", StringComparison.Ordinal))
            {
                // OpenIddictApplications -> oidc_applications
                entity.SetTableName("oidc_" + table["OpenIddict".Length..].ToLowerInvariant());
            }
        }
    }
}

/// <summary>For `dotnet ef migrations add` only.</summary>
public class OidcDbContextFactory : IDesignTimeDbContextFactory<OidcDbContext>
{
    public OidcDbContext CreateDbContext(string[] args)
    {
        DbContextOptionsBuilder<OidcDbContext> builder = new();
        builder.UseNpgsql(DesignTime.ConnectionString, b => b.MigrationsHistoryTable(OidcDbContext.HistoryTable, GuardDbContext.Schema));
        builder.UseOpenIddict<Guid>();
        return new OidcDbContext(builder.Options);
    }
}
