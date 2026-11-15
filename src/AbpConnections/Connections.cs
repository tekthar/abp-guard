using Microsoft.EntityFrameworkCore;
using Volo.Abp.Domain.Entities;
using Volo.Abp.EntityFrameworkCore;

namespace AbpConnections;

/// <summary>Where a connection stands: ready, waiting for an OAuth sign-in, or failing its last test or refresh.</summary>
public static class ConnectionStatus
{
    public const string Ready = "ready";
    public const string NeedsSignIn = "needs-sign-in";
    public const string Failing = "failing";
}

/// <summary>
/// An outside system the application talks to: a type, the site or a scope of the application's (a project), plain
/// settings, encrypted secrets and, once it has signed in with OAuth, encrypted tokens and the outside account they're for.
/// </summary>
public class Connection : Entity<Guid>
{
    protected Connection()
    {
    }

    public Connection(Guid id, string name, string type, Guid? scopeId, Guid createdBy) : base(id)
    {
        Name = name;
        Type = type;
        ScopeId = scopeId;
        CreatedBy = createdBy;
        CreatedAt = UpdatedAt = DateTime.UtcNow;
    }

    public string Name { get; set; } = null!;
    public string Type { get; private set; } = null!;

    /// <summary>The scope it belongs to (a project); null for the site's.</summary>
    public Guid? ScopeId { get; private set; }

    public string SettingsJson { get; set; } = "{}";

    /// <summary>The secrets, as one protected JSON object.</summary>
    public string? ProtectedSecrets { get; set; }

    /// <summary>The OAuth tokens (access, refresh, expiry), as one protected JSON object.</summary>
    public string? ProtectedTokens { get; set; }

    /// <summary>The outside account it signed in as, or reached in its last test.</summary>
    public string? Account { get; set; }

    public DateTime? ConnectedAt { get; set; }
    public string Status { get; set; } = ConnectionStatus.Ready;
    public DateTime? LastTestedAt { get; set; }
    public string? LastError { get; set; }
    public Guid CreatedBy { get; private set; }
    public DateTime CreatedAt { get; private set; }
    public DateTime UpdatedAt { get; set; }

    /// <summary>
    /// Each person signs in with their own outside account, instead of one sign-in for everyone: their tokens are theirs
    /// (<see cref="ConnectionAccount"/>), and what uses it for a person uses theirs.
    /// </summary>
    public bool EachPerson { get; set; }

    /// <summary>
    /// What its sign-in found or was given before the first one: an authorization server's endpoints and the client
    /// registered there, as one protected JSON object. Found again when its address changes.
    /// </summary>
    public string? ProtectedSignIn { get; set; }
}

/// <summary>
/// One person's own sign-in to a connection each person signs in to: their tokens, encrypted as a connection's are, and
/// the outside account they're for. Theirs alone: they sign out when they like, and nobody sees the tokens.
/// </summary>
public class ConnectionAccount : Entity
{
    protected ConnectionAccount()
    {
    }

    public ConnectionAccount(Guid connectionId, Guid accountId)
    {
        ConnectionId = connectionId;
        AccountId = accountId;
    }

    public Guid ConnectionId { get; private set; }
    public Guid AccountId { get; private set; }

    /// <summary>The OAuth tokens (access, refresh, expiry), as one protected JSON object.</summary>
    public string ProtectedTokens { get; set; } = "";

    /// <summary>The outside account they signed in as, when the provider says.</summary>
    public string? Account { get; set; }

    public DateTime ConnectedAt { get; set; }

    public override object[] GetKeys() => [ConnectionId, AccountId];
}

/// <summary>
/// The connections' tables, in the application's own context: the context implements this, maps them with
/// <see cref="ConnectionsModel.ConfigureConnections"/>, and stands in for it (<c>ReplaceDbContext</c>).
/// </summary>
public interface IConnectionsDbContext : IEfCoreDbContext
{
    DbSet<Connection> Connections { get; }

    DbSet<ConnectionAccount> ConnectionAccounts { get; }
}

public static class ConnectionsModel
{
    /// <summary>
    /// Maps <c>connections</c> and <c>connection_accounts</c> in <paramref name="schema"/> (the context's default when
    /// null). <paramref name="scopeColumn"/> names the column a connection's scope is kept in, so a table made before
    /// keeps its own.
    /// </summary>
    public static ModelBuilder ConfigureConnections(this ModelBuilder builder, string? schema = null, string scopeColumn = "ScopeId")
    {
        builder.Entity<Connection>(b =>
        {
            b.ToTable("connections", schema);
            b.Property(c => c.Name).HasMaxLength(200).IsRequired();
            b.Property(c => c.Type).HasMaxLength(200).IsRequired();
            b.Property(c => c.ScopeId).HasColumnName(scopeColumn);
            b.Property(c => c.SettingsJson).HasColumnType("jsonb").IsRequired();
            b.Property(c => c.Account).HasMaxLength(320);
            b.Property(c => c.Status).HasMaxLength(32).IsRequired();
            b.HasIndex(c => new { c.ScopeId, c.Type });
        });

        builder.Entity<ConnectionAccount>(b =>
        {
            // Each person's own sign-in to a connection each person signs in to.
            b.ToTable("connection_accounts", schema);
            b.HasKey(a => new { a.ConnectionId, a.AccountId });
            b.Property(a => a.ProtectedTokens).IsRequired();
            b.Property(a => a.Account).HasMaxLength(320);
            b.HasIndex(a => a.AccountId);
        });
        return builder;
    }
}
