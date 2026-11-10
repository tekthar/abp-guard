using Microsoft.Extensions.Configuration;
using Npgsql;

namespace AbpGuard;

/// <summary>
/// A lock every server of a site shares, so one server at a time does some work: a directory's sync, the
/// sync schedule's round. The default is a Postgres advisory lock on a connection of its own; a host may give its own
///. A server that stops releases its locks with its connections.
/// </summary>
public interface IGuardLocks
{
    /// <summary>The lock, or null when another server holds it now (a worker's round skips this time).</summary>
    Task<IAsyncDisposable?> TryTakeAsync(string name, CancellationToken cancellationToken);

    /// <summary>The lock once no other server holds it (work a person asked for waits its turn); cancelling stops the wait.</summary>
    Task<IAsyncDisposable> TakeAsync(string name, CancellationToken cancellationToken);
}

/// <summary>
/// The default locks: <c>pg_advisory_lock</c> on Guard's database, named "guard:{name}". Without a connection string (a
/// test host) every lock is granted: one process is a cluster of one.
/// </summary>
public sealed class PostgresGuardLocks(IConfiguration configuration) : IGuardLocks
{
    private readonly string? _connectionString = Data.GuardConnection.Of(configuration);

    public async Task<IAsyncDisposable?> TryTakeAsync(string name, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(_connectionString))
        {
            return Granted.Instance;
        }

        NpgsqlConnection connection = new(_connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            await using NpgsqlCommand take = new("SELECT pg_try_advisory_lock(hashtextextended(@name, 0))", connection);
            take.Parameters.AddWithValue("name", "guard:" + name);
            if (await take.ExecuteScalarAsync(cancellationToken) is true)
            {
                return new Held(connection, name);
            }
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }

        await connection.DisposeAsync();
        return null;
    }

    public async Task<IAsyncDisposable> TakeAsync(string name, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(_connectionString))
        {
            return Granted.Instance;
        }

        NpgsqlConnection connection = new(_connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            // No command timeout: the wait lasts as long as the other server's work, and the token ends it.
            await using NpgsqlCommand take = new("SELECT pg_advisory_lock(hashtextextended(@name, 0))", connection) { CommandTimeout = 0 };
            take.Parameters.AddWithValue("name", "guard:" + name);
            await take.ExecuteNonQueryAsync(cancellationToken);
            return new Held(connection, name);
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    private sealed class Held(NpgsqlConnection connection, string name) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            try
            {
                // Released before the connection goes back to the pool, which keeps its session.
                await using NpgsqlCommand release = new("SELECT pg_advisory_unlock(hashtextextended(@name, 0))", connection);
                release.Parameters.AddWithValue("name", "guard:" + name);
                await release.ExecuteScalarAsync();
            }
            finally
            {
                await connection.DisposeAsync();
            }
        }
    }

    private sealed class Granted : IAsyncDisposable
    {
        public static readonly Granted Instance = new();

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
