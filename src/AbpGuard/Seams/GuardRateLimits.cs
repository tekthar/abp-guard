using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace AbpGuard;

/// <summary>
/// Hits counted per key over a sliding window for the whole site: what Guard's limits count with (signing in,
/// self-service, second-factor codes), so every server counts the same and a lockout on one is a lockout on all. A
/// host may give its own. A window is at most a day.
/// </summary>
public interface IGuardRateLimits
{
    /// <summary>
    /// Counts a hit for the key unless it already has <paramref name="max"/> within the window; whether it was counted.
    /// To have several limits all count an attempt, take from each before combining them.
    /// </summary>
    Task<bool> TryTakeAsync(string key, int max, TimeSpan window, CancellationToken cancellationToken = default);

    /// <summary>Counts a hit for the key, however many it has.</summary>
    Task AddAsync(string key, CancellationToken cancellationToken = default);

    /// <summary>The key's hits within the window, without counting another.</summary>
    Task<int> CountAsync(string key, TimeSpan window, CancellationToken cancellationToken = default);

    /// <summary>Forgets the key's hits.</summary>
    Task ResetAsync(string key, CancellationToken cancellationToken = default);
}

/// <summary>
/// The default limits: rows in <c>guard.rate_limits</c> (unlogged, made on first use), one per hit, stamped with the
/// database's clock, keys kept as their SHA-256; a key's count is its rows within the window. A key's old hits go when
/// it's counted again, and now and then everyone's. Without a connection string (a test host) hits are counted in
/// memory: one process is a site of one.
/// </summary>
public sealed class PostgresGuardRateLimits(IConfiguration configuration) : IGuardRateLimits
{
    /// <summary>The longest window a limit may have; older hits are swept.</summary>
    public static readonly TimeSpan LongestWindow = TimeSpan.FromDays(1);

    private const string CreateTableSql = """
        CREATE SCHEMA IF NOT EXISTS guard;
        CREATE UNLOGGED TABLE IF NOT EXISTS guard.rate_limits ("KeyHash" bytea NOT NULL, "At" timestamptz NOT NULL);
        CREATE INDEX IF NOT EXISTS "IX_rate_limits_KeyHash_At" ON guard.rate_limits ("KeyHash", "At");
        """;

    private readonly string? _connectionString = Data.GuardConnection.Of(configuration);
    private readonly InMemoryWindows _memory = new();
    private volatile bool _made;

    public async Task<bool> TryTakeAsync(string key, int max, TimeSpan window, CancellationToken cancellationToken = default)
    {
        Check(window);
        if (string.IsNullOrEmpty(_connectionString))
        {
            return _memory.TryTake(key, max, window, DateTime.UtcNow);
        }

        byte[] hash = Hash(key);
        await using NpgsqlConnection connection = await OpenAsync(cancellationToken);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using NpgsqlBatch batch = new(connection, transaction)
        {
            BatchCommands =
            {
                // Two servers taking the last hit at once can't both have it: the key is locked while it's counted.
                new NpgsqlBatchCommand("SELECT pg_advisory_xact_lock(hashtextextended('guard:limit:' || encode($1, 'hex'), 0))")
                {
                    Parameters = { new NpgsqlParameter { Value = hash } },
                },
                new NpgsqlBatchCommand("""
                    INSERT INTO guard.rate_limits ("KeyHash", "At")
                    SELECT $1, now() WHERE (SELECT count(*) FROM guard.rate_limits WHERE "KeyHash" = $1 AND "At" > now() - $2) < $3
                    """)
                {
                    Parameters = { new NpgsqlParameter { Value = hash }, new NpgsqlParameter { Value = window }, new NpgsqlParameter { Value = max } },
                },
            },
        };
        await batch.ExecuteNonQueryAsync(cancellationToken);
        bool taken = batch.BatchCommands[1].RecordsAffected == 1;
        await transaction.CommitAsync(cancellationToken);
        await SweepNowAndThenAsync(connection, hash, cancellationToken);
        return taken;
    }

    public async Task AddAsync(string key, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(_connectionString))
        {
            _memory.Add(key, DateTime.UtcNow);
            return;
        }

        byte[] hash = Hash(key);
        await using NpgsqlConnection connection = await OpenAsync(cancellationToken);
        await using NpgsqlCommand add = new("""INSERT INTO guard.rate_limits ("KeyHash", "At") VALUES ($1, now())""", connection)
        {
            Parameters = { new NpgsqlParameter { Value = hash } },
        };
        await add.ExecuteNonQueryAsync(cancellationToken);
        await SweepNowAndThenAsync(connection, hash, cancellationToken);
    }

    public async Task<int> CountAsync(string key, TimeSpan window, CancellationToken cancellationToken = default)
    {
        Check(window);
        if (string.IsNullOrEmpty(_connectionString))
        {
            return _memory.Count(key, window, DateTime.UtcNow);
        }

        await using NpgsqlConnection connection = await OpenAsync(cancellationToken);
        await using NpgsqlCommand count = new("""SELECT count(*) FROM guard.rate_limits WHERE "KeyHash" = $1 AND "At" > now() - $2""", connection)
        {
            Parameters = { new NpgsqlParameter { Value = Hash(key) }, new NpgsqlParameter { Value = window } },
        };
        return Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture);
    }

    public async Task ResetAsync(string key, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(_connectionString))
        {
            _memory.Reset(key);
            return;
        }

        await using NpgsqlConnection connection = await OpenAsync(cancellationToken);
        await using NpgsqlCommand reset = new("""DELETE FROM guard.rate_limits WHERE "KeyHash" = $1""", connection)
        {
            Parameters = { new NpgsqlParameter { Value = Hash(key) } },
        };
        await reset.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task<NpgsqlConnection> OpenAsync(CancellationToken cancellationToken)
    {
        NpgsqlConnection connection = new(_connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);
            if (!_made)
            {
                await using NpgsqlCommand make = new(CreateTableSql, connection);
                await make.ExecuteNonQueryAsync(cancellationToken);
                _made = true;
            }

            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    /// <summary>Drops this key's hits older than any window, and about once in a hundred writes everyone's.</summary>
    private static async Task SweepNowAndThenAsync(NpgsqlConnection connection, byte[] hash, CancellationToken cancellationToken)
    {
        bool everyone = Random.Shared.Next(100) == 0;
        await using NpgsqlCommand sweep = new(
            everyone ? """DELETE FROM guard.rate_limits WHERE "At" < now() - $1"""
                     : """DELETE FROM guard.rate_limits WHERE "KeyHash" = $2 AND "At" < now() - $1""", connection)
        {
            Parameters = { new NpgsqlParameter { Value = LongestWindow }, new NpgsqlParameter { Value = hash } },
        };
        await sweep.ExecuteNonQueryAsync(cancellationToken);
    }

    private static byte[] Hash(string key) => SHA256.HashData(Encoding.UTF8.GetBytes(key));

    private static void Check(TimeSpan window)
    {
        if (window <= TimeSpan.Zero || window > LongestWindow)
        {
            throw new ArgumentOutOfRangeException(nameof(window), window, $"A limit's window is between zero and {LongestWindow}.");
        }
    }

    /// <summary>Hits per key over a sliding window, in memory: safe across threads, a key's old hits dropped as it's counted.</summary>
    private sealed class InMemoryWindows
    {
        private readonly ConcurrentDictionary<string, List<DateTime>> _hits = new();

        public bool TryTake(string key, int max, TimeSpan window, DateTime now)
        {
            List<DateTime> hits = _hits.GetOrAdd(key, _ => []);
            lock (hits)
            {
                hits.RemoveAll(t => now - t > LongestWindow);
                if (hits.Count(t => now - t <= window) >= max)
                {
                    return false;
                }

                hits.Add(now);
                return true;
            }
        }

        public void Add(string key, DateTime now)
        {
            List<DateTime> hits = _hits.GetOrAdd(key, _ => []);
            lock (hits)
            {
                hits.Add(now);
            }
        }

        public int Count(string key, TimeSpan window, DateTime now)
        {
            if (!_hits.TryGetValue(key, out List<DateTime>? hits))
            {
                return 0;
            }

            lock (hits)
            {
                return hits.Count(t => now - t <= window);
            }
        }

        public void Reset(string key) => _hits.TryRemove(key, out _);
    }
}
