using Npgsql;

namespace AbpGuard;

/// <summary>
/// A connection for the key stores. They're read before migrations run, so on a new database they're the
/// first to reach Postgres: they make the database when it isn't there yet, as the migrations would have.
/// Guard's own copy of the platform's, for the sign-in keys in guard.oidc_keys.
/// </summary>
internal static class KeyDatabase
{
    public static NpgsqlConnection Open(string connectionString)
    {
        NpgsqlConnection connection = new(connectionString);
        try
        {
            connection.Open();
            return connection;
        }
        catch (PostgresException e) when (e.SqlState == PostgresErrorCodes.InvalidCatalogName)
        {
            connection.Dispose();
        }

        string database = new NpgsqlConnectionStringBuilder(connectionString).Database!;
        NpgsqlConnectionStringBuilder maintenance = new(connectionString) { Database = "postgres", Pooling = false };
        using (NpgsqlConnection server = new(maintenance.ConnectionString))
        {
            server.Open();
            using NpgsqlCommand create = new($"CREATE DATABASE \"{database.Replace("\"", "\"\"")}\"", server);
            try
            {
                create.ExecuteNonQuery();
            }
            catch (PostgresException e) when (e.SqlState == PostgresErrorCodes.DuplicateDatabase)
            {
                // Another node made it first.
            }
        }

        NpgsqlConnection created = new(connectionString);
        created.Open();
        return created;
    }
}
