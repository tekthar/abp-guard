using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Npgsql;

namespace AbpGuard.Services;

/// <summary>
/// Sign-in's token signing and encryption keys, the same on every node and after every restart, so tokens
/// stay valid. Taken, in order, from:
/// <list type="number">
/// <item>certificates named in configuration (<c>Guard:Oidc:SigningCertificate</c>, <c>Guard:Oidc:EncryptionCertificate</c>:
/// a <c>Path</c> to a .pfx and its <c>Password</c>), which is what production should use;</item>
/// <item>a folder named in configuration (<c>Guard:Oidc:KeysPath</c>), for keys mounted from a secret store as files;</item>
/// <item>Postgres (<c>guard.oidc_keys</c>, made here before migrations run, since keys are needed first): made once by
/// whichever node gets there first, from the key files of before (<c>{DataRoot}/oidc-keys</c>) when they're there.</item>
/// </list>
/// </summary>
public static class OidcKeys
{
    // One node makes the keys: an id of Guard's own (2).
    private const long KeysLock = 0x4D534152_00000002;

    public static (SecurityKey Signing, SecurityKey Encryption) Resolve(IConfiguration configuration, string dataRoot)
    {
        SecurityKey? signing = Certificate(configuration, "Guard:Oidc:SigningCertificate");
        SecurityKey? encryption = Certificate(configuration, "Guard:Oidc:EncryptionCertificate");
        if (signing is not null && encryption is not null)
        {
            return (signing, encryption);
        }

        (string SigningPem, string EncryptionKey) stored = configuration["Guard:Oidc:KeysPath"] is { Length: > 0 } folder
            ? FromFolder(Path.GetFullPath(folder))
            : Data.GuardConnection.Of(configuration) is { Length: > 0 } connectionString
                ? FromDatabase(connectionString, Path.Combine(dataRoot, "oidc-keys"))
                : FromFolder(Path.Combine(dataRoot, "oidc-keys"));
        return (signing ?? Signing(stored.SigningPem), encryption ?? Encryption(stored.EncryptionKey));
    }

    /// <summary>The keys kept in a folder (made there when they aren't), as before.</summary>
    public static (string SigningPem, string EncryptionKey) FromFolder(string folder)
    {
        Directory.CreateDirectory(folder);
        string signingPath = Path.Combine(folder, "signing.pem");
        string encryptionPath = Path.Combine(folder, "encryption.key");
        if (!File.Exists(signingPath))
        {
            using RSA rsa = RSA.Create(2048);
            File.WriteAllText(signingPath, rsa.ExportRSAPrivateKeyPem());
        }

        if (!File.Exists(encryptionPath))
        {
            File.WriteAllText(encryptionPath, Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        }

        return (File.ReadAllText(signingPath), File.ReadAllText(encryptionPath).Trim());
    }

    /// <summary>The keys in Postgres, made once under a lock: from the old key files when they're there, else new.</summary>
    private static (string SigningPem, string EncryptionKey) FromDatabase(string connectionString, string legacyFolder)
    {
        using NpgsqlConnection connection = KeyDatabase.Open(connectionString);
        using NpgsqlTransaction transaction = connection.BeginTransaction();
        Execute(connection, transaction, $"SELECT pg_advisory_xact_lock({KeysLock})");
        Execute(connection, transaction, """
            CREATE SCHEMA IF NOT EXISTS guard;
            CREATE TABLE IF NOT EXISTS guard.oidc_keys (
                name text PRIMARY KEY,
                value text NOT NULL,
                created_at timestamptz NOT NULL DEFAULT now());
            """);
        Dictionary<string, string> keys = [];
        using (NpgsqlCommand read = new("SELECT name, value FROM guard.oidc_keys", connection, transaction))
        using (NpgsqlDataReader rows = read.ExecuteReader())
        {
            while (rows.Read())
            {
                keys[rows.GetString(0)] = rows.GetString(1);
            }
        }

        if (!keys.ContainsKey("signing") || !keys.ContainsKey("encryption"))
        {
            (string pem, string key) = File.Exists(Path.Combine(legacyFolder, "signing.pem")) && File.Exists(Path.Combine(legacyFolder, "encryption.key"))
                ? (File.ReadAllText(Path.Combine(legacyFolder, "signing.pem")), File.ReadAllText(Path.Combine(legacyFolder, "encryption.key")).Trim())
                : New();
            foreach ((string name, string value) in new[] { ("signing", pem), ("encryption", key) })
            {
                using NpgsqlCommand insert = new("INSERT INTO guard.oidc_keys (name, value) VALUES (@name, @value) ON CONFLICT (name) DO NOTHING", connection, transaction);
                insert.Parameters.AddWithValue("name", name);
                insert.Parameters.AddWithValue("value", value);
                insert.ExecuteNonQuery();
                keys.TryAdd(name, value);
            }
        }

        transaction.Commit();
        return (keys["signing"], keys["encryption"]);
    }

    private static (string SigningPem, string EncryptionKey) New()
    {
        using RSA rsa = RSA.Create(2048);
        return (rsa.ExportRSAPrivateKeyPem(), Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
    }

    private static RsaSecurityKey Signing(string pem)
    {
        RSA rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return new RsaSecurityKey(rsa) { KeyId = Convert.ToHexString(SHA256.HashData(rsa.ExportRSAPublicKey()))[..16] };
    }

    private static SymmetricSecurityKey Encryption(string base64)
    {
        byte[] key = Convert.FromBase64String(base64);
        return new SymmetricSecurityKey(key) { KeyId = Convert.ToHexString(SHA256.HashData(key))[..16] };
    }

    /// <summary>A certificate named in configuration (<c>{section}:Path</c> and <c>:Password</c>), or null when none is.</summary>
    private static X509SecurityKey? Certificate(IConfiguration configuration, string section)
    {
        if (configuration[$"{section}:Path"] is not { Length: > 0 } path)
        {
            return null;
        }

        X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12FromFile(path, configuration[$"{section}:Password"]);
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException($"{section}: the certificate at {path} has no private key.");
        }

        return new X509SecurityKey(certificate);
    }

    private static void Execute(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql)
    {
        using NpgsqlCommand command = new(sql, connection, transaction);
        command.ExecuteNonQuery();
    }
}
