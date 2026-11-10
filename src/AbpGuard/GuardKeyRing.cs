using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;

namespace AbpGuard;

/// <summary>
/// Guard keeps what it protects with the host's Data Protection key ring: the authenticator apps'
/// secrets, directories' passwords, the links it mails, sessions' anti-forgery values. A ring that isn't kept somewhere
/// every server and every restart reads (Guard keeps it in Postgres) loses all of them, so Guard checks at start.
/// </summary>
public static class GuardKeyRing
{
    /// <summary>
    /// Why the key ring isn't persisted, or null when it is: keys held in memory only, or in the per-user folder Data
    /// Protection falls back to when the host chose nothing (gone with the container, and not shared by other servers).
    /// </summary>
    public static string? Problem(KeyManagementOptions options) => options.XmlRepository switch
    {
        // Nothing chosen: Data Protection falls back to the per-user folder, or to memory where there's none.
        null => "the host keeps the Data Protection key ring nowhere it chose (no PersistKeysTo… or XmlRepository), so it falls back to a per-user folder or to memory",
        { } repository when repository.GetType().Name.Contains("Ephemeral", StringComparison.Ordinal) =>
            "the Data Protection key ring is kept in memory only, so every restart forgets the keys",
        FileSystemXmlRepository files when FileSystemXmlRepository.DefaultKeyStorageDirectory is { } fallback
            && string.Equals(Path.GetFullPath(files.Directory.FullName).TrimEnd(Path.DirectorySeparatorChar),
                Path.GetFullPath(fallback.FullName).TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase) =>
            $"the Data Protection key ring is in the per-user fallback folder ({fallback.FullName}), which a container loses and other servers don't share",
        _ => null,
    };
}
