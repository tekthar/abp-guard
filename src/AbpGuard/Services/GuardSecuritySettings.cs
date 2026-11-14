using AbpGuard.Data;
using AbpGuard.Domain;
using Microsoft.EntityFrameworkCore;

namespace AbpGuard.Services;

/// <summary>The site's security settings: the one row, made with its defaults the first time it's read.</summary>
public static class GuardSecuritySettings
{
    public static async Task<SecuritySettings> LoadAsync(GuardDbContext db, CancellationToken cancellationToken)
    {
        SecuritySettings? settings = await db.SecuritySettings.FirstOrDefaultAsync(s => s.Id == SecuritySettings.SingletonId, cancellationToken);
        if (settings is null)
        {
            settings = new SecuritySettings(SecuritySettings.SingletonId);
            db.SecuritySettings.Add(settings);
            await db.SaveChangesAsync(cancellationToken);
        }

        return settings;
    }
}
