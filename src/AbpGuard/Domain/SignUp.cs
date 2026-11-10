using Volo.Abp.Domain.Entities;

namespace AbpGuard.Domain;

/// <summary>
/// Sign-up, one row for the site: off by default; when on, people create their own accounts in an internal
/// directory the admin names, optionally only with an email in some domains. An account is active once its email is
/// verified.
/// </summary>
public class SignUpSettings : Entity<Guid>
{
    public static readonly Guid SiteId = Guid.Parse("00000000-0000-0000-0000-00000000c001");

    protected SignUpSettings()
    {
    }

    public SignUpSettings(Guid id) : base(id)
    {
    }

    public bool Enabled { get; set; }
    public Guid? DirectoryId { get; set; }
    public List<string> EmailDomains { get; set; } = [];
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
