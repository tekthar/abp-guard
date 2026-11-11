using Microsoft.EntityFrameworkCore;
using AbpGuard.Domain;
using Volo.Abp.Data;
using Volo.Abp.EntityFrameworkCore;
using Volo.Abp.EntityFrameworkCore.DistributedEvents;

namespace AbpGuard.Data;

// ConnectionStrings:Guard, else Default (ABP falls back to it): GuardConnection.
[ConnectionStringName(GuardConnection.Name)]
public class GuardDbContext(DbContextOptions<GuardDbContext> options) : AbpDbContext<GuardDbContext>(options), IHasEventOutbox
{
    public const string Schema = "guard";

    /// <summary>The events Guard publishes for others, written with the change and sent after it.</summary>
    public DbSet<OutgoingEventRecord> OutgoingEvents { get; set; } = null!;

    public DbSet<UserDirectory> Directories => Set<UserDirectory>();
    public DbSet<DirectoryUser> DirectoryUsers => Set<DirectoryUser>();
    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<Group> Groups => Set<Group>();
    public DbSet<GroupMembership> Memberships => Set<GroupMembership>();
    public DbSet<SyncRun> SyncRuns => Set<SyncRun>();
    public DbSet<SecurityEvent> SecurityEvents => Set<SecurityEvent>();
    public DbSet<SecuritySettings> SecuritySettings => Set<SecuritySettings>();
    public DbSet<PersonalAccessToken> PersonalAccessTokens => Set<PersonalAccessToken>();
    public DbSet<WebSession> WebSessions => Set<WebSession>();
    public DbSet<SessionHandoff> SessionHandoffs => Set<SessionHandoff>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<RoleRule> RoleRules => Set<RoleRule>();
    public DbSet<RoleGrant> RoleGrants => Set<RoleGrant>();
    public DbSet<SignUpSettings> SignUpSettings => Set<SignUpSettings>();
    public DbSet<PermissionStamp> PermissionStamps => Set<PermissionStamp>();
    public DbSet<AccountEmail> AccountEmails => Set<AccountEmail>();
    public DbSet<AccountMergeRecord> Merges => Set<AccountMergeRecord>();
    public DbSet<SecondFactor> SecondFactors => Set<SecondFactor>();
    public DbSet<RecoveryCode> RecoveryCodes => Set<RecoveryCode>();
    public DbSet<SignInTicket> SignInTickets => Set<SignInTicket>();
    public DbSet<SentCode> SentCodes => Set<SentCode>();
    public DbSet<PrivacyStoreRecord> PrivacyStores => Set<PrivacyStoreRecord>();
    public DbSet<PrivacySettings> PrivacySettings => Set<PrivacySettings>();
    public DbSet<LegalHold> LegalHolds => Set<LegalHold>();
    public DbSet<RetentionSettings> RetentionSettings => Set<RetentionSettings>();
    public DbSet<SecurityFeedSettings> SecurityFeeds => Set<SecurityFeedSettings>();
    public DbSet<SecurityAlertState> SecurityAlertStates => Set<SecurityAlertState>();
    public DbSet<PrivacyNoticeVersion> PrivacyNotices => Set<PrivacyNoticeVersion>();
    public DbSet<PrivacyAcceptance> PrivacyAcceptances => Set<PrivacyAcceptance>();
    public DbSet<ConsentWithdrawal> ConsentWithdrawals => Set<ConsentWithdrawal>();
    public DbSet<RetentionPeriod> RetentionPeriods => Set<RetentionPeriod>();
    public DbSet<PersonalDataErasureRecord> Erasures => Set<PersonalDataErasureRecord>();

    /// <summary>A map of names by language in a jsonb column, empty by default.</summary>
    private static void NamesMap(Microsoft.EntityFrameworkCore.Metadata.Builders.PropertyBuilder<Dictionary<string, string>> property)
    {
        System.Text.Json.JsonSerializerOptions json = new(System.Text.Json.JsonSerializerDefaults.Web);
        property.HasColumnType("jsonb").HasDefaultValueSql("'{}'::jsonb").HasConversion(
            v => System.Text.Json.JsonSerializer.Serialize(v, json),
            v => System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(v, json) ?? new(),
            new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<Dictionary<string, string>>(
                (a, b) => System.Text.Json.JsonSerializer.Serialize(a, json) == System.Text.Json.JsonSerializer.Serialize(b, json),
                v => System.Text.Json.JsonSerializer.Serialize(v, json).GetHashCode(),
                v => new Dictionary<string, string>(v)));
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        // Stored inside account_merges.Steps as JSON, never as entities of their own: ignored before ABP's base maps
        // every entity type found so far, or EF warns that MergeStep was mapped and then ignored.
        builder.Ignore<MergeStep>();
        builder.Ignore<MergeStepCount>();
        base.OnModelCreating(builder);
        builder.HasDefaultSchema(Schema);
        builder.ConfigureEventOutbox();

        builder.Entity<UserDirectory>(b =>
        {
            b.ToTable("directories");
            b.Property(x => x.Name).HasMaxLength(200).IsRequired();
            NamesMap(b.Property(x => x.Names));
            b.Property(x => x.Type).HasMaxLength(64).IsRequired();
            b.Property(x => x.SettingsJson).HasColumnType("jsonb");
            b.HasIndex(x => x.Order);
        });

        builder.Entity<DirectoryUser>(b =>
        {
            b.ToTable("directory_users");
            // Null until a connector says something about names by language.
            System.Text.Json.JsonSerializerOptions names = new(System.Text.Json.JsonSerializerDefaults.Web);
            b.Property(x => x.DisplayNames).HasColumnType("jsonb").HasConversion(
                v => v == null ? null : System.Text.Json.JsonSerializer.Serialize(v, names),
                v => v == null ? null : System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(v, names),
                new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<Dictionary<string, string>?>(
                    (a, b) => System.Text.Json.JsonSerializer.Serialize(a, names) == System.Text.Json.JsonSerializer.Serialize(b, names),
                    v => System.Text.Json.JsonSerializer.Serialize(v, names).GetHashCode(),
                    v => v == null ? null : new Dictionary<string, string>(v)));
            b.Property(x => x.ExternalId).HasMaxLength(256).IsRequired();
            b.Property(x => x.Username).HasMaxLength(256).IsRequired();
            b.Property(x => x.NormalizedUsername).HasMaxLength(256).IsRequired();
            b.HasIndex(x => new { x.DirectoryId, x.NormalizedUsername }).IsUnique();
            b.HasIndex(x => new { x.DirectoryId, x.ExternalId }).IsUnique();
            b.HasIndex(x => x.NormalizedUsername);
        });

        builder.Entity<Account>(b =>
        {
            // An agent's account is always a service account, so its kind can't come out wrong.
            b.ToTable("accounts", t => t.HasCheckConstraint("CK_accounts_agent_is_service", "NOT \"IsAgent\" OR \"IsService\""));
            b.Property(x => x.Username).HasMaxLength(256).IsRequired();
            b.Property(x => x.NormalizedUsername).HasMaxLength(256).IsRequired();
            b.Property(x => x.Status).HasConversion<string>().HasMaxLength(16);
            b.Property(x => x.Language).HasMaxLength(35);
            b.Property(x => x.TimeZone).HasMaxLength(64);
            b.Property(x => x.Motion).HasMaxLength(16);
            b.Property(x => x.MailTo).HasMaxLength(320);
            b.Property(x => x.Picture).HasMaxLength(AccountPictures.MaxLength);
            // The person's name in other languages, and their text for search.
            System.Text.Json.JsonSerializerOptions names = new(System.Text.Json.JsonSerializerDefaults.Web);
            b.Property(x => x.DisplayNames).HasColumnType("jsonb").HasDefaultValueSql("'{}'::jsonb").HasConversion(
                v => System.Text.Json.JsonSerializer.Serialize(v, names),
                v => System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(v, names) ?? new(),
                new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<Dictionary<string, string>>(
                    (a, b) => System.Text.Json.JsonSerializer.Serialize(a, names) == System.Text.Json.JsonSerializer.Serialize(b, names),
                    v => System.Text.Json.JsonSerializer.Serialize(v, names).GetHashCode(),
                    v => new Dictionary<string, string>(v)));
            b.Property(x => x.OtherNames).HasMaxLength(2048);
            b.Ignore(x => x.MailAddress);
            b.HasIndex(x => x.NormalizedUsername).IsUnique();
            b.HasIndex(x => x.MergedIntoId);
        });

        builder.Entity<AccountEmail>(b =>
        {
            b.ToTable("account_emails");
            b.Property(x => x.Email).HasMaxLength(320).IsRequired();
            b.Property(x => x.NormalizedEmail).HasMaxLength(320).IsRequired();
            b.Property(x => x.Source).HasMaxLength(16).IsRequired();
            b.HasIndex(x => new { x.AccountId, x.NormalizedEmail }).IsUnique();
            // A verified address belongs to one account; addresses waiting for their link don't hold it.
            b.HasIndex(x => x.NormalizedEmail, "IX_account_emails_verified").IsUnique().HasFilter("\"VerifiedAt\" IS NOT NULL");
        });

        builder.Entity<AccountMergeRecord>(b =>
        {
            b.ToTable("account_merges");
            b.Property(x => x.SourceUsername).HasMaxLength(256).IsRequired();
            b.Property(x => x.SourceDisplayName).HasMaxLength(256).IsRequired();
            b.Property(x => x.SourceEmail).HasMaxLength(320);
            b.Property(x => x.SurvivorUsername).HasMaxLength(256).IsRequired();
            b.Property(x => x.Reason).HasMaxLength(32).IsRequired();
            b.Property(x => x.State).HasMaxLength(16).IsRequired();
            System.Text.Json.JsonSerializerOptions json = new(System.Text.Json.JsonSerializerDefaults.Web);
            b.Property(x => x.Steps).HasColumnType("jsonb").HasConversion(
                v => System.Text.Json.JsonSerializer.Serialize(v, json),
                v => System.Text.Json.JsonSerializer.Deserialize<List<MergeStep>>(v, json) ?? new(),
                new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<List<MergeStep>>(
                    (a, b) => System.Text.Json.JsonSerializer.Serialize(a, json) == System.Text.Json.JsonSerializer.Serialize(b, json),
                    v => System.Text.Json.JsonSerializer.Serialize(v, json).GetHashCode(),
                    v => System.Text.Json.JsonSerializer.Deserialize<List<MergeStep>>(System.Text.Json.JsonSerializer.Serialize(v, json), json)!));
            b.HasIndex(x => x.SourceId);
            b.HasIndex(x => x.SurvivorId);
            b.HasIndex(x => x.StartedAt);
        });

        builder.Entity<Group>(b =>
        {
            b.ToTable("groups");
            b.Property(x => x.Name).HasMaxLength(256).IsRequired();
            NamesMap(b.Property(x => x.Names));
            b.Property(x => x.NormalizedName).HasMaxLength(256).IsRequired();
            b.Property(x => x.Kind).HasMaxLength(16).IsRequired().HasDefaultValue(GroupKinds.Standard);
            b.Property(x => x.TwoFactor).HasMaxLength(16).IsRequired().HasDefaultValue(TwoFactorModes.Off);
            System.Text.Json.JsonSerializerOptions json = new(System.Text.Json.JsonSerializerDefaults.Web);
            b.Property(x => x.Attributes).HasColumnType("jsonb").HasConversion(
                v => System.Text.Json.JsonSerializer.Serialize(v, json),
                v => System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(v, json) ?? new(),
                new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<Dictionary<string, string>>(
                    (a, b) => System.Text.Json.JsonSerializer.Serialize(a, json) == System.Text.Json.JsonSerializer.Serialize(b, json),
                    v => System.Text.Json.JsonSerializer.Serialize(v, json).GetHashCode(),
                    v => new Dictionary<string, string>(v)));
            b.Property(x => x.EmailDomains).HasColumnType("jsonb").HasConversion(
                v => System.Text.Json.JsonSerializer.Serialize(v, json),
                v => System.Text.Json.JsonSerializer.Deserialize<List<string>>(v, json) ?? new(),
                new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<List<string>>(
                    (a, b) => a!.SequenceEqual(b!),
                    v => string.Join(",", v).GetHashCode(),
                    v => v.ToList()));
            b.Ignore(x => x.Computed);
            b.HasIndex(x => new { x.DirectoryId, x.NormalizedName }).IsUnique();
            b.HasIndex(x => x.Kind);
        });

        builder.Entity<GroupMembership>(b =>
        {
            b.ToTable("memberships");
            b.Property(x => x.MemberType).HasConversion<string>().HasMaxLength(16);
            b.Property(x => x.Source).HasConversion<string>().HasMaxLength(16);
            b.HasIndex(x => new { x.GroupId, x.MemberType, x.MemberId, x.Source }).IsUnique();
            b.HasIndex(x => new { x.MemberType, x.MemberId });
        });

        builder.Entity<SyncRun>(b =>
        {
            b.ToTable("sync_runs");
            b.HasIndex(x => new { x.DirectoryId, x.StartedAt });
        });

        builder.Entity<Role>(b =>
        {
            b.ToTable("roles");
            b.Property(x => x.Key).HasMaxLength(64).IsRequired();
            b.Property(x => x.Name).HasMaxLength(200).IsRequired();
            NamesMap(b.Property(x => x.Names));
            NamesMap(b.Property(x => x.Descriptions));
            b.HasIndex(x => x.Key).IsUnique();
        });

        builder.Entity<RoleRule>(b =>
        {
            b.ToTable("role_rules");
            b.Property(x => x.Json).HasColumnType("jsonb").IsRequired();
            b.HasIndex(x => new { x.RoleId, x.Order });
        });

        builder.Entity<RoleGrant>(b =>
        {
            b.ToTable("role_grants");
            b.Property(x => x.PrincipalType).HasConversion<string>().HasMaxLength(16);
            b.Property(x => x.ScopeJson).HasColumnType("jsonb").IsRequired();
            b.Property(x => x.ScopeKey).HasMaxLength(128);
            b.HasIndex(x => new { x.PrincipalType, x.PrincipalId });
            b.HasIndex(x => x.ScopeKey);
            b.HasIndex(x => x.RoleId);
        });

        builder.Entity<PermissionStamp>(b =>
        {
            b.ToTable("permission_stamp");
            b.Property(x => x.Id).ValueGeneratedNever();
            b.HasData(new PermissionStamp { Id = PermissionStamp.RowId, Version = 0 });
        });

        builder.Entity<SignUpSettings>(b =>
        {
            b.ToTable("signup_settings");
            b.Property(x => x.Id).ValueGeneratedNever();
            System.Text.Json.JsonSerializerOptions json = new(System.Text.Json.JsonSerializerDefaults.Web);
            b.Property(x => x.EmailDomains).HasColumnType("jsonb").HasConversion(
                v => System.Text.Json.JsonSerializer.Serialize(v, json),
                v => System.Text.Json.JsonSerializer.Deserialize<List<string>>(v, json) ?? new(),
                new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<List<string>>(
                    (a, b) => a!.SequenceEqual(b!),
                    v => string.Join(",", v).GetHashCode(),
                    v => v.ToList()));
        });

        builder.Entity<SecurityEvent>(b =>
        {
            b.ToTable("security_events");
            b.Property(x => x.Type).HasMaxLength(64).IsRequired();
            b.Property(x => x.ActingMode).HasMaxLength(32);
            b.Property(x => x.TargetType).HasMaxLength(32);
            b.Property(x => x.TargetName).HasMaxLength(256);
            b.HasIndex(x => x.Time);
            b.HasIndex(x => x.AccountId);
            b.HasIndex(x => x.TargetId);
        });

        builder.Entity<SecuritySettings>(b =>
        {
            b.ToTable("security_settings");
            b.Property(x => x.StepUpMinutes).HasDefaultValue(Domain.SecuritySettings.DefaultStepUpMinutes);
            b.Property(x => x.TokenMaxDays).HasDefaultValue(Domain.SecuritySettings.DefaultTokenMaxDays);
            System.Text.Json.JsonSerializerOptions json = new(System.Text.Json.JsonSerializerDefaults.Web);
            b.Property(x => x.SecondFactorMethods).HasColumnType("jsonb").HasDefaultValueSql("'[]'::jsonb").HasConversion(
                v => System.Text.Json.JsonSerializer.Serialize(v, json),
                v => System.Text.Json.JsonSerializer.Deserialize<List<string>>(v, json) ?? new(),
                new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<List<string>>(
                    (a, b) => a!.SequenceEqual(b!),
                    v => string.Join(",", v).GetHashCode(),
                    v => v.ToList()));
        });

        builder.Entity<PersonalAccessToken>(b =>
        {
            b.ToTable("personal_access_tokens");
            b.Property(x => x.Name).HasMaxLength(100).IsRequired();
            b.Property(x => x.Prefix).HasMaxLength(32).IsRequired();
            b.Property(x => x.SecretHash).HasMaxLength(64).IsRequired();
            b.Property(x => x.Access).HasMaxLength(16).IsRequired();
            b.Property(x => x.LastUsedIp).HasMaxLength(64);
            b.Property(x => x.ResourceIds).HasColumnName("ProjectIds"); // Guard's word, the column as it always was
            b.HasIndex(x => x.SecretHash).IsUnique();
            b.HasIndex(x => x.AccountId);
        });

        builder.Entity<WebSession>(b =>
        {
            b.ToTable("sessions");
            b.Property(x => x.TokenHash).HasMaxLength(64).IsRequired();
            b.Property(x => x.UserAgent).HasMaxLength(256);
            b.Property(x => x.Ip).HasMaxLength(64);
            b.Property(x => x.RevokedReason).HasMaxLength(32);
            b.Property(x => x.ParentAuthorizationId).HasMaxLength(100);
            b.HasIndex(x => x.TokenHash).IsUnique();
            b.HasIndex(x => x.AccountId);
            b.HasIndex(x => x.ExpiresAt);
            b.HasIndex(x => x.ParentAuthorizationId);
        });

        // A second factor.
        builder.Entity<SecondFactor>(b =>
        {
            b.ToTable("second_factors");
            b.Property(x => x.Kind).HasMaxLength(32).IsRequired();
            b.HasIndex(x => x.AccountId);
        });

        builder.Entity<RecoveryCode>(b =>
        {
            b.ToTable("recovery_codes");
            b.Property(x => x.Hash).HasMaxLength(64).IsRequired();
            b.HasIndex(x => x.AccountId);
        });

        builder.Entity<SentCode>(b =>
        {
            b.ToTable("sent_codes");
            b.Property(x => x.Method).HasMaxLength(100).IsRequired();
            b.Property(x => x.CodeHash).HasMaxLength(64).IsRequired();
            b.HasIndex(x => new { x.AccountId, x.Method });
            b.HasIndex(x => x.ExpiresAt);
        });

        builder.Entity<SignInTicket>(b =>
        {
            b.ToTable("sign_in_tickets");
            b.Property(x => x.TicketHash).HasMaxLength(64).IsRequired();
            b.Property(x => x.Client).HasMaxLength(100).IsRequired();
            b.Property(x => x.Scopes).HasMaxLength(500);
            b.Property(x => x.Ip).HasMaxLength(64);
            b.HasIndex(x => x.TicketHash).IsUnique();
            b.HasIndex(x => x.ExpiresAt);
        });

        builder.Entity<SessionHandoff>(b =>
        {
            b.ToTable("session_handoffs");
            b.Property(x => x.CodeHash).HasMaxLength(64).IsRequired();
            b.Property(x => x.AuthorizationId).HasMaxLength(100).IsRequired();
            b.HasIndex(x => x.CodeHash).IsUnique();
            b.HasIndex(x => x.ExpiresAt);
        });

        builder.Entity<PrivacyStoreRecord>(b =>
        {
            b.ToTable("privacy_stores");
            b.HasKey(x => x.StoreKey);
            b.Property(x => x.StoreKey).HasMaxLength(200);
            b.Property(x => x.LegalBasis).HasMaxLength(32);
            b.Property(x => x.Notes).HasMaxLength(4000);
        });

        builder.Entity<PrivacyNoticeVersion>(b =>
        {
            b.ToTable("privacy_notices");
            b.HasKey(x => x.Number);
            b.Property(x => x.Number).UseIdentityByDefaultColumn();
            b.Property(x => x.Texts).HasColumnType("jsonb").IsRequired();
        });

        builder.Entity<PrivacyAcceptance>(b =>
        {
            b.ToTable("privacy_acceptances");
            b.Property(x => x.Address).HasMaxLength(320);
            b.Property(x => x.Where).HasMaxLength(32).IsRequired();
            b.Property(x => x.Ip).HasMaxLength(64);
            b.HasIndex(x => x.AccountId);
            b.HasIndex(x => x.Address);
        });

        builder.Entity<ConsentWithdrawal>(b =>
        {
            b.ToTable("consent_withdrawals");
            b.Property(x => x.StoreKey).HasMaxLength(200).IsRequired();
            b.Property(x => x.Note).HasMaxLength(2000);
            b.HasIndex(x => x.AccountId);
        });

        builder.Entity<SecurityFeedSettings>(b =>
        {
            b.ToTable("security_feed");
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.Url).HasMaxLength(2000);
            b.Property(x => x.LastError).HasMaxLength(2000);
        });

        builder.Entity<SecurityAlertState>(b =>
        {
            b.ToTable("security_alerts");
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.Sent).HasColumnType("jsonb").IsRequired();
        });

        builder.Entity<RetentionSettings>(b =>
        {
            b.ToTable("retention_settings");
            b.Property(x => x.Id).ValueGeneratedNever();
        });

        builder.Entity<RetentionPeriod>(b =>
        {
            b.ToTable("retention_periods");
            b.HasKey(x => x.RuleKey);
            b.Property(x => x.RuleKey).HasMaxLength(200);
        });

        builder.Entity<LegalHold>(b =>
        {
            b.ToTable("legal_holds");
            b.Property(x => x.Address).HasMaxLength(320);
            b.Property(x => x.Reason).HasMaxLength(1000).IsRequired();
            b.HasIndex(x => x.AccountId);
            b.HasIndex(x => x.Address);
        });

        builder.Entity<PersonalDataErasureRecord>(b =>
        {
            b.ToTable("erasures");
            b.Property(x => x.Number).UseIdentityByDefaultColumn();
            b.HasIndex(x => x.Number).IsUnique();
            b.Property(x => x.Subject).HasColumnType("jsonb");
            b.Property(x => x.Stores).HasColumnType("jsonb").IsRequired();
            b.Property(x => x.State).HasMaxLength(16).IsRequired();
            b.Property(x => x.Reason).HasMaxLength(2000);
            b.Property(x => x.DeclinedReason).HasMaxLength(2000);
            b.HasIndex(x => x.AccountId);
            b.HasIndex(x => x.State);
        });

        builder.Entity<PrivacySettings>(b =>
        {
            b.ToTable("privacy_settings");
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.ControllerName).HasMaxLength(200);
            b.Property(x => x.ControllerContact).HasMaxLength(500);
            b.Property(x => x.OfficerName).HasMaxLength(200);
            b.Property(x => x.OfficerContact).HasMaxLength(500);
            b.Property(x => x.Country).HasMaxLength(200);
            System.Text.Json.JsonSerializerOptions json = new(System.Text.Json.JsonSerializerDefaults.Web);
            b.Property(x => x.Destinations).HasColumnType("jsonb").HasConversion(
                v => System.Text.Json.JsonSerializer.Serialize(v, json),
                v => System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, PrivacyDestination>>(v, json) ?? new(),
                new Microsoft.EntityFrameworkCore.ChangeTracking.ValueComparer<Dictionary<string, PrivacyDestination>>(
                    (a, b) => System.Text.Json.JsonSerializer.Serialize(a, json) == System.Text.Json.JsonSerializer.Serialize(b, json),
                    v => System.Text.Json.JsonSerializer.Serialize(v, json).GetHashCode(),
                    v => new Dictionary<string, PrivacyDestination>(v)));
        });
    }
}
