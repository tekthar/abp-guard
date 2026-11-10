using System.Text;
using AbpGuard.Domain;
using AbpGuard.Services;
using AbpGuard.Services.TwoFactor;

namespace AbpGuard.Tests;

/// <summary>A second factor: codes as RFC 4226 and 6238 give them, each good once, and the strictest group's mode.</summary>
public class TwoFactorTests
{
    private static readonly byte[] RfcSecret = Encoding.ASCII.GetBytes("12345678901234567890");

    [Theory]
    [InlineData(0, "755224")]
    [InlineData(1, "287082")]
    [InlineData(2, "359152")]
    [InlineData(3, "969429")]
    [InlineData(4, "338314")]
    [InlineData(5, "254676")]
    [InlineData(6, "287922")]
    [InlineData(7, "162583")]
    [InlineData(8, "399871")]
    [InlineData(9, "520489")]
    public void Codes_match_RFC_4226(long counter, string expected) => Assert.Equal(expected, Totp.Code(RfcSecret, counter));

    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1111111111L, "14050471")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(2000000000L, "69279037")]
    [InlineData(20000000000L, "65353130")]
    public void Codes_match_RFC_6238_SHA1(long unixSeconds, string expected) =>
        Assert.Equal(expected, Totp.Code(RfcSecret, Totp.StepAt(DateTimeOffset.FromUnixTimeSeconds(unixSeconds)), digits: 8));

    [Fact]
    public void A_code_is_taken_one_step_either_side_and_only_once()
    {
        byte[] secret = Totp.NewSecret();
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        long step = Totp.StepAt(now);

        Assert.Equal(step, Totp.Verify(secret, Totp.Code(secret, step), now, lastStep: 0));
        Assert.Equal(step - 1, Totp.Verify(secret, Totp.Code(secret, step - 1), now, lastStep: 0));
        Assert.Equal(step + 1, Totp.Verify(secret, Totp.Code(secret, step + 1), now, lastStep: 0));
        Assert.Null(Totp.Verify(secret, Totp.Code(secret, step - 2), now, lastStep: 0));
        Assert.Null(Totp.Verify(secret, Totp.Code(secret, step), now, lastStep: step)); // used already
        Assert.Null(Totp.Verify(secret, Totp.Code(secret, step - 1), now, lastStep: step)); // an older one after a newer
    }

    [Fact]
    public void A_code_may_be_typed_with_spaces_but_not_short()
    {
        byte[] secret = Totp.NewSecret();
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        string code = Totp.Code(secret, Totp.StepAt(now));

        Assert.NotNull(Totp.Verify(secret, $"{code[..3]} {code[3..]}", now, 0));
        Assert.Null(Totp.Verify(secret, code[..5], now, 0));
        Assert.Null(Totp.Verify(secret, null, now, 0));
    }

    [Fact]
    public void Base32_follows_RFC_4648_and_round_trips()
    {
        Assert.Equal("MZXW6YTBOI", Totp.ToBase32(Encoding.ASCII.GetBytes("foobar")));
        Assert.Equal("foobar", Encoding.ASCII.GetString(Totp.FromBase32("mzxw 6ytb oi======")));
        byte[] secret = Totp.NewSecret();
        Assert.Equal(secret, Totp.FromBase32(Totp.ToBase32(secret)));
        Assert.Throws<FormatException>(() => Totp.FromBase32("not-base32!"));
    }

    [Fact]
    public void The_address_is_what_authenticator_apps_read()
    {
        string address = Totp.Address("Acme (site.example.com)", "jsmith", Encoding.ASCII.GetBytes("foobar"));

        Assert.Equal("otpauth://totp/Acme%20%28site.example.com%29:jsmith?secret=MZXW6YTBOI&issuer=Acme%20%28site.example.com%29"
            + "&algorithm=SHA1&digits=6&period=30", address);
    }

    [Theory]
    [InlineData(new string[0], TwoFactorModes.Off)]
    [InlineData(new[] { TwoFactorModes.Off, TwoFactorModes.Optional }, TwoFactorModes.Optional)]
    [InlineData(new[] { TwoFactorModes.Optional, TwoFactorModes.Required, TwoFactorModes.Off }, TwoFactorModes.Required)]
    [InlineData(new[] { TwoFactorModes.Required, TwoFactorModes.Strong, TwoFactorModes.Optional }, TwoFactorModes.Strong)]
    [InlineData(new[] { "something-else" }, TwoFactorModes.Off)]
    public void The_strictest_mode_wins(string[] modes, string expected) => Assert.Equal(expected, TwoFactorModes.Strictest(modes));

    [Fact]
    public void Only_required_and_strong_ask()
    {
        Assert.False(TwoFactorModes.Asks(TwoFactorModes.Off));
        Assert.False(TwoFactorModes.Asks(TwoFactorModes.Optional));
        Assert.True(TwoFactorModes.Asks(TwoFactorModes.Required));
        Assert.True(TwoFactorModes.Asks(TwoFactorModes.Strong));
    }

    [Fact]
    public void A_group_further_up_asks_its_nested_members()
    {
        Guid corp = Guid.NewGuid(), internalDirectory = Guid.NewGuid();
        Group backend = new(Guid.NewGuid(), corp, "backend", isLocal: false);
        Group engineering = new(Guid.NewGuid(), corp, "engineering", isLocal: false) { TwoFactor = TwoFactorModes.Optional };
        Group admins = new(Guid.NewGuid(), internalDirectory, "admins", isLocal: true) { TwoFactor = TwoFactorModes.Required };
        Group other = new(Guid.NewGuid(), internalDirectory, "auditors", isLocal: true) { TwoFactor = TwoFactorModes.Strong };
        Guid jsmith = Guid.NewGuid();
        List<GroupMembership> memberships =
        [
            new(Guid.NewGuid(), engineering.Id, MemberType.Group, backend.Id, MembershipSource.Directory),
            new(Guid.NewGuid(), admins.Id, MemberType.Group, engineering.Id, MembershipSource.Manual),
            new(Guid.NewGuid(), backend.Id, MemberType.DirectoryUser, jsmith, MembershipSource.Directory),
        ];
        Dictionary<Guid, Group> groups = new[] { backend, engineering, admins, other }.ToDictionary(g => g.Id);
        Account account = new(Guid.NewGuid(), "jsmith") { DirectoryUserId = jsmith, Status = AccountStatus.Active };

        var effective = MembershipGraph.ResolveEffectiveGroups(new MembershipGraph.Snapshot([internalDirectory, corp], groups, memberships), account,
            new HashSet<Guid> { jsmith });

        Assert.Equal(TwoFactorModes.Required, TwoFactorModes.Strictest(effective.Select(g => g.Group.TwoFactor))); // not auditors' strong: not a member
    }

    [Theory]
    [InlineData("email", true)]
    [InlineData("messaging:sms", true)]
    [InlineData("messaging:whatsapp", true)]
    [InlineData("app", false)]
    [InlineData("recovery", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Codes_are_sent_by_email_or_a_channel(string? method, bool sent) => Assert.Equal(sent, SecondFactorKinds.IsSent(method));

    [Fact]
    public void Where_a_code_goes_is_shown_masked()
    {
        Assert.Equal("d•••@example.com", SecondFactors.MaskEmail("dana@example.com"));
        Assert.Equal("•••", SecondFactors.MaskEmail("not-an-address"));
        Assert.Equal("•••• 1234", SecondFactors.MaskNumber("+966 50 000 1234"));
        Assert.Equal("••••", SecondFactors.MaskNumber("+12"));
    }

    [Fact]
    public void A_sent_code_is_good_for_ten_minutes()
    {
        SentCode code = new(Guid.NewGuid(), Guid.NewGuid(), SecondFactorKinds.Email, SecondFactors.Hash("x"));

        Assert.Equal(SentCode.Lifetime, code.ExpiresAt - code.CreatedAt);
        Assert.Equal(TimeSpan.FromMinutes(10), SentCode.Lifetime);
        Assert.Null(code.UsedAt);
    }

    [Fact]
    public void A_ticket_is_good_for_five_minutes_and_five_tries()
    {
        SignInTicket ticket = new(Guid.NewGuid(), Guid.NewGuid(), SecondFactors.Hash("t"), "web", null, null);

        Assert.True(ticket.Usable(DateTime.UtcNow));
        Assert.False(ticket.Usable(ticket.ExpiresAt));
        ticket.Attempts = SignInTicket.MaxAttempts;
        Assert.False(ticket.Usable(DateTime.UtcNow));
        Assert.Equal(64, ticket.TicketHash.Length);
    }
}
