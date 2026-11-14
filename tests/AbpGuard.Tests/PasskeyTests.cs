using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.Extensions.Configuration;
using AbpGuard.Acting;
using AbpGuard.Data;
using AbpGuard.Domain;
using AbpGuard.Services.Privacy;
using AbpGuard.Services.TwoFactor;

namespace AbpGuard.Tests;

/// <summary>
/// Passkeys' parts that need no server: the providers named by AAGUID, which kinds are strong, the relying party from the
/// site's address, a challenge read from client data, the strong proof's claims, and every table in the data map.
/// </summary>
public class PasskeyTests
{
    [Theory]
    [InlineData("fbfc3007-154e-4ecc-8c0b-6e020557d7bd", "iCloud Keychain")]
    [InlineData("ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4", "Google Password Manager")]
    [InlineData("08987058-cadc-4b81-b6e1-30de50dcbe96", "Windows Hello")]
    [InlineData("bada5566-a7aa-401f-bd96-45619a55120d", "1Password")]
    [InlineData("cb69481e-8ff7-4039-93ec-0a2729a154a8", "YubiKey 5 Series")]
    [InlineData("00000000-0000-0000-0000-000000000000", null)]
    [InlineData("12345678-1234-1234-1234-123456789abc", null)]
    public void A_provider_is_named_by_its_aaguid_or_not_at_all(string aaguid, string? name) => Assert.Equal(name, PasskeyProviders.Name(Guid.Parse(aaguid)));

    [Theory]
    [InlineData(SecondFactorKinds.Passkey, true, false)]
    [InlineData(SecondFactorKinds.App, true, false)]
    [InlineData(SecondFactorKinds.Recovery, false, false)]
    [InlineData(SecondFactorKinds.Email, false, true)]
    [InlineData("messaging:sms", false, true)]
    [InlineData(null, false, false)]
    public void A_passkey_and_the_app_are_strong_and_sent_codes_and_recovery_codes_arent(string? kind, bool strong, bool sent)
    {
        Assert.Equal(strong, SecondFactorKinds.IsStrong(kind));
        Assert.Equal(sent, SecondFactorKinds.IsSent(kind));
    }

    [Fact]
    public void The_relying_party_is_the_sites_address_unless_the_host_names_one()
    {
        PasskeyRelyingParty site = Passkeys.Resolve(new GuardOptions { PublicUrl = "https://work.example.com/app" })!;
        Assert.Equal("work.example.com", site.Id);
        Assert.Equal(["https://work.example.com"], site.Origins);
        Assert.Equal("AbpGuard", site.Name);

        GuardOptions named = new() { PublicUrl = "https://work.example.com", Passkeys = { RpId = "Example.com", RpName = "Example", Origins = ["https://a.example.com, https://b.example.com/"] } };
        PasskeyRelyingParty given = Passkeys.Resolve(named)!;
        Assert.Equal("example.com", given.Id);
        Assert.Equal("Example", given.Name);
        Assert.Equal(["https://a.example.com", "https://b.example.com"], given.Origins.Order(StringComparer.Ordinal));

        IConfiguration environment = new ConfigurationBuilder().AddInMemoryCollection([new("Guard:Passkeys:Origins", "https://c.example.com,https://d.example.com")]).Build();
        Assert.Equal(2, Passkeys.Resolve(new GuardOptions { Passkeys = { RpId = "example.com" } }, environment)!.Origins.Count);

        // Nothing to go by: the host is told what to set rather than given a guess.
        Assert.Null(Passkeys.Resolve(new GuardOptions()));
    }

    [Fact]
    public void A_challenge_is_read_from_the_client_data_or_not_at_all()
    {
        byte[] challenge = [1, 2, 3, 250, 251, 252];
        string text = Convert.ToBase64String(challenge).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Assert.Equal(challenge, Passkeys.ChallengeOf(Encoding.UTF8.GetBytes($$"""{"type":"webauthn.get","challenge":"{{text}}","origin":"https://example.com"}""")));
        Assert.Null(Passkeys.ChallengeOf(Encoding.UTF8.GetBytes("""{"type":"webauthn.get"}""")));
        Assert.Null(Passkeys.ChallengeOf(Encoding.UTF8.GetBytes("not json")));
        Assert.Null(Passkeys.ChallengeOf(Encoding.UTF8.GetBytes("""{"challenge":"***"}""")));
        Assert.Null(Passkeys.ChallengeOf(null));
    }

    [Fact]
    public void A_token_says_when_the_person_proved_themselves_strongly_and_with_a_recovery_code()
    {
        ActingContext acting = new(new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(
                    [
                        new Claim("sub", Guid.NewGuid().ToString()), new Claim(ActingContext.AuthTimeClaim, "1800000300"),
                        new Claim(ActingContext.StrongAuthTimeClaim, "1800000200"), new Claim(ActingContext.RecoveryAuthTimeClaim, "1800000100"),
                    ], "test")),
            },
        });

        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_800_000_300), acting.AuthTime);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_800_000_200), acting.StrongAuthTime);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_800_000_100), acting.RecoveryAuthTime);
        Assert.Null(new ActingContext(new HttpContextAccessor { HttpContext = new DefaultHttpContext() }).StrongAuthTime);
    }

    [Fact]
    public void Every_table_of_Guards_is_in_the_data_map_and_every_one_naming_an_account_holds_personal_data()
    {
        using GuardDbContext db = new(new DbContextOptionsBuilder<GuardDbContext>().UseNpgsql("Host=localhost;Database=guard_model_only").Options);
        GuardPersonalData map = new();
        HashSet<string> personal = [.. map.Stores.SelectMany(s => s.Tables)];
        HashSet<string> notPersonal = [.. map.NotPersonal.Select(t => t.Table)];
        List<string> missing = [];
        List<string> wrong = [];
        foreach (IEntityType entity in db.Model.GetEntityTypes().Where(e => e.GetTableName() is not null))
        {
            string table = $"{entity.GetSchema() ?? GuardDbContext.Schema}.{entity.GetTableName()}";
            if (!personal.Contains(table) && !notPersonal.Contains(table))
            {
                missing.Add(table);
            }

            if (entity.FindProperty("AccountId") is not null && !personal.Contains(table))
            {
                wrong.Add(table);
            }
        }

        Assert.True(missing.Count == 0, "Not in the data map: " + string.Join(", ", missing));
        Assert.True(wrong.Count == 0, "Names an account but isn't personal data: " + string.Join(", ", wrong));
        Assert.Contains("guard.passkeys", personal);
        Assert.Contains("guard.passkey_challenges", personal);
    }
}
