using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AbpGuard.Tests;

/// <summary>Guard's messages: its own texts for each kind, and the default messenger that writes them to a folder.</summary>
public class GuardMessengerTests
{
    [Fact]
    public void Every_kind_has_its_texts_in_English_and_Arabic_with_the_values_it_names()
    {
        string[] kinds = [GuardMessageKinds.SignUpVerify, GuardMessageKinds.PasswordReset, GuardMessageKinds.AddressVerify,
            GuardMessageKinds.SecondFactorCode, GuardMessageKinds.SecondFactorCodeMessage];
        Assert.Equal(kinds.Order(), GuardMessageTemplates.All.Select(t => t.Key).Order());
        foreach (GuardMessageTemplate template in GuardMessageTemplates.All)
        {
            Assert.True(template.Texts.ContainsKey("en") && template.Texts.ContainsKey("ar"), template.Key);
            Assert.Equal(template.Email, template.Texts.Values.All(t => t.Subject is not null));
            foreach (GuardTemplateText text in template.Texts.Values)
            {
                string rendered = PickupGuardMessenger.Render(text.Body, template.Sample);
                Assert.DoesNotContain("{{", rendered);
            }
        }

        // A second step's code is in both of its texts: the code must reach the person.
        Assert.All(GuardMessageTemplates.All.Where(t => t.Key.StartsWith(GuardMessageKinds.SecondFactorCode, StringComparison.Ordinal)),
            t => Assert.All(t.Texts.Values, x => Assert.Contains("{{ code }}", x.Body)));
    }

    [Fact]
    public void A_host_names_its_product_or_gives_its_own_template()
    {
        // Guard's own texts mark where the product's name goes; without one given, they name AbpGuard.
        string[] naming = [GuardMessageKinds.SignUpVerify, GuardMessageKinds.PasswordReset, GuardMessageKinds.AddressVerify];
        Assert.All(GuardMessageTemplates.All.Where(t => naming.Contains(t.Key)), t => Assert.Contains(GuardMessageTemplates.ProductMarker, t.Texts["en"].Subject));
        GuardMessageTemplate unnamed = GuardMessageTemplates.Find(new GuardTextOptions(), GuardMessageKinds.PasswordReset)!;
        Assert.Equal("Reset your AbpGuard password", unnamed.Texts["en"].Subject);

        // A product names itself; a language it didn't name uses its English name.
        GuardTextOptions market = new();
        market.ProductName["en"] = "Market";
        GuardMessageTemplate reset = GuardMessageTemplates.Find(market, GuardMessageKinds.PasswordReset)!;
        Assert.Equal("Reset your Market password", reset.Texts["en"].Subject);
        Assert.Contains("Market", reset.Texts["ar"].Body);
        Assert.All(GuardMessageTemplates.For(market), t =>
        {
            Assert.All(t.Texts.Values, x => Assert.DoesNotContain(GuardMessageTemplates.ProductMarker, (x.Subject ?? "") + x.Body, StringComparison.Ordinal));
            Assert.All(t.Names.Values.Concat(t.Descriptions.Values), x => Assert.DoesNotContain(GuardMessageTemplates.ProductMarker, x, StringComparison.Ordinal));
        });

        // Or gives a whole template of its own for a kind.
        GuardMessageTemplate own = reset with { Texts = new Dictionary<string, GuardTemplateText> { ["en"] = new("New password", "Go to {{ link }}") } };
        market.Messages[GuardMessageKinds.PasswordReset] = own;
        Assert.Same(own, GuardMessageTemplates.Find(market, GuardMessageKinds.PasswordReset));
    }

    [Fact]
    public void Values_are_filled_by_their_path_and_missing_ones_left_empty()
    {
        Dictionary<string, object?> model = new() { ["code"] = "482913", ["recipient"] = new Dictionary<string, object?> { ["name"] = "Dana" } };

        Assert.Equal("Dana: 482913 ()", PickupGuardMessenger.Render("{{ recipient.name }}: {{code}} ({{ nothing.here }})", model));
    }

    [Fact]
    public async Task The_default_messenger_writes_mail_to_its_folder_and_reaches_no_one_without_one()
    {
        string folder = Path.Combine(Path.GetTempPath(), "guard-pickup-" + Guid.NewGuid().ToString("N"));
        try
        {
            PickupGuardMessenger messenger = new(Options.Create(new GuardOptions { Messenger = { PickupFolder = folder } }), new NoAccounts(),
                NullLogger<PickupGuardMessenger>.Instance);
            Assert.Single(await messenger.ReachAsync(Guid.NewGuid(), "dana@example.com", CancellationToken.None));
            Assert.Equal([new GuardMethod("email", "Email", true)], await messenger.MethodsAsync(CancellationToken.None));

            GuardSendResult sent = await messenger.SendAsync(new GuardMessage(GuardMessageKinds.PasswordReset, null, "dana@example.com", "Dana",
                new Dictionary<string, object?> { ["username"] = "dana", ["link"] = "https://example.com/reset#t", ["minutes"] = 60 }, "ar", "password-reset"),
                CancellationToken.None);

            Assert.Equal(new GuardSendResult(1, 0), sent);
            string mail = await File.ReadAllTextAsync(Assert.Single(Directory.GetFiles(folder)));
            Assert.Contains("To: \"Dana\" <dana@example.com>", mail);
            Assert.Contains("https://example.com/reset#t", mail);
            Assert.Contains("AbpGuard", mail);
            Assert.DoesNotContain(GuardMessageTemplates.ProductMarker, mail);

            PickupGuardMessenger nowhere = new(Options.Create(new GuardOptions()), new NoAccounts(), NullLogger<PickupGuardMessenger>.Instance);
            Assert.Empty(await nowhere.ReachAsync(Guid.NewGuid(), "dana@example.com", CancellationToken.None));
            Assert.False(Assert.Single(await nowhere.MethodsAsync(CancellationToken.None)).Ready);
            Assert.Equal(new GuardSendResult(0, 1), await nowhere.SendAsync(new GuardMessage(GuardMessageKinds.PasswordReset, null, "dana@example.com", null,
                new Dictionary<string, object?>(), null, "password-reset"), CancellationToken.None));
        }
        finally
        {
            if (Directory.Exists(folder))
            {
                Directory.Delete(folder, recursive: true);
            }
        }
    }

    [Fact]
    public async Task A_name_or_address_with_line_breaks_starts_no_header_of_its_own()
    {
        string folder = Path.Combine(Path.GetTempPath(), "guard-pickup-" + Guid.NewGuid().ToString("N"));
        try
        {
            PickupGuardMessenger messenger = new(Options.Create(new GuardOptions { Messenger = { PickupFolder = folder } }), new NoAccounts(),
                NullLogger<PickupGuardMessenger>.Instance);
            await messenger.SendAsync(new GuardMessage(GuardMessageKinds.PasswordReset, null, "dana@example.com\r\nCc: eve@attacker.example",
                "Dana\r\nBcc: eve@attacker.example\u2028X-Injected: yes",
                new Dictionary<string, object?> { ["username"] = "dana", ["link"] = "https://example.com/reset#t", ["minutes"] = 60 }, "en", "password-reset"),
                CancellationToken.None);

            string mail = await File.ReadAllTextAsync(Assert.Single(Directory.GetFiles(folder)));
            string[] headers = mail[..mail.IndexOf("\r\n\r\n", StringComparison.Ordinal)].Split("\r\n");
            Assert.Equal(["To", "Subject", "Content-Type", "X-Guard-Kind"], headers.Select(h => h[..h.IndexOf(':', StringComparison.Ordinal)]));
            Assert.DoesNotContain(mail.Split("\r\n"), line => line.StartsWith("Bcc:", StringComparison.Ordinal) || line.StartsWith("Cc:", StringComparison.Ordinal));
            Assert.DoesNotContain('\u2028', mail);
        }
        finally
        {
            if (Directory.Exists(folder))
            {
                Directory.Delete(folder, recursive: true);
            }
        }
    }

    private sealed class NoAccounts : IAccountLookup
    {
        public Task<AccountInfo?> GetAsync(Guid accountId, CancellationToken cancellationToken = default) => Task.FromResult<AccountInfo?>(null);

        public Task<IReadOnlyDictionary<Guid, AccountInfo>> GetManyAsync(IEnumerable<Guid> accountIds, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyDictionary<Guid, AccountInfo>>(new Dictionary<Guid, AccountInfo>());

        public Task<AccountInfo?> FindByUsernameAsync(string username, CancellationToken cancellationToken = default) => Task.FromResult<AccountInfo?>(null);

        public Task<IReadOnlyList<AccountInfo>> FindByEmailAsync(string email, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AccountInfo>>([]);

        public Task<IReadOnlyList<AccountInfo>> SearchAsync(string text, int max = 20, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AccountInfo>>([]);
    }
}
