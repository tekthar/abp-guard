using AbpConnections;
using AbpGuard;
using Microsoft.EntityFrameworkCore;
using Volo.Abp;

namespace AbpNotify.Tests;

/// <summary>
/// Notices in an application's own database, with its messenger, people and channels: a notice is claimed once and sent
/// through the messenger as each person chose (now, gathered, in a digest, by a chat channel first), the inbox reads
/// and unreads, a typed address is verified with a code sent as a secret, phones are kept by their token, and a team's
/// channel posts once per event and keeps its connection from being removed.
/// </summary>
public class NoticeTests
{
    private static Notice New(Guid account, string summary, Guid? eventId = null, string delivery = NoticeChoices.Now, string? template = "status", bool alone = false) =>
        new(Guid.NewGuid(), eventId ?? Guid.NewGuid(), account, "status", "watchers", null, delivery, summary, Guid.NewGuid(), Guid.NewGuid(), "PAY-1")
        {
            Template = template,
            ModelJson = Notice.Keep(new Dictionary<string, object?> { ["summary"] = summary }),
            Source = "test",
            Alone = alone,
        };

    [Fact]
    public async Task The_tables_and_columns_are_the_hosts_and_the_raw_sql_follows_them()
    {
        await using NotifyApp app = await NotifyApp.StartAsync();
        await app.RunAsync(db =>
        {
            NotifyTable notices = NotifyTable.Of<Notice>(db);
            Assert.Equal(("\"told\".\"notices\"", "\"ProjectId\", \"RecordId\", \"RecordKey\""),
                (notices.Name, notices.Columns(nameof(Notice.ScopeId), nameof(Notice.SubjectId), nameof(Notice.SubjectKey))));
            Assert.Equal("\"told\".\"channel_targets\"", NotifyTable.Of<ChannelTarget>(db).Name);
            return Task.FromResult(0);
        });

        // The claim is an INSERT ... ON CONFLICT in SQL of its own: it writes to the renamed columns.
        Guid dana = app.People.Add("Dana");
        Notice n = New(dana, "PAY-1 moved to Done");
        Assert.True(await app.Get<NoticeStore>().ClaimAsync(n, default));
        string? key = await app.RunAsync(db => db.Database.SqlQueryRaw<string>("SELECT \"RecordKey\" AS \"Value\" FROM told.notices").SingleAsync());
        Assert.Equal("PAY-1", key);
    }

    [Fact]
    public async Task A_notice_is_claimed_once_sent_through_the_messenger_and_read_in_the_inbox()
    {
        await using NotifyApp app = await NotifyApp.StartAsync();
        NoticeStore store = app.Get<NoticeStore>();
        Guid dana = app.People.Add("Dana");
        Guid eventId = Guid.NewGuid();

        Assert.True(await store.ClaimAsync(New(dana, "PAY-1 moved to Done", eventId), default));
        Assert.False(await store.ClaimAsync(New(dana, "PAY-1 moved to Done", eventId), default)); // the same event heard twice
        await app.RoundAsync();

        NotifyMessage sent = Assert.Single(app.Messenger.Messages);
        Assert.Equal(("status", null, "test", true, "PAY-1"), (sent.Template, sent.Channel, sent.Source, sent.Later, sent.SubjectKey));
        Assert.Equal(NotifyRecipient.Person(dana), Assert.Single(sent.To));
        Assert.Equal("PAY-1 moved to Done", sent.Model["summary"]?.ToString());

        await app.RoundAsync();
        Assert.Single(app.Messenger.Messages); // sent once

        InboxView inbox = await store.InboxAsync(dana, unreadOnly: false, before: null, default);
        NoticeView seen = Assert.Single(inbox.Items);
        Assert.Equal(("PAY-1", "PAY-1 moved to Done", 1), (seen.SubjectKey, seen.Summary, inbox.Unread));
        Assert.NotNull(seen.SentAt);
        Assert.Equal(0, await store.MarkReadAsync(dana, new InboxReadInput(null, true), default));
        Assert.Equal(1, await store.MarkUnreadAsync(dana, seen.Id, default));
        Assert.Equal(0, await store.UnreadAsync(app.People.Add("Omar"), default));
    }

    [Fact]
    public async Task What_follows_a_message_waits_for_the_window_and_goes_together()
    {
        await using NotifyApp app = await NotifyApp.StartAsync();
        NoticeStore store = app.Get<NoticeStore>();
        Guid dana = app.People.Add("Dana");
        await store.ClaimAsync(New(dana, "first"), default);
        await app.RoundAsync();

        await store.ClaimAsync(New(dana, "second"), default);
        await store.ClaimAsync(New(dana, "third"), default);
        await store.ClaimAsync(New(dana, "a mention", alone: true), default);
        await app.RoundAsync();
        // Within the window only the one meant to go alone goes; the rest wait for the window to end.
        Assert.Equal(["status", "status"], app.Messenger.Messages.Select(m => m.Template));
        Assert.Equal("a mention", app.Messenger.Messages[1].Model["summary"]?.ToString());

        await store.SaveSiteAsync(new NoticeSiteSettingsDto(0, 30), default);
        await app.RoundAsync();
        NotifyMessage together = app.Messenger.Messages[2];
        Assert.Equal(("notice.digest", "notice:batch", false, 2), (together.Template, together.Source, (bool)together.Model["digest"]!, (int)together.Model["count"]!));
    }

    [Fact]
    public async Task A_digest_comes_by_mail_at_the_persons_hour()
    {
        await using NotifyApp app = await NotifyApp.StartAsync();
        NoticeStore store = app.Get<NoticeStore>();
        Guid dana = app.People.Add("Dana");
        await store.SaveSettingsAsync(dana, new NotificationSettingsInput(new() { ["status"] = NoticeChoices.Digest }, true, false, DigestFrequencies.Hourly), default);
        Assert.Equal(NoticeChoices.Digest, (await store.SettingsDtoAsync(dana, default)).Choices["status"]);

        await store.ClaimAsync(New(dana, "PAY-1 moved", delivery: NoticeChoices.Digest), default);
        await store.ClaimAsync(New(dana, "PAY-2 moved", delivery: NoticeChoices.Digest), default);
        await app.RoundAsync();
        NotifyMessage digest = Assert.Single(app.Messenger.Messages);
        Assert.Equal(("notice.digest", "notice:digest", null, true), (digest.Template, digest.Source, digest.Channel, (bool)digest.Model["digest"]!));
        Assert.Equal(["PAY-1 moved", "PAY-2 moved"], (List<string>)digest.Model["summaries"]!);

        await store.ClaimAsync(New(dana, "PAY-3 moved", delivery: NoticeChoices.Digest), default);
        await app.RoundAsync();
        Assert.Single(app.Messenger.Messages); // the next one is due in an hour
    }

    [Fact]
    public async Task Someone_who_hears_by_a_chat_channel_gets_the_short_form_and_mail_when_it_cant_reach_them()
    {
        await using NotifyApp app = await NotifyApp.StartAsync();
        NoticeStore store = app.Get<NoticeStore>();
        ChannelAddressBook book = app.Get<ChannelAddressBook>();
        Guid dana = app.People.Add("Dana");
        await Assert.ThrowsAsync<UserFriendlyException>(() =>
            store.SaveSettingsAsync(dana, new NotificationSettingsInput(null, true, false, Channel: Sms.ChannelKey), default)); // no verified number yet

        await book.StartAsync(dana, Sms.ChannelKey, "+966 50 000 0000", default);
        string code = (string)app.Messenger.Messages[^1].Model["code"]!;
        await book.VerifyAsync(dana, Sms.ChannelKey, code, default);
        Assert.Equal(Sms.ChannelKey, (await store.SaveSettingsAsync(dana, new NotificationSettingsInput(null, true, false, Channel: Sms.ChannelKey), default)).Channel);

        await store.ClaimAsync(New(dana, "PAY-1 moved"), default);
        await app.RoundAsync();
        NotifyMessage chat = app.Messenger.Messages[^1];
        Assert.Equal(("status.message", Sms.ChannelKey), (chat.Template, chat.Channel));

        app.Messenger.SmsUnreachable = true;
        await store.SaveSiteAsync(new NoticeSiteSettingsDto(0, 30), default);
        await store.ClaimAsync(New(dana, "PAY-2 moved"), default);
        await app.RoundAsync();
        Assert.Equal(("status.message", Sms.ChannelKey), (app.Messenger.Messages[^2].Template, app.Messenger.Messages[^2].Channel));
        Assert.Equal(("status", null), (app.Messenger.Messages[^1].Template, app.Messenger.Messages[^1].Channel)); // then by mail
    }

    [Fact]
    public async Task A_typed_address_is_verified_with_a_code_sent_once_as_a_secret()
    {
        await using NotifyApp app = await NotifyApp.StartAsync();
        ChannelAddressBook book = app.Get<ChannelAddressBook>();
        Guid dana = app.People.Add("Dana");

        MyChannelDto pending = (await book.StartAsync(dana, Sms.ChannelKey, "+966 50 000 0000", default)).Single(c => c.Channel == Sms.ChannelKey);
        Assert.Equal(("+966500000000", false, true), (pending.Address, pending.Verified, pending.Pending));
        NotifyMessage sent = Assert.Single(app.Messenger.Messages);
        Assert.Equal((ChannelAddressBook.CodeTemplate, Sms.ChannelKey, "channel-code", true, false), (sent.Template, sent.Channel, sent.Source, sent.Secret, sent.Later));
        Assert.Equal(NotifyRecipient.Address("+966500000000"), Assert.Single(sent.To));
        string code = (string)sent.Model["code"]!;
        Assert.Matches("^[0-9]{6}$", code);

        UserFriendlyException again = await Assert.ThrowsAsync<UserFriendlyException>(() => book.StartAsync(dana, Sms.ChannelKey, "+966500000000", default));
        Assert.Equal(GuardErrorCodes.TooManyRequests, again.Code);
        UserFriendlyException wrong = await Assert.ThrowsAsync<UserFriendlyException>(() => book.VerifyAsync(dana, Sms.ChannelKey, code == "000000" ? "111111" : "000000", default));
        Assert.Equal("That isn't the code we sent.", wrong.Message);
        Assert.Null(await book.AddressAsync(dana, Sms.ChannelKey));

        MyChannelDto verified = (await book.VerifyAsync(dana, Sms.ChannelKey, code, default)).Single(c => c.Channel == Sms.ChannelKey);
        Assert.Equal(("+966500000000", true, false), (verified.Address, verified.Verified, verified.Pending));
        Assert.Equal("+966500000000", await book.AddressAsync(dana, Sms.ChannelKey));
        Assert.True(await book.ReachesAsync(dana, Sms.ChannelKey, default));
        string? kept = await app.RunAsync(db => db.ChannelAddresses.Select(a => a.CodeHash).SingleAsync());
        Assert.Null(kept); // the code is gone once used

        await Assert.ThrowsAsync<UserFriendlyException>(() => book.StartAsync(dana, Sms.ChannelKey, "not a number", default));
        await Assert.ThrowsAsync<UserFriendlyException>(() => book.StartAsync(dana, "email", "dana@example.com", default));
    }

    [Fact]
    public async Task A_phone_is_kept_by_its_token_and_forgotten_on_sign_out()
    {
        await using NotifyApp app = await NotifyApp.StartAsync();
        DeviceBook devices = app.Get<DeviceBook>();
        Guid dana = app.People.Add("Dana");

        DeviceDto first = await devices.RegisterAsync(dana, new DeviceInput("token-1", DevicePlatforms.Android, "Pixel"), default);
        DeviceDto same = await devices.RegisterAsync(dana, new DeviceInput("token-1", DevicePlatforms.Android, "Pixel"), default);
        Assert.Equal(first.Id, same.Id);
        await devices.RegisterAsync(dana, new DeviceInput("token-2", DevicePlatforms.Ios, "iPhone"), default);
        Assert.Equal(2, (await devices.MineAsync(dana, default)).Count);
        Assert.True(await devices.AnyAsync(dana, default));
        await Assert.ThrowsAsync<UserFriendlyException>(() => devices.RegisterAsync(dana, new DeviceInput("token-3", "windows", "PC"), default));

        await devices.UnregisterAsync(dana, "token-1", default);
        await Assert.ThrowsAsync<Volo.Abp.Domain.Entities.EntityNotFoundException>(() => devices.UnregisterAsync(app.People.Add("Omar"), first.Id, default)); // not his
        Assert.Equal(["token-2"], await devices.TokensAsync(dana, default));
    }

    [Fact]
    public async Task A_teams_channel_posts_once_per_event_and_keeps_its_connection()
    {
        await using NotifyApp app = await NotifyApp.StartAsync();
        ConnectionManager connections = app.Get<ConnectionManager>();
        ChannelTargetStore targets = app.Get<ChannelTargetStore>();
        Guid admin = Guid.NewGuid();
        ConnectionView slack = await connections.CreateAsync(new("Team chat", SlackConnectionKind.Key, new() { ["apiUrl"] = "https://slack.test/api" }, new() { ["botToken"] = "xoxb-1" }),
            null, admin, default);
        Assert.Contains(await connections.KindsAsync(default), k => k.Type == SlackConnectionKind.Key);

        Assert.Equal("Name the Slack channel to post to (its id, or #name).",
            (await Assert.ThrowsAsync<UserFriendlyException>(() => targets.CreateAsync(null, new ChannelTargetInput("Ops", slack.Id, " "), admin, default))).Message);
        ChannelTargetView ops = await targets.CreateAsync(null, new ChannelTargetInput("Ops", slack.Id, "#ops"), admin, default);
        Assert.Equal(("ops", SlackConnectionKind.Key, "Team chat"), (ops.Where, ops.Channel, ops.Connection));
        Assert.Equal([ops.Id], (await targets.ListAsync(Guid.NewGuid(), default)).Select(t => t.Id)); // the site's reach every scope
        Assert.Equal([slack.Id], (await targets.ConnectionsAsync(null, default)).Select(c => c.Id));

        Guid eventId = Guid.NewGuid();
        Assert.True(await targets.PostOnceAsync(eventId, ops.Id, "status", new Dictionary<string, object?>(), null, null, "PAY-1", "rule", default));
        Assert.False(await targets.PostOnceAsync(eventId, ops.Id, "status", new Dictionary<string, object?>(), null, null, "PAY-1", "rule", default));
        NotifyMessage post = Assert.Single(app.Messenger.Messages);
        Assert.Equal((SlackConnectionKind.Key, "rule", true), (post.Channel, post.Source, post.Later));
        Assert.Equal(NotifyRecipient.Address(ChatAddress.Of(slack.Id, "ops"), "Ops"), Assert.Single(post.To));

        UserFriendlyException inUse = await Assert.ThrowsAsync<UserFriendlyException>(() => connections.DeleteAsync(slack.Id, null, default));
        Assert.Equal("Team chat is in use: the team channel Ops. Stop using it first.", inUse.Message);
        await targets.DeleteAsync(null, ops.Id, default);
        await connections.DeleteAsync(slack.Id, null, default);
    }

    [Fact]
    public async Task Slack_posts_through_the_connection_in_its_own_markdown()
    {
        await using NotifyApp app = await NotifyApp.StartAsync();
        ConnectionView slack = await app.Get<ConnectionManager>().CreateAsync(
            new("Team chat", SlackConnectionKind.Key, new() { ["apiUrl"] = "https://slack.test/api" }, new() { ["botToken"] = "xoxb-1" }), null, Guid.NewGuid(), default);

        await app.Get<SlackChannel>().DeliverAsync(new NotifyDelivery(Guid.NewGuid(), ChatAddress.Of(slack.Id, "ops"), "Ops", null,
            "[PAY-1](https://app.test/browse/PAY-1) **Refund**: moved", "PAY-1 Refund: moved", "", "en", "<m@app.test>"), default);
        (string url, string body) = Assert.Single(app.Chat.Calls);
        Assert.Equal("https://slack.test/api/chat.postMessage", url);
        System.Text.Json.JsonElement posted = System.Text.Json.JsonDocument.Parse(body).RootElement;
        Assert.Equal(("ops", "<https://app.test/browse/PAY-1|PAY-1> *Refund*: moved"), (posted.GetProperty("channel").GetString(), posted.GetProperty("text").GetString()));
    }

    [Fact]
    public async Task The_sites_settings_start_from_configuration_and_are_kept()
    {
        await using NotifyApp app = await NotifyApp.StartAsync(new() { ["Notices:WindowSeconds"] = "60", ["Notices:MailsPerHour"] = "10" });
        NoticeStore store = app.Get<NoticeStore>();
        Assert.Equal(new NoticeSiteSettingsDto(60, 10), await store.SiteAsync(default));
        Assert.Equal(new NoticeSiteSettingsDto(300, 5), await store.SaveSiteAsync(new NoticeSiteSettingsDto(300, 5), default));
        Assert.Equal(new NoticeSiteSettingsDto(300, 5), await store.SiteAsync(default));
    }
}
