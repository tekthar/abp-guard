using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using AbpConnections;
using Microsoft.Extensions.Options;
using Volo.Abp.DependencyInjection;

namespace AbpNotify;

/// <summary>
/// An address on a chat channel that goes through a connection: <c>{connection id}|{where}</c>, so a scope's team
/// channel posts with the scope's connection and a person's message with the site's.
/// </summary>
public static class ChatAddress
{
    public static string Of(Guid connectionId, string where) => $"{connectionId}|{where}";

    public static bool TryParse(string address, out Guid connectionId, out string where)
    {
        (connectionId, where) = (Guid.Empty, "");
        int bar = address.IndexOf('|');
        if (bar < 0 || !Guid.TryParse(address[..bar], out connectionId))
        {
            return false;
        }

        where = address[(bar + 1)..];
        return true;
    }
}

/// <summary>A Slack workspace: its bot's token; the application posts as the bot. The API address is Slack's unless a test points elsewhere.</summary>
[ExposeServices(typeof(IConnectionKind), typeof(SlackConnectionKind))]
public sealed class SlackConnectionKind : IConnectionKind, ITransientDependency
{
    public const string Key = "slack";

    public string Type => Key;

    public string DisplayName => "Slack";

    public bool SignsIn => false;

    public IReadOnlyList<ConnectionSetting> Settings { get; } =
    [
        new("apiUrl", "API address", DefaultValue: "https://slack.com/api"),
        new("botToken", "Bot token", Secret: true, Required: true, Help: "A bot token (xoxb-…) with chat:write, im:write and users:read.email."),
    ];

    public ConnectionOAuthSetup? OAuth(IReadOnlyDictionary<string, string> settings, IReadOnlyDictionary<string, string> secrets) => null;

    public async Task<ConnectionTestResult> TestAsync(ConnectionInUse connection, HttpClient http, CancellationToken cancellationToken)
    {
        JsonElement answer = await SlackChannel.CallAsync(http, connection, "auth.test", new { }, cancellationToken);
        return answer.GetProperty("ok").GetBoolean()
            ? new ConnectionTestResult(true, $"Signed in to {answer.GetProperty("team").GetString()}.", answer.GetProperty("user").GetString())
            : new ConnectionTestResult(false, $"Slack said {answer.GetProperty("error").GetString()}.");
    }
}

/// <summary>
/// Slack: messages to people (found by their email in the site's workspace) and posts to a team's channel. Uses the
/// site's Slack connection for people; a post names its own.
/// </summary>
[ExposeServices(typeof(INotifyChannel), typeof(SlackChannel))]
public sealed partial class SlackChannel(ConnectionManager connections, INotifyAddresses addresses, IHttpClientFactory clients, IOptions<NotifyOptions> options)
    : INotifyChannel, IPersonalNotifyChannel, ITransientDependency
{
    public string Key => SlackConnectionKind.Key;

    public IReadOnlyList<string> Kinds { get; } = [NotifyTemplateKinds.Message];

    public string Name => "Slack";

    public bool PeopleTypeAddress => false;

    public string? AddressHint => null;

    public string? Normalize(string address) => null;

    public async Task<bool> ReadyAsync(CancellationToken cancellationToken) => (await connections.ListOfTypeAsync(SlackConnectionKind.Key, null, cancellationToken)).Count > 0;

    public bool IsAddress(string address) => ChatAddress.TryParse(address, out _, out string where) && where.Length > 0;

    /// <summary>The person's Slack member in the site's workspace: remembered, or found by their email (and remembered).</summary>
    public async Task<string?> AddressAsync(NotifyPerson person, CancellationToken cancellationToken)
    {
        if (await addresses.AddressAsync(person.Id, Key, cancellationToken) is { } known)
        {
            return known;
        }

        if (person.Email is null || (await connections.ListOfTypeAsync(SlackConnectionKind.Key, null, cancellationToken)).FirstOrDefault(c => c.ScopeId is null) is not { } site
            || await connections.GetForUseAsync(site.Id, cancellationToken) is not { } connection)
        {
            return null;
        }

        JsonElement found = await CallAsync(Http(), connection, "users.lookupByEmail", new { email = person.Email }, cancellationToken, form: true);
        if (!found.GetProperty("ok").GetBoolean())
        {
            return null; // not in the workspace
        }

        string address = ChatAddress.Of(site.Id, found.GetProperty("user").GetProperty("id").GetString()!);
        await addresses.RememberAsync(person.Id, Key, address, cancellationToken);
        return address;
    }

    public async Task DeliverAsync(NotifyDelivery delivery, CancellationToken cancellationToken)
    {
        if (!ChatAddress.TryParse(delivery.Address, out Guid connectionId, out string where))
        {
            throw new InvalidOperationException($"{delivery.Address} isn't a Slack address.");
        }

        ConnectionInUse connection = await connections.GetForUseAsync(connectionId, cancellationToken)
            ?? throw new InvalidOperationException("The Slack connection this was for is gone.");
        JsonElement posted = await CallAsync(Http(), connection, "chat.postMessage", new { channel = where, text = Slack(delivery.Markdown), unfurl_links = false }, cancellationToken);
        if (!posted.GetProperty("ok").GetBoolean())
        {
            throw new InvalidOperationException($"Slack refused the message: {posted.GetProperty("error").GetString()}.");
        }
    }

    private HttpClient Http() => clients.CreateClient(options.Value.HttpClientName);

    /// <summary>Calls a Slack Web API method with the bot token; Slack answers 200 with <c>ok</c> false on its own errors.</summary>
    internal static async Task<JsonElement> CallAsync(HttpClient http, ConnectionInUse connection, string method, object body, CancellationToken cancellationToken, bool form = false)
    {
        string url = (connection.Settings.GetValueOrDefault("apiUrl") is { Length: > 0 } api ? api : "https://slack.com/api").TrimEnd('/') + "/" + method;
        using HttpRequestMessage request = new(HttpMethod.Post, url)
        {
            Content = form
                ? new FormUrlEncodedContent(JsonSerializer.SerializeToElement(body).EnumerateObject().Select(p => KeyValuePair.Create(p.Name, p.Value.ToString())))
                : JsonContent.Create(body),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", connection.Secrets.GetValueOrDefault("botToken"));
        using HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        // Slack's answers are small: a megabyte at most is read.
        return JsonSerializer.Deserialize<JsonElement>(await OutboundGuard.ReadAtMostAsync(response.Content, 1 << 20, cancellationToken));
    }

    /// <summary>Markdown as Slack's mrkdwn: **bold** becomes *bold*, and [text](url) becomes &lt;url|text&gt;.</summary>
    internal static string Slack(string markdown) =>
        MarkdownLink().Replace(markdown.Replace("**", "*"), "<$2|$1>");

    /// <summary>How long a pattern may run on text it's given, so a crafted message can't hold a thread.</summary>
    private const int TimeoutMilliseconds = 1000;

    [GeneratedRegex(@"\[([^\]]+)\]\(([^)\s]+)\)", RegexOptions.None, TimeoutMilliseconds)]
    private static partial Regex MarkdownLink();
}

/// <summary>A Microsoft Teams channel's incoming webhook: the application posts to that one channel. The address is a secret.</summary>
[ExposeServices(typeof(IConnectionKind), typeof(TeamsConnectionKind))]
public sealed class TeamsConnectionKind(IOptions<NotifyOptions> options) : IConnectionKind, ITransientDependency
{
    public const string Key = "teams";

    public string Type => Key;

    public string DisplayName => "Microsoft Teams channel";

    public bool SignsIn => false;

    public IReadOnlyList<ConnectionSetting> Settings { get; } =
    [
        new("webhookUrl", "Webhook address", Secret: true, Required: true, Help: "From the channel's Workflows: post to a channel when a webhook request is received."),
    ];

    public ConnectionOAuthSetup? OAuth(IReadOnlyDictionary<string, string> settings, IReadOnlyDictionary<string, string> secrets) => null;

    public Task<ConnectionTestResult> TestAsync(ConnectionInUse connection, HttpClient http, CancellationToken cancellationToken) =>
        Task.FromResult(Uri.TryCreate(connection.Secrets.GetValueOrDefault("webhookUrl"), UriKind.Absolute, out Uri? url) && url.Scheme is "https" or "http"
            ? new ConnectionTestResult(true, $"A webhook address; {options.Value.ApplicationName} posts to it when a notification rule says so (a test posts nothing).")
            : new ConnectionTestResult(false, "That isn't a webhook address."));
}

/// <summary>Microsoft Teams: posts to a team's channel through its incoming webhook, as an Adaptive Card. It doesn't reach people one by one.</summary>
[ExposeServices(typeof(INotifyChannel), typeof(TeamsChannel))]
public sealed class TeamsChannel(ConnectionManager connections, IHttpClientFactory clients, IOptions<NotifyOptions> options) : INotifyChannel, ITransientDependency
{
    public string Key => TeamsConnectionKind.Key;

    public IReadOnlyList<string> Kinds { get; } = [NotifyTemplateKinds.Message];

    public async Task<bool> ReadyAsync(CancellationToken cancellationToken) => (await connections.ListOfTypeAsync(TeamsConnectionKind.Key, null, cancellationToken)).Count > 0;

    public bool IsAddress(string address) => ChatAddress.TryParse(address, out _, out _);

    public Task<string?> AddressAsync(NotifyPerson person, CancellationToken cancellationToken) => Task.FromResult<string?>(null);

    public async Task DeliverAsync(NotifyDelivery delivery, CancellationToken cancellationToken)
    {
        if (!ChatAddress.TryParse(delivery.Address, out Guid connectionId, out _))
        {
            throw new InvalidOperationException($"{delivery.Address} isn't a Teams address.");
        }

        ConnectionInUse connection = await connections.GetForUseAsync(connectionId, cancellationToken)
            ?? throw new InvalidOperationException("The Teams connection this was for is gone.");
        object card = new
        {
            type = "message",
            attachments = new[]
            {
                new
                {
                    contentType = "application/vnd.microsoft.card.adaptive",
                    content = new Dictionary<string, object>
                    {
                        ["$schema"] = "https://adaptivecards.io/schemas/adaptive-card.json", ["type"] = "AdaptiveCard", ["version"] = "1.4",
                        ["body"] = new[] { new { type = "TextBlock", text = delivery.Markdown, wrap = true } },
                    },
                },
            },
        };
        using HttpResponseMessage response = await clients.CreateClient(options.Value.HttpClientName)
            .PostAsJsonAsync(connection.Secrets.GetValueOrDefault("webhookUrl"), card, cancellationToken);
        response.EnsureSuccessStatusCode();
    }
}
