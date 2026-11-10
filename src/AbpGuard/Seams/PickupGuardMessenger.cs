using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AbpGuard;

/// <summary>
/// The default messenger: email only, each message rendered from Guard's texts, or the host's
/// (<see cref="GuardOptions.Texts"/>), in the recipient's language, else the message's, else English, and written as a
/// file to <see cref="GuardMessengerOptions.PickupFolder"/>, for Development and tests. Without a folder nothing reaches
/// anyone, and a send says so. It never logs a message's text.
/// </summary>
public sealed partial class PickupGuardMessenger(IOptions<GuardOptions> options, IAccountLookup accounts, ILogger<PickupGuardMessenger> logger) : IGuardMessenger
{
    private const int TimeoutMilliseconds = 1000;

    private string? Folder => options.Value.Messenger.PickupFolder is { Length: > 0 } folder ? folder : null;

    public Task<IReadOnlyList<GuardChannel>> ReachAsync(Guid accountId, string? emailAddress, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<GuardChannel>>(Folder is not null && emailAddress is { Length: > 0 } address
            ? [new GuardChannel("email", "Email", address)]
            : []);

    public Task<IReadOnlyList<GuardMethod>> MethodsAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<GuardMethod>>([new GuardMethod("email", "Email", Folder is not null)]);

    public async Task<GuardSendResult> SendAsync(GuardMessage message, CancellationToken cancellationToken)
    {
        string? to = message.Address;
        string? name = message.Name;
        string? language = message.Language;
        if (message.AccountId is { } accountId && await accounts.GetAsync(accountId, cancellationToken) is { } account)
        {
            to ??= account.Email;
            name ??= account.DisplayName;
            language = account.Language ?? language;
        }

        if (Folder is not { } folder || message.Channel is not null || to is not { Length: > 0 }
            || GuardMessageTemplates.Find(options.Value.Texts, message.Kind) is not { } template)
        {
            logger.LogWarning("Guard's {Kind} message reached no one: the default messenger sends email to a pickup folder only", message.Kind);
            return new GuardSendResult(0, 1);
        }

        GuardTemplateText text = template.Texts.TryGetValue(language ?? "", out GuardTemplateText? chosen) ? chosen : template.Texts["en"];
        Dictionary<string, object?> model = new(message.Model)
        {
            ["recipient"] = new Dictionary<string, object?> { ["name"] = OneLine(name ?? to), ["email"] = OneLine(to) },
        };

        StringBuilder mail = new();
        // A header is one line: a name, an address or a subject with a line break in it would start headers of its own.
        string address = OneLine(to).Replace("<", "", StringComparison.Ordinal).Replace(">", "", StringComparison.Ordinal);
        string? shown = name is { Length: > 0 } ? OneLine(name).Replace("\"", "", StringComparison.Ordinal).Replace("\\", "", StringComparison.Ordinal) : null;
        mail.Append("To: ").Append(shown is { Length: > 0 } ? $"\"{shown}\" <{address}>" : address).Append("\r\n");
        mail.Append("Subject: ").Append(OneLine(Render(text.Subject ?? template.Names["en"], model))).Append("\r\n");
        mail.Append("Content-Type: text/plain; charset=utf-8\r\n");
        mail.Append("X-Guard-Kind: ").Append(message.Kind).Append("\r\n\r\n");
        mail.Append(Render(text.Body, model)).Append("\r\n");

        Directory.CreateDirectory(folder);
        string file = Path.Combine(folder, $"{DateTime.UtcNow:yyyyMMddHHmmssfff}-{Guid.NewGuid():N}.eml");
        await File.WriteAllTextAsync(file, mail.ToString(), Encoding.UTF8, cancellationToken);
        return new GuardSendResult(1, 0);
    }

    /// <summary>The text on one line: each control character, and Unicode's line and paragraph separators, a space.</summary>
    public static string OneLine(string text) =>
        string.Create(text.Length, text, static (span, source) =>
        {
            for (int i = 0; i < source.Length; i++)
            {
                char c = source[i];
                span[i] = char.IsControl(c) || c is '\u2028' or '\u2029' ? ' ' : c;
            }
        });

    /// <summary>Each <c>{{ name }}</c> or <c>{{ a.b }}</c> with its value from the model; one that isn't there is left empty.</summary>
    public static string Render(string text, IReadOnlyDictionary<string, object?> model) =>
        Placeholder().Replace(text, match =>
        {
            object? value = model;
            foreach (string part in match.Groups[1].Value.Split('.'))
            {
                value = value is IReadOnlyDictionary<string, object?> map && map.TryGetValue(part, out object? next) ? next
                    : value is IDictionary<string, object?> dictionary && dictionary.TryGetValue(part, out object? other) ? other
                    : null;
            }

            return Convert.ToString(value, CultureInfo.InvariantCulture) ?? "";
        });

    [GeneratedRegex(@"\{\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\}\}", RegexOptions.None, TimeoutMilliseconds)]
    private static partial Regex Placeholder();
}
