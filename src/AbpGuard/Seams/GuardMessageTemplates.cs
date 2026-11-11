using AbpGuard.Services.Privacy;

namespace AbpGuard;

/// <summary>The kinds of message Guard sends; each is also the key of its template.</summary>
public static class GuardMessageKinds
{
    /// <summary>Confirming the email of someone who signed up.</summary>
    public const string SignUpVerify = "guard.signup-verify";

    /// <summary>A link to choose a new password.</summary>
    public const string PasswordReset = "guard.password-reset";

    /// <summary>Confirming an address someone added to their account.</summary>
    public const string AddressVerify = "guard.email-verify";

    /// <summary>Telling an address that it's no longer the account's primary (a correction).</summary>
    public const string AddressChanged = "guard.email-changed";

    /// <summary>Site admins told of a possible breach.</summary>
    public const string SecurityAlert = Services.SecurityAlerts.MessageKind;

    /// <summary>A second step's code by email.</summary>
    public const string SecondFactorCode = "guard.second-factor-code";

    /// <summary>A second step's code in a line, by SMS, WhatsApp or another channel.</summary>
    public const string SecondFactorCodeMessage = SecondFactorCode + ".message";

    /// <summary>
    /// Whether the kind carries a link or a code that works for someone (all of Guard's but the notices, AddressChanged and
    /// SecurityAlert): then it's sent as a secret, so the mail log keeps neither its text nor its subject, and an admin
    /// reading it can't use a reset or a code.
    /// </summary>
    public static bool CarriesSecret(string kind) => kind is SignUpVerify or PasswordReset or AddressVerify or SecondFactorCode or SecondFactorCodeMessage;
}

/// <summary>A template's subject (an email's; null for a message) and body, in Markdown with <c>{{ name }}</c> values.</summary>
public sealed record GuardTemplateText(string? Subject, string Body);

/// <summary>A value a template may use, with what it holds by language.</summary>
public sealed record GuardTemplateVariable(string Name, IReadOnlyDictionary<string, string> Descriptions);

/// <summary>
/// The package's own texts for one kind of message, by language: what the default messenger renders, and what a host starts
/// from (as templates its admins may reword, say). <paramref name="Email"/> is false for a message (a line for SMS or
/// chat), which has no subject.
/// </summary>
public sealed record GuardMessageTemplate(
    string Key,
    bool Email,
    IReadOnlyDictionary<string, string> Names,
    IReadOnlyDictionary<string, string> Descriptions,
    IReadOnlyDictionary<string, GuardTemplateText> Texts,
    IReadOnlyList<GuardTemplateVariable> Variables,
    IReadOnlyDictionary<string, object?> Sample);

/// <summary>
/// The texts a host gives Guard's messages without forking it: the product's name in Guard's own texts, and a whole
/// template of its own for any kind.
/// </summary>
public sealed class GuardTextOptions
{
    /// <summary>
    /// The product's name by language, where Guard's own texts say <see cref="GuardMessageTemplates.ProductMarker"/>; a
    /// language without one uses English's, and without any, <see cref="GuardMessageTemplates.DefaultProductName"/>.
    /// </summary>
    public Dictionary<string, string> ProductName { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// A host's own template for a kind (<see cref="GuardMessageKinds"/>), in place of Guard's, set in code; start from
    /// <see cref="GuardMessageTemplates.For"/>'s and change what differs (<c>template with { Texts = ... }</c>).
    /// </summary>
    public Dictionary<string, GuardMessageTemplate> Messages { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// The record of processing's words by language, English and Arabic by default: a host adds a language, or
    /// rewords one (<c>ProcessingRecordTexts.English with { Title = ... }</c>).
    /// </summary>
    public Dictionary<string, ProcessingRecordTexts> Record { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["en"] = ProcessingRecordTexts.English,
        ["ar"] = ProcessingRecordTexts.Arabic,
    };

    /// <summary>A person's data export's words by language (its README and why a store isn't in it), as <see cref="Record"/>.</summary>
    public Dictionary<string, PersonalDataExportTexts> Export { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["en"] = PersonalDataExportTexts.English,
        ["ar"] = PersonalDataExportTexts.Arabic,
    };

    /// <summary>The product's name in a language ("ar" for "ar-SA"), else its English name: what Guard's texts call the host.</summary>
    public string Product(string language = "en") => GuardMessageTemplates.ProductIn(ProductName, Base(language));

    /// <summary>The record's words in a language ("ar" for "ar-SA"), English's when it has none, naming the host's product.</summary>
    public ProcessingRecordTexts RecordIn(string language)
    {
        string lang = Base(language);
        ProcessingRecordTexts texts = Record.TryGetValue(lang, out ProcessingRecordTexts? own) ? own
            : Record.TryGetValue("en", out ProcessingRecordTexts? english) ? english : ProcessingRecordTexts.English;
        return texts with { Subjects = texts.Subjects.ToDictionary(p => p.Key, p => GuardMessageTemplates.Naming(p.Value, lang, ProductName)) };
    }

    /// <summary>The export's words in a language ("ar" for "ar-SA"), English's when it has none.</summary>
    public PersonalDataExportTexts ExportIn(string language) =>
        Export.TryGetValue(Base(language), out PersonalDataExportTexts? own) ? own
        : Export.TryGetValue("en", out PersonalDataExportTexts? english) ? english : PersonalDataExportTexts.English;

    private static string Base(string language) => language.Split('-', 2)[0].ToLowerInvariant();
}

/// <summary>Guard's own texts for every kind of message it sends, English and Arabic.</summary>
public static class GuardMessageTemplates
{
    /// <summary>Where Guard's own texts name the host's product: replaced with its name before anyone sees them.</summary>
    public const string ProductMarker = "{product}";

    /// <summary>The product's name when the host gives none (Guard:Texts:ProductName): every site should give its own.</summary>
    public const string DefaultProductName = "AbpGuard";

    private static readonly GuardMessageTemplate[] Builtin =
    [
        Services.SelfServiceMail.VerifyDefinition,
        Services.SelfServiceMail.ResetDefinition,
        Services.AddressMail.VerifyDefinition,
        Services.AddressMail.ChangedDefinition,
        Services.TwoFactor.SecondFactorMail.CodeDefinition,
        Services.TwoFactor.SecondFactorMail.CodeMessageDefinition,
        Services.SecurityAlerts.Definition,
    ];

    /// <summary>Guard's own texts, as they are: <see cref="ProductMarker"/> where the product's name goes.</summary>
    public static IReadOnlyList<GuardMessageTemplate> All => Builtin;

    /// <summary>The templates a host's messages use: its own where it gave one, else Guard's, naming its product.</summary>
    public static IReadOnlyList<GuardMessageTemplate> For(GuardTextOptions texts) =>
        [.. Builtin.Select(t => texts.Messages.TryGetValue(t.Key, out GuardMessageTemplate? own) ? own : Named(t, texts.ProductName))];

    public static GuardMessageTemplate? Find(GuardTextOptions texts, string key) => For(texts).FirstOrDefault(t => t.Key == key);

    /// <summary>A text of Guard's in a language with the host's product named where it says <see cref="ProductMarker"/>.</summary>
    internal static string Naming(string text, string language, IReadOnlyDictionary<string, string> product) =>
        text.Replace(ProductMarker, ProductIn(product, language), StringComparison.Ordinal);

    /// <summary>The product's name in a language, else its English name, else Guard's own.</summary>
    internal static string ProductIn(IReadOnlyDictionary<string, string> product, string language) =>
        product.TryGetValue(language, out string? own) && own is { Length: > 0 } ? own
        : product.TryGetValue("en", out string? english) && english is { Length: > 0 } ? english
        : DefaultProductName;

    /// <summary>The template with the host's product named, language by language.</summary>
    private static GuardMessageTemplate Named(GuardMessageTemplate template, IReadOnlyDictionary<string, string> product)
    {
        string In(string language, string text) => Naming(text, language, product);
        Dictionary<string, string> Each(IReadOnlyDictionary<string, string> texts) => texts.ToDictionary(p => p.Key, p => In(p.Key, p.Value));

        return template with
        {
            Names = Each(template.Names),
            Descriptions = Each(template.Descriptions),
            Texts = template.Texts.ToDictionary(p => p.Key, p => new GuardTemplateText(p.Value.Subject is { } subject ? In(p.Key, subject) : null, In(p.Key, p.Value.Body))),
        };
    }
}
