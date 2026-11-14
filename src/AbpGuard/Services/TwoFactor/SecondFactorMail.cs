namespace AbpGuard.Services.TwoFactor;

/// <summary>
/// The code of a second step, sent by email or as a message by SMS or WhatsApp. Sent as a secret: the mail
/// log keeps it without its text. These are the package's own texts; a host's admins may reword either in
/// Administration › Templates, and the code must stay in it.
/// </summary>
public static class SecondFactorMail
{
    public const string Code = GuardMessageKinds.SecondFactorCode;
    public const string CodeMessage = GuardMessageKinds.SecondFactorCodeMessage;

    private static Dictionary<string, string> Text(string en, string ar) => new() { ["en"] = en, ["ar"] = ar };

    private static readonly GuardTemplateVariable[] Variables =
    [
        new("recipient.name", Text("The person signing in", "الشخص الذي يسجّل الدخول")),
        new("code", Text("The code: six digits", "الرمز: ستة أرقام")),
        new("minutes", Text("How long the code works", "مدة صلاحية الرمز")),
        new("site", Text("The site's name", "اسم الموقع")),
    ];

    private static Dictionary<string, object?> Sample() => new()
    {
        ["recipient"] = new Dictionary<string, object?> { ["name"] = "Dana Dev", ["email"] = "dana@example.com", ["time_zone"] = "UTC" },
        ["code"] = "482913",
        ["minutes"] = 10,
        ["site"] = "Example (example.com)",
    };

    public static readonly GuardMessageTemplate CodeDefinition = new(
        Code,
        Email: true,
        Text("Sign-in code", "رمز تسجيل الدخول"),
        Text("Sent when someone signing in, or confirming it's them, asks for a code by email (two-factor sign-in).",
            "تُرسل عندما يطلب من يسجّل الدخول، أو يؤكد هويته، رمزًا بالبريد (التحقق بخطوتين)."),
        new Dictionary<string, GuardTemplateText>
        {
            ["en"] = new("{{ code }} is your {{ site }} code",
                "Hello {{ recipient.name }},\n\nYour code to sign in to {{ site }}:\n\n**{{ code }}**\n\n"
                + "It works for {{ minutes }} minutes, once. If you didn't just sign in, someone may know your password: change it."),
            ["ar"] = new("{{ code }} رمزك في {{ site }}",
                "مرحبًا {{ recipient.name }}،\n\nرمزك لتسجيل الدخول إلى {{ site }}:\n\n**{{ code }}**\n\n"
                + "يعمل لمدة {{ minutes }} دقائق، مرة واحدة. إن لم تكن تسجّل الدخول الآن، فقد يعرف أحدٌ كلمة مرورك: غيّرها."),
        },
        Variables,
        Sample());

    public const string Added = GuardMessageKinds.SecondFactorAdded;
    public const string Removed = GuardMessageKinds.SecondFactorRemoved;

    private static readonly GuardTemplateVariable[] ChangeVariables =
    [
        new("recipient.name", Text("The account's owner", "صاحب الحساب")),
        new("username", Text("The account's username", "اسم المستخدم للحساب")),
        new("change", Text("What changed, and who changed it, in a sentence", "ما الذي تغيّر ومن غيّره، في جملة")),
    ];

    private static Dictionary<string, object?> ChangeSample(string change) => new()
    {
        ["recipient"] = new Dictionary<string, object?> { ["name"] = "Dana Dev", ["email"] = "dana@example.com", ["time_zone"] = "UTC" },
        ["username"] = "dana",
        ["change"] = change,
    };

    /// <summary>Telling a person a second factor was added to their account, so they hear of one that wasn't theirs.</summary>
    public static readonly GuardMessageTemplate AddedDefinition = new(
        Added,
        Email: true,
        Text("A second factor added", "إضافة عامل ثانٍ"),
        Text("Sent when a passkey or an authenticator app is added to someone's account.", "تُرسل عند إضافة مفتاح مرور أو تطبيق مصادقة إلى حساب أحدهم."),
        new Dictionary<string, GuardTemplateText>
        {
            ["en"] = new("A second factor was added to your {product} account",
                "Hello {{ recipient.name }},\n\n{{ change }} It's on your {product} account {{ username }}.\n\n"
                + "If this wasn't you, someone may be signed in as you: change your password, sign out everywhere else, and tell your site's administrators at once."),
            ["ar"] = new("أُضيف عامل ثانٍ إلى حسابك في {product}",
                "مرحبًا {{ recipient.name }}،\n\n{{ change }} وذلك في حسابك في {product} {{ username }}.\n\n"
                + "إن لم تكن أنت، فقد يكون أحدٌ مسجّلًا الدخول باسمك: غيّر كلمة مرورك، وسجّل الخروج من كل مكان آخر، وأخبر مشرفي موقعك فورًا."),
        },
        ChangeVariables,
        ChangeSample("You added the passkey “Dana's phone” to your second factors."));

    /// <summary>Telling a person a second factor was removed from their account, by them or an admin.</summary>
    public static readonly GuardMessageTemplate RemovedDefinition = new(
        Removed,
        Email: true,
        Text("A second factor removed", "إزالة عامل ثانٍ"),
        Text("Sent when a passkey or an authenticator app is removed from someone's account, by them or an admin, or an admin resets them.",
            "تُرسل عند إزالة مفتاح مرور أو تطبيق مصادقة من حساب أحدهم، بيده أو بيد مشرف، أو عند إعادة مشرفٍ ضبطها."),
        new Dictionary<string, GuardTemplateText>
        {
            ["en"] = new("A second factor was removed from your {product} account",
                "Hello {{ recipient.name }},\n\n{{ change }} It was on your {product} account {{ username }}.\n\n"
                + "If you didn't expect this, change your password and tell your site's administrators at once."),
            ["ar"] = new("أُزيل عامل ثانٍ من حسابك في {product}",
                "مرحبًا {{ recipient.name }}،\n\n{{ change }} وذلك في حسابك في {product} {{ username }}.\n\n"
                + "إن لم تتوقع هذا، فغيّر كلمة مرورك وأخبر مشرفي موقعك فورًا."),
        },
        ChangeVariables,
        ChangeSample("An administrator removed the passkey “Dana's phone” from your second factors."));

    public static readonly GuardMessageTemplate CodeMessageDefinition = new(
        CodeMessage,
        Email: false,
        Text("Sign-in code (message)", "رمز تسجيل الدخول (رسالة)"),
        Text("The sign-in code in a line, for someone who asks for it by SMS or WhatsApp.", "رمز تسجيل الدخول في سطر، لمن يطلبه عبر الرسائل القصيرة أو واتساب."),
        new Dictionary<string, GuardTemplateText>
        {
            ["en"] = new(null, "{{ code }} is your {{ site }} code. It works for {{ minutes }} minutes. Don't share it."),
            ["ar"] = new(null, "{{ code }} رمزك في {{ site }}. يعمل لمدة {{ minutes }} دقائق. لا تشاركه مع أحد."),
        },
        Variables,
        Sample());
}

/// <summary>
/// What changed in a person's second factors, said in a sentence in their language (English, else Arabic for "ar"):
/// the <c>change</c> a notice's template puts in.
/// </summary>
public sealed record FactorChange(string English, string Arabic)
{
    public static FactorChange Added(string kind, string? name) => new(
        $"You added {What(kind, name, arabic: false)} to your second factors.",
        $"أضفتَ {What(kind, name, arabic: true)} إلى عواملك الثانية.");

    public static FactorChange Removed(string kind, string? name, bool byAdmin) => byAdmin
        ? new($"An administrator removed {What(kind, name, arabic: false)} from your second factors.", $"أزال أحد المشرفين {What(kind, name, arabic: true)} من عواملك الثانية.")
        : new($"You removed {What(kind, name, arabic: false)} from your second factors.", $"أزلتَ {What(kind, name, arabic: true)} من عواملك الثانية.");

    public static FactorChange Reset() => new(
        "An administrator reset your second factors: if your site asks for one, you'll set one up again when you next sign in.",
        "أعاد أحد المشرفين ضبط عواملك الثانية: إن طلب موقعك عاملًا ثانيًا، فستُعدّه من جديد عند تسجيل دخولك القادم.");

    public string In(string language) => language.StartsWith("ar", StringComparison.OrdinalIgnoreCase) ? Arabic : English;

    private static string What(string kind, string? name, bool arabic) => kind switch
    {
        Domain.SecondFactorKinds.Passkey when name is { Length: > 0 } => arabic ? $"مفتاح المرور «{name}»" : $"the passkey “{name}”",
        Domain.SecondFactorKinds.Passkey => arabic ? "مفتاح مرور" : "a passkey",
        _ => arabic ? "تطبيق مصادقة" : "an authenticator app",
    };
}
