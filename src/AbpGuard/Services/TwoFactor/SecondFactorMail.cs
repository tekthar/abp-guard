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
