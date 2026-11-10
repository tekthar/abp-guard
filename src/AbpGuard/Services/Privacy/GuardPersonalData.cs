using AbpGuard.Domain;
using Volo.Abp.DependencyInjection;
using To = AbpGuard.PersonalDataDestinations;
using static AbpGuard.PersonalDataKinds;

namespace AbpGuard.Services.Privacy;

/// <summary>
/// What Guard keeps about people (the data map): accounts, who is in which group, what proves who people are,
/// where they're signed in, and the security log. Every table of Guard's and OpenIddict's is here or among the tables
/// holding nothing about people; a host's own tests check that.
/// </summary>
[ExposeServices(typeof(IPersonalDataDeclarations))]
public sealed class GuardPersonalData(Microsoft.Extensions.Options.IOptions<GuardOptions>? options = null) : IPersonalDataDeclarations, ITransientDependency
{
    /// <summary>A text in English and Arabic with the host's product named in each.</summary>
    private static LocalizedText Named(Microsoft.Extensions.Options.IOptions<GuardOptions>? options, string en, string ar) =>
        new(NamedIn(options, en, "en"), NamedIn(options, ar, "ar"));

    private static string NamedIn(Microsoft.Extensions.Options.IOptions<GuardOptions>? options, string text, string language) =>
        GuardMessageTemplates.Naming(text, language, (options?.Value.Texts ?? new GuardTextOptions()).ProductName);

    private const string Owner = "guard";

    public IReadOnlyList<PersonalDataStore> Stores { get; } =
    [
        new("guard.accounts", Owner,
            new("Accounts", "الحسابات"),
            new("Who people are: usernames, names and email addresses, as each directory reports them, with the addresses people add and the accounts merged into others. "
                + "An account is deactivated, never deleted, so history keeps its name; someone who signed up and never confirmed stays too.",
                "من هم الأشخاص: أسماء المستخدمين والأسماء وعناوين البريد كما يذكرها كل دليل، مع العناوين التي يضيفونها والحسابات المدمجة في غيرها. "
                + "يُعطَّل الحساب ولا يُحذف أبدًا ليبقى اسمه في السجل، ويبقى كذلك من سجّل ولم يؤكّد."),
            ["guard.accounts", "guard.account_emails", "guard.directory_users", "guard.account_merges"], [],
            PersonalDataSubjects.Accounts, [Identity, Contact, Credentials, Activity], PersonalDataKept.Forever, [To.Directory, To.Mail], []),
        new("guard.access", Owner,
            new("Groups and roles", "المجموعات والأدوار"),
            Named(options, "Which groups people are in, from a directory or set in {product}, and the roles granted to them.",
                "المجموعات التي ينتمي إليها الأشخاص، من دليل أو في {product}، والأدوار الممنوحة لهم."),
            ["guard.memberships", "guard.role_grants"], [],
            PersonalDataSubjects.Accounts, [Identity], PersonalDataKept.WithAccount, [], []),
        new("guard.sign-in-secrets", Owner,
            new("Sign-in secrets", "أسرار الدخول"),
            new("Personal access tokens, second factors, recovery codes, codes sent for a second step and sign-ins waiting for one: kept hashed or encrypted, never shown again.",
                "رموز الوصول الشخصية والعوامل الثانية ورموز الاسترداد والرموز المرسلة للخطوة الثانية وعمليات الدخول التي تنتظرها: تُحفظ مجزّأة أو مشفّرة ولا تُعرض مرة أخرى."),
            ["guard.personal_access_tokens", "guard.second_factors", "guard.recovery_codes", "guard.sent_codes", "guard.sign_in_tickets"], [],
            PersonalDataSubjects.Accounts, [Credentials, Security], PersonalDataKept.WithAccount, [], []),
        new("guard.sessions", Owner,
            new("Sessions", "الجلسات"),
            new("Where people are signed in: browsers, with the browser and the address each came from, and the phone app and other apps people let sign them in. "
                + "A browser's session goes 30 days after it ends; an app's sign-ins and tokens stay when they expire or are revoked.",
                "أين سجّل الأشخاص دخولهم: المتصفحات مع المتصفح والعنوان الذي جاء منه كل منها، وتطبيق الهاتف والتطبيقات الأخرى التي أذنوا لها بإدخالهم. "
                + "تُحذف جلسة المتصفح بعد 30 يومًا من انتهائها، وتبقى عمليات دخول التطبيقات ورموزها بعد انتهائها أو إلغائها."),
            ["guard.sessions", "guard.session_handoffs", "guard.oidc_authorizations", "guard.oidc_tokens"], [],
            PersonalDataSubjects.Accounts, [Security, Activity], PersonalDataKept.Forever, [], []),
        new("guard.security-log", Owner,
            new("The security log", "سجل الأمان"),
            new("Sign-ins and their failures, exports, and every change to who may do what: who, when, from which address, and to what.",
                "عمليات الدخول وإخفاقاتها والتصدير وكل تغيير فيمن يحق له فعل ماذا: من ومتى ومن أي عنوان وعلى ماذا."),
            ["guard.security_events"], [],
            PersonalDataSubjects.Both, [Identity, Security, Activity], PersonalDataKept.Setting("guard.security_settings.RetentionDays", SecuritySettings.DefaultRetentionDays), [], []),
        new("guard.privacy-record", Owner,
            new("The record of processing", "سجل المعالجة"),
            new("Who the controller and the data protection officer are, with their contacts, and which admin recorded each store's legal basis and notes.",
                "من هما جهة التحكم ومسؤول حماية البيانات مع بيانات التواصل، وأي مشرف سجّل الأساس النظامي لكل مخزن وملاحظاته."),
            ["guard.privacy_stores", "guard.privacy_settings"], [],
            PersonalDataSubjects.Both, [Identity, Contact, Activity], PersonalDataKept.Forever, [], []),
        new("guard.events", Owner,
            new("Events waiting to go", "أحداث تنتظر الإرسال"),
            new("Changes to accounts and groups waiting to reach other modules, plugins and webhooks; they name the accounts.",
                "تغييرات الحسابات والمجموعات التي تنتظر الوصول إلى الوحدات الأخرى والإضافات وخطافات الويب، وفيها الحسابات."),
            ["guard.AbpEventOutbox"], [],
            PersonalDataSubjects.Accounts, [Identity, Activity], PersonalDataKept.UntilDone, [To.Webhooks], []),
        new("guard.limits", Owner,
            new("Counts against abuse", "عدّادات منع الإساءة"),
            new("Failed sign-ins and other tries counted by address, email or account, kept only as hashes for a day, when the site counts them in Guard's own table rather than the host's.",
                "محاولات الدخول الفاشلة وغيرها معدودة حسب العنوان أو البريد أو الحساب، محفوظة مجزّأة ليوم واحد فقط، حين يعدّها الموقع في جدول Guard نفسه لا في جدول المضيف."),
            ["guard.rate_limits"], [],
            PersonalDataSubjects.Both, [Security], PersonalDataKept.Days(1), [], []),
    ];

    public IReadOnlyList<NonPersonalTable> NotPersonal { get; } =
    [
        new("guard.directories", NamedIn(options, "the directories {product} reads people from, and their settings", "en")),
        new("guard.sync_runs", "when each directory sync ran and what it counted"),
        new("guard.groups", "groups and how they're kept"),
        new("guard.roles", "roles"),
        new("guard.role_rules", "what each role allows"),
        new("guard.permission_stamp", "a version number"),
        new("guard.signup_settings", "whether people may sign up, and from which domains"),
        new("guard.security_settings", "the site's security settings"),
        new("guard.oidc_applications", "the apps that may sign people in"),
        new("guard.oidc_scopes", "what those apps may ask for"),
        new("guard.oidc_keys", "the keys sign-in tokens are signed with"),
        new("guard.data_protection_keys", "the keys Data Protection protects secrets with, for a host that keeps them in Guard's database"),
    ];
}
