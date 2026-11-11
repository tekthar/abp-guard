using System.Globalization;
using System.Text;
using AbpGuard.Domain;

namespace AbpGuard.Services.Privacy;

/// <summary>
/// The words of a record of processing in one language; <c>{0}</c> takes a number or a name where a text has one. A host
/// rewords them or adds a language in <see cref="GuardTextOptions.Record"/> (Guard:Texts).
/// </summary>
public sealed record ProcessingRecordTexts
{
    public required string Title { get; init; }
    public required string Intro { get; init; }
    public required string Controller { get; init; }
    public required string Officer { get; init; }
    public required string Name { get; init; }
    public required string Contact { get; init; }
    public required string NotRecorded { get; init; }
    public required string Activities { get; init; }
    public required string Store { get; init; }
    public required string Owner { get; init; }
    public required string Purpose { get; init; }
    public required string About { get; init; }
    public required string Kinds { get; init; }
    public required string LegalBasis { get; init; }
    public required string Recipients { get; init; }
    public required string OutsideCountry { get; init; }
    public required string SiteCountry { get; init; }

    /// <summary>The privacy notice's heading, its version ({0} the version, {1} the date), and the gap when none is published.</summary>
    public string Notice { get; init; } = "The privacy notice";

    public string NoticeVersion { get; init; } = "Version {0}, published {1}; people accept it on signing up and on the portal, and are asked again when it changes.";

    public string NoNotice { get; init; } = "None published yet: publish it in Administration › Privacy.";

    /// <summary>Whether apps may register themselves, and what each says.</summary>
    public string AppsRegister { get; init; } = "Apps that register themselves";

    public string AppsRegisterOn { get; init; } = "On: an app may register itself, and once a person allows it, it reads what they may. Turn it off in Administration › Security audit unless the site needs it.";

    public string AppsRegisterOff { get; init; } = "Off: only apps a site admin adds may ask people to allow them.";

    /// <summary>The security log's feed: where it goes ({0} its host), or that it's off.</summary>
    public string Feed { get; init; } = "The security log's feed";

    public string FeedOn { get; init; } = "On, to {0}: it receives the security log as it's written, with usernames and network addresses; what it received can't be erased from here.";

    public string FeedOff { get; init; } = "Off.";
    public required string Service { get; init; }
    public required string Kept { get; init; }
    public required string Sensitive { get; init; }
    public required string Notes { get; init; }
    public required string StaysOnSite { get; init; }
    public required string Yes { get; init; }
    public required string No { get; init; }
    public required string Undecided { get; init; }
    public required string Removed { get; init; }
    public required string Gaps { get; init; }
    public required string NoCountry { get; init; }
    public required string NoLegalBasis { get; init; }
    public required string DoesntSay { get; init; }
    public required string HasProblems { get; init; }
    public required string NoGaps { get; init; }
    public required string UntilDone { get; init; }
    public required string WithAccount { get; init; }
    public required string Forever { get; init; }
    public required string Days { get; init; }
    public required string Setting { get; init; }
    public required IReadOnlyDictionary<string, string> Modules { get; init; }
    public required IReadOnlyDictionary<string, string> Subjects { get; init; }
    public required IReadOnlyDictionary<string, string> KindNames { get; init; }
    public required IReadOnlyDictionary<string, string> DestinationNames { get; init; }
    public required IReadOnlyDictionary<string, string> LegalBasisNames { get; init; }

    public static readonly ProcessingRecordTexts English = new()
    {
        Title = "Record of processing activities",
        Intro = "What this site keeps about people, why, for how long and where it goes, as its modules and plugins declare it and its admins recorded it, on {0}.",
        Controller = "Controller",
        Officer = "Data protection officer",
        Name = "Name",
        Contact = "Contact",
        NotRecorded = "not recorded yet",
        Activities = "Processing activities",
        Store = "Store",
        Owner = "Kept by",
        Purpose = "Purpose",
        About = "Whom it's about",
        Kinds = "Personal data",
        LegalBasis = "Legal basis",
        Recipients = "Who receives it",
        OutsideCountry = "Outside the site's country",
        SiteCountry = "The site's country",
        Service = "the service {0}",
        Kept = "Kept today",
        Sensitive = "May hold sensitive data",
        Notes = "Notes",
        StaysOnSite = "stays on the site",
        Yes = "yes",
        No = "no",
        Undecided = "not decided",
        Removed = "uninstalled; what it kept may remain",
        Gaps = "Gaps",
        NoCountry = "The site's country isn't recorded, so what leaves it can't be said",
        NoLegalBasis = "Stores with no legal basis yet",
        DoesntSay = "Plugins that don't say what they keep about people",
        HasProblems = "Plugins whose declaration has problems",
        NoGaps = "None.",
        UntilDone = "until it's done its work",
        WithAccount = "while the account is kept",
        Forever = "for ever",
        Days = "{0} days",
        Setting = "{0} days by default ({1})",
        Modules = new Dictionary<string, string> { ["guard"] = "Accounts and sign-in", ["platform"] = "Platform", ["projects"] = "Projects", ["assets"] = "Assets" },
        Subjects = new Dictionary<string, string>
            { [PersonalDataSubjects.Accounts] = "people with accounts", [PersonalDataSubjects.Outside] = "people outside {product}, known by an address", [PersonalDataSubjects.Both] = "people with accounts and people outside {product}" },
        KindNames = new Dictionary<string, string>
        {
            [PersonalDataKinds.Identity] = "identity", [PersonalDataKinds.Contact] = "contact details", [PersonalDataKinds.Credentials] = "sign-in secrets",
            [PersonalDataKinds.Security] = "addresses and devices", [PersonalDataKinds.Activity] = "activity", [PersonalDataKinds.Content] = "what people write or upload",
            [PersonalDataKinds.Preferences] = "preferences",
        },
        DestinationNames = new Dictionary<string, string>
        {
            [PersonalDataDestinations.Mail] = "the mail server", [PersonalDataDestinations.Sms] = "the SMS provider", [PersonalDataDestinations.WhatsApp] = "WhatsApp",
            [PersonalDataDestinations.Chat] = "chat (Slack, Teams)", [PersonalDataDestinations.Push] = "phone notifications", [PersonalDataDestinations.Webhooks] = "webhooks",
            [PersonalDataDestinations.Ai] = "AI providers", [PersonalDataDestinations.OutsideMcp] = "outside MCP servers", [PersonalDataDestinations.GitHosts] = "git hosts",
            [PersonalDataDestinations.Storage] = "file storage", [PersonalDataDestinations.Backups] = "backup places", [PersonalDataDestinations.Directory] = "the LDAP directory",
        },
        LegalBasisNames = new Dictionary<string, string>
        {
            [LegalBases.Consent] = "consent", [LegalBases.Agreement] = "an agreement with the person", [LegalBases.LegalObligation] = "a legal obligation",
            [LegalBases.PublicTask] = "a public task", [LegalBases.VitalInterest] = "a vital interest", [LegalBases.LegitimateInterest] = "a legitimate interest",
        },
    };

    public static readonly ProcessingRecordTexts Arabic = new()
    {
        Title = "سجل أنشطة المعالجة",
        Intro = "ما يحفظه هذا الموقع عن الأشخاص ولماذا وإلى متى وإلى أين يذهب، كما تعلنه وحداته وإضافاته وكما سجّله مشرفوه، في {0}.",
        Controller = "جهة التحكم",
        Officer = "مسؤول حماية البيانات",
        Name = "الاسم",
        Contact = "التواصل",
        NotRecorded = "لم يُسجَّل بعد",
        Activities = "أنشطة المعالجة",
        Store = "المخزن",
        Owner = "يحفظه",
        Purpose = "الغرض",
        About = "عمّن هو",
        Kinds = "البيانات الشخصية",
        LegalBasis = "الأساس النظامي",
        Recipients = "من يتلقاها",
        OutsideCountry = "خارج بلد الموقع",
        SiteCountry = "بلد الموقع",
        Notice = "إشعار الخصوصية",
        NoticeVersion = "الإصدار {0}، نُشر في {1}؛ يقبله الأشخاص عند التسجيل وفي البوابة، ويُسألون مجددًا عند تغييره.",
        NoNotice = "لم يُنشر بعد: انشره من الإدارة › الخصوصية.",
        AppsRegister = "التطبيقات التي تسجّل نفسها",
        AppsRegisterOn = "مفعّل: يمكن لتطبيق أن يسجّل نفسه، ومتى أذن له شخص قرأ ما يحق له. أوقفه من الإدارة › سجل الأمان ما لم يحتجه الموقع.",
        AppsRegisterOff = "متوقف: لا يطلب إذن الأشخاص إلا التطبيقات التي يضيفها مشرف الموقع.",
        Feed = "تغذية سجل الأمان",
        FeedOn = "مفعّلة، إلى {0}: يستقبل سجل الأمان عند كتابته، بأسماء المستخدمين وعناوين الشبكة، وما استقبله لا يمكن محوه من هنا.",
        FeedOff = "متوقفة.",
        Service = "الخدمة {0}",
        Kept = "مدة الحفظ حاليًا",
        Sensitive = "قد يحوي بيانات حساسة",
        Notes = "ملاحظات",
        StaysOnSite = "تبقى في الموقع",
        Yes = "نعم",
        No = "لا",
        Undecided = "لم يُحدَّد",
        Removed = "أُزيلت؛ قد يبقى ما حفظته",
        Gaps = "النواقص",
        NoCountry = "لم يُسجَّل بلد الموقع، فلا يمكن القول ما الذي يغادره",
        NoLegalBasis = "مخازن بلا أساس نظامي بعد",
        DoesntSay = "إضافات لا تذكر ما تحفظه عن الأشخاص",
        HasProblems = "إضافات في إعلانها مشكلات",
        NoGaps = "لا شيء.",
        UntilDone = "حتى ينتهي عمله",
        WithAccount = "ما دام الحساب محفوظًا",
        Forever = "دائمًا",
        Days = "{0} يومًا",
        Setting = "{0} يومًا افتراضيًا ({1})",
        Modules = new Dictionary<string, string> { ["guard"] = "الحسابات والدخول", ["platform"] = "المنصة", ["projects"] = "المشاريع", ["assets"] = "الأصول" },
        Subjects = new Dictionary<string, string>
            { [PersonalDataSubjects.Accounts] = "أصحاب الحسابات", [PersonalDataSubjects.Outside] = "أشخاص من خارج {product} يُعرفون بعنوان", [PersonalDataSubjects.Both] = "أصحاب الحسابات وأشخاص من خارج {product}" },
        KindNames = new Dictionary<string, string>
        {
            [PersonalDataKinds.Identity] = "الهوية", [PersonalDataKinds.Contact] = "بيانات التواصل", [PersonalDataKinds.Credentials] = "أسرار الدخول",
            [PersonalDataKinds.Security] = "العناوين والأجهزة", [PersonalDataKinds.Activity] = "النشاط", [PersonalDataKinds.Content] = "ما يكتبه الأشخاص أو يرفعونه",
            [PersonalDataKinds.Preferences] = "التفضيلات",
        },
        DestinationNames = new Dictionary<string, string>
        {
            [PersonalDataDestinations.Mail] = "خادم البريد", [PersonalDataDestinations.Sms] = "مزوّد الرسائل النصية", [PersonalDataDestinations.WhatsApp] = "واتساب",
            [PersonalDataDestinations.Chat] = "المحادثة (Slack وTeams)", [PersonalDataDestinations.Push] = "إشعارات الهاتف", [PersonalDataDestinations.Webhooks] = "خطافات الويب",
            [PersonalDataDestinations.Ai] = "مزوّدو الذكاء الاصطناعي", [PersonalDataDestinations.OutsideMcp] = "خوادم MCP الخارجية", [PersonalDataDestinations.GitHosts] = "مستضيفو git",
            [PersonalDataDestinations.Storage] = "تخزين الملفات", [PersonalDataDestinations.Backups] = "أماكن النسخ الاحتياطي", [PersonalDataDestinations.Directory] = "دليل LDAP",
        },
        LegalBasisNames = new Dictionary<string, string>
        {
            [LegalBases.Consent] = "الموافقة", [LegalBases.Agreement] = "اتفاق مع صاحب البيانات", [LegalBases.LegalObligation] = "التزام نظامي",
            [LegalBases.PublicTask] = "مهمة عامة", [LegalBases.VitalInterest] = "مصلحة حيوية", [LegalBases.LegitimateInterest] = "مصلحة مشروعة",
        },
    };
}

/// <summary>
/// The record of processing, what PDPL asks a controller to keep: the controller and the officer;
/// the site's country; each store as a processing activity with its purpose, whom it's about, its kinds of data, legal
/// basis, recipients, whether it leaves the site's country, how long it's kept and whether it may hold sensitive data;
/// then the gaps.
/// </summary>
public static class ProcessingRecord
{
    public const string Markdown = "markdown";
    public const string Csv = "csv";

    public static string ToMarkdown(PrivacyMapDto map, ProcessingRecordTexts t, string language, DateTime on)
    {
        StringBuilder md = new();
        md.Append("# ").Append(t.Title).Append("\n\n").Append(string.Format(CultureInfo.InvariantCulture, t.Intro, on.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture))).Append("\n\n");
        foreach ((string heading, PrivacyContactDto who) in new[] { (t.Controller, map.Settings.Controller), (t.Officer, map.Settings.Officer) })
        {
            md.Append("## ").Append(heading).Append("\n\n")
                .Append("- ").Append(t.Name).Append(": ").Append(Line(who.Name) ?? t.NotRecorded).Append('\n')
                .Append("- ").Append(t.Contact).Append(": ").Append(Line(who.Contact) ?? t.NotRecorded).Append("\n\n");
        }

        md.Append("## ").Append(t.SiteCountry).Append("\n\n").Append(Line(map.Settings.Country) ?? t.NotRecorded).Append("\n\n");
        md.Append("## ").Append(t.Notice).Append("\n\n").Append(map.Settings.NoticeVersion is { } version
            ? string.Format(CultureInfo.InvariantCulture, t.NoticeVersion, version, map.Settings.NoticePublishedAt?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture))
            : t.NoNotice).Append("\n\n");
        md.Append("## ").Append(t.AppsRegister).Append("\n\n").Append(map.Settings.AppsMayRegister ? t.AppsRegisterOn : t.AppsRegisterOff).Append("\n\n");
        md.Append("## ").Append(t.Feed).Append("\n\n").Append(map.Settings.SecurityFeedHost is { } feedHost
            ? string.Format(CultureInfo.InvariantCulture, t.FeedOn, feedHost) : t.FeedOff).Append("\n\n");
        md.Append("## ").Append(t.Activities).Append('\n');
        foreach (Row row in Rows(map, t, language))
        {
            md.Append("\n### ").Append(Line(row.Name)).Append(" (`").Append(row.Key).Append("`)\n\n");
            foreach ((string label, string value) in row.Fields(t))
            {
                md.Append("- ").Append(label).Append(": ").Append(Line(value)).Append('\n');
            }
        }

        md.Append("\n## ").Append(t.Gaps).Append("\n\n");
        // Every "outside the site's country" rests on it, so a site that hasn't said its country has that gap first.
        if (Line(map.Settings.Country) is null)
        {
            md.Append("**").Append(t.NoCountry).Append("**\n\n");
        }

        List<string> unrecorded = [.. map.Stores.Where(s => s.Recorded?.LegalBasis is null).Select(s => $"{Line(Text(s.Name, language))} (`{s.Key}`)")];
        List<string> silent = [.. map.Plugins.Where(p => p.PersonalData.State == PersonalDataDeclaration.States.DoesntSay).Select(p => $"{Line(Text(p.Name, language))} (`{p.Key}`)")];
        List<string> broken = [.. map.Plugins.Where(p => p.PersonalData.State == PersonalDataDeclaration.States.Problems)
            .Select(p => $"{Line(Text(p.Name, language))} (`{p.Key}`): {Line(string.Join("; ", p.PersonalData.Problems))}")];
        foreach ((string heading, List<string> items) in new[] { (t.NoLegalBasis, unrecorded), (t.DoesntSay, silent), (t.HasProblems, broken) })
        {
            md.Append("**").Append(heading).Append("**: ").Append(items.Count == 0 ? t.NoGaps : "").Append('\n');
            foreach (string item in items)
            {
                md.Append("- ").Append(item).Append('\n');
            }

            md.Append('\n');
        }

        return md.ToString();
    }

    /// <summary>A row a store, with a byte-order mark so a spreadsheet reads it as UTF-8 (Arabic too).</summary>
    public static string ToCsv(PrivacyMapDto map, ProcessingRecordTexts t, string language)
    {
        StringBuilder csv = new("﻿");
        csv.AppendJoin(',', new[] { "key", t.Store, t.Owner, t.Purpose, t.About, t.Kinds, t.LegalBasis, t.Recipients, t.OutsideCountry, t.Kept, t.Sensitive, t.Notes }.Select(Cell))
            .Append("\r\n");
        foreach (Row row in Rows(map, t, language))
        {
            csv.AppendJoin(',', new[] { row.Key, row.Name }.Concat(row.Fields(t).Select(f => f.Value)).Select(Cell)).Append("\r\n");
        }

        return csv.ToString();
    }

    private sealed record Row(string Key, string Name, string Owner, string Purpose, string About, string Kinds, string LegalBasis, string Recipients,
        string Outside, string Kept, string Sensitive, string Notes)
    {
        public IEnumerable<(string Label, string Value)> Fields(ProcessingRecordTexts t) =>
        [
            (t.Owner, Owner), (t.Purpose, Purpose), (t.About, About), (t.Kinds, Kinds), (t.LegalBasis, LegalBasis), (t.Recipients, Recipients),
            (t.OutsideCountry, Outside), (t.Kept, Kept), (t.Sensitive, Sensitive), (t.Notes, Notes),
        ];
    }

    private static IEnumerable<Row> Rows(PrivacyMapDto map, ProcessingRecordTexts t, string language)
    {
        Dictionary<string, InstalledPlugin> plugins = map.Plugins.ToDictionary(p => p.Key);
        foreach (PrivacyStoreDto s in map.Stores)
        {
            string owner = s.OwnerKind == PrivacyStoreDto.Plugin && plugins.TryGetValue(s.Owner, out InstalledPlugin? plugin)
                ? Text(plugin.Name, language) + (plugin.State == InstalledPlugin.States.Removed ? $" ({t.Removed})" : "")
                : t.Modules.GetValueOrDefault(s.Owner, s.Owner);
            List<string> recipients = [];
            List<string> outside = [];
            foreach (string destination in s.GoesTo)
            {
                string name = PersonalDataDestinations.IsService(destination)
                    ? string.Format(CultureInfo.InvariantCulture, t.Service, destination[PersonalDataDestinations.ServicePrefix.Length..])
                    : t.DestinationNames.GetValueOrDefault(destination, destination);
                if (map.Settings.Destinations.TryGetValue(destination, out PrivacyDestination? where))
                {
                    string detail = string.Join(", ", new[] { where.Recipient, where.Country }.Where(x => !string.IsNullOrWhiteSpace(x)));
                    recipients.Add(detail.Length > 0 ? $"{name}: {detail}" : name);
                    if (where.OutsideCountry)
                    {
                        outside.Add(string.IsNullOrWhiteSpace(where.Country) ? name : $"{name} ({where.Country})");
                    }
                }
                else
                {
                    recipients.Add(name);
                }
            }

            yield return new Row(s.Key, Text(s.Name, language), owner, Text(s.Purpose, language), t.Subjects.GetValueOrDefault(s.About, s.About),
                string.Join(", ", s.Kinds.Select(k => t.KindNames.GetValueOrDefault(k, k))),
                s.Recorded?.LegalBasis is { } basis ? t.LegalBasisNames.GetValueOrDefault(basis, basis) : t.NotRecorded,
                recipients.Count == 0 ? t.StaysOnSite : string.Join("; ", recipients),
                s.GoesTo.Count == 0 ? t.No : outside.Count > 0 ? $"{t.Yes}: {string.Join("; ", outside)}"
                    : s.GoesTo.All(map.Settings.Destinations.ContainsKey) ? t.No : t.NotRecorded,
                Kept(s.Kept, t),
                s.Recorded?.Sensitive switch { true => t.Yes, false => t.No, null => t.Undecided },
                s.Recorded?.Notes ?? "");
        }
    }

    internal static string Kept(string kept, ProcessingRecordTexts t) => kept switch
    {
        PersonalDataKept.UntilDone => t.UntilDone,
        PersonalDataKept.WithAccount => t.WithAccount,
        PersonalDataKept.Forever => t.Forever,
        _ when kept.StartsWith("days:", StringComparison.Ordinal) => string.Format(CultureInfo.InvariantCulture, t.Days, kept[5..]),
        _ when kept.LastIndexOf('=') is > 8 and int at => string.Format(CultureInfo.InvariantCulture, t.Setting, kept[(at + 1)..], kept[8..at]),
        _ => kept,
    };

    private static string Text(LocalizedText text, string language) => language == "ar" ? text.Ar : text.En;

    /// <summary>One line of Markdown: what someone typed can't start a heading or a list of its own.</summary>
    private static string? Line(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.ReplaceLineEndings(" ").Trim();

    /// <summary>A CSV cell, quoted when it has to be, and never read as a formula.</summary>
    private static string Cell(string? value)
    {
        string cell = value ?? "";
        if (cell.Length > 0 && cell[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
        {
            cell = "'" + cell;
        }

        return cell.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + cell.Replace("\"", "\"\"") + "\"" : cell;
    }
}
