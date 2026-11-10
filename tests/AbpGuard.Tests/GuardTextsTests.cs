using System.Reflection;
using AbpGuard.Services.Privacy;
using Xunit;

namespace AbpGuard.Tests;

/// <summary>
/// The record of processing's and a person's export's words are a host's to change (Guard:Texts;):
/// Guard keeps Guard's own word for word, a language is found by its first part and falls back to English, and Guard's
/// own words name the host's product where they mark it.
/// </summary>
public class GuardTextsTests
{
    /// <summary>Every text of a record, its strings and its lists of names, as it reads.</summary>
    private static void SameWords(ProcessingRecordTexts expected, ProcessingRecordTexts actual)
    {
        foreach (PropertyInfo property in typeof(ProcessingRecordTexts).GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            Assert.Equal(property.GetValue(expected), property.GetValue(actual) is IReadOnlyDictionary<string, string> names
                ? names.ToDictionary() as object
                : property.GetValue(actual));
        }
    }

    [Fact]
    public void The_records_and_the_exports_words_are_guards_by_default()
    {
        // Named for the host's product: here none was given, so AbpGuard.
        GuardTextOptions defaults = new();
        ProcessingRecordTexts Named(ProcessingRecordTexts texts) => texts with
        {
            Subjects = texts.Subjects.ToDictionary(p => p.Key, p => p.Value.Replace(GuardMessageTemplates.ProductMarker, "AbpGuard", StringComparison.Ordinal)),
        };

        SameWords(Named(ProcessingRecordTexts.English), defaults.RecordIn("en"));
        SameWords(Named(ProcessingRecordTexts.Arabic), defaults.RecordIn("ar-SA"));
        SameWords(Named(ProcessingRecordTexts.English), defaults.RecordIn("fr"));
        Assert.Same(PersonalDataExportTexts.English, defaults.ExportIn("en"));
        Assert.Same(PersonalDataExportTexts.Arabic, defaults.ExportIn("AR"));
        Assert.Same(PersonalDataExportTexts.English, defaults.ExportIn("fr-FR"));
    }

    [Fact]
    public void Guards_own_words_name_the_hosts_product()
    {
        GuardTextOptions market = new();
        market.ProductName["en"] = "Market";
        market.ProductName["ar"] = "ماركت";

        Assert.Equal("people outside Market, known by an address", market.RecordIn("en").Subjects[PersonalDataSubjects.Outside]);
        Assert.Equal("أشخاص من خارج ماركت يُعرفون بعنوان", market.RecordIn("ar").Subjects[PersonalDataSubjects.Outside]);
        Assert.Equal("people outside {product}, known by an address", ProcessingRecordTexts.English.Subjects[PersonalDataSubjects.Outside]);
    }

    [Fact]
    public void A_host_adds_a_language_or_rewords_one()
    {
        GuardTextOptions texts = new();
        texts.Record["fr"] = ProcessingRecordTexts.English with { Title = "Registre des activités de traitement" };
        texts.Export["en"] = PersonalDataExportTexts.English with { Title = "Your data" };

        Assert.Equal("Registre des activités de traitement", texts.RecordIn("fr-CA").Title);
        Assert.Equal("Your data", texts.ExportIn("en").Title);
        Assert.Equal("Record of processing activities", texts.RecordIn("en").Title);
    }
}
