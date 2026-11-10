using System.Text.Json.Nodes;
using Casl;
using AbpGuard.Domain;
using AbpGuard.Services;

namespace AbpGuard.Tests;

/// <summary>
/// Allow rules merged into one per condition path (M10's load test): fewer rules, one query parameter instead of one per
/// rule, and exactly the same answers, in memory and as a query filter.
/// </summary>
public class RuleMergingTests
{
    private static readonly Guid[] Ids = [.. Enumerable.Range(0, 12).Select(_ => Guid.NewGuid())];
    private static readonly Guid[] Directories = [.. Enumerable.Range(0, 3).Select(_ => Guid.NewGuid())];
    private static readonly string[] Actions = ["read", "update", "delete", "manage"];
    private static readonly string?[] FieldsAsked = [null, "displayName", "email", "status"];

    private static Ability Build(IEnumerable<RawRule> rules) =>
        new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options).AddRange(rules, null).Build();

    private static RawRule Allow(string[] actions, JsonObject? conditions, string[]? fields = null) =>
        new() { Action = actions, Subject = ["Account"], Conditions = conditions, Fields = fields };

    [Fact]
    public void A_person_in_many_projects_gets_one_rule_per_set_of_actions()
    {
        // As a project member's grants give: one rule per project, and one for the projects above each.
        List<RawRule> rules = [];
        foreach (Guid id in Ids)
        {
            rules.Add(Allow(["read", "update"], new JsonObject { ["id"] = id.ToString() }));
            rules.Add(Allow(["read"], new JsonObject { ["id"] = new JsonObject { ["$in"] = new JsonArray(Ids[0].ToString(), id.ToString()) } }));
        }

        List<RawRule> merged = RuleMerging.Merge(rules);
        Assert.Equal(2, merged.Count);
        Assert.Equal(Ids.Length, merged[0].Conditions!["id"]!["$in"]!.AsArray().Count);
        Assert.Equal(Ids.Length, merged[1].Conditions!["id"]!["$in"]!.AsArray().Count); // values once each
    }

    [Fact]
    public void Denies_other_conditions_and_different_fields_stay_apart()
    {
        List<RawRule> rules =
        [
            Allow(["read"], new JsonObject { ["id"] = Ids[0].ToString() }),
            Allow(["read"], new JsonObject { ["id"] = Ids[1].ToString() }, ["email"]),
            Allow(["read"], new JsonObject { ["id"] = new JsonObject { ["$ne"] = Ids[2].ToString() } }),
            Allow(["read"], new JsonObject { ["id"] = Ids[3].ToString(), ["status"] = "Active" }),
            Allow(["read"], null),
            new() { Action = ["read"], Subject = ["Account"], Conditions = new JsonObject { ["id"] = Ids[4].ToString() }, Inverted = true },
            new() { Action = ["read"], Subject = ["Account"], Conditions = new JsonObject { ["id"] = Ids[5].ToString() }, Inverted = true },
        ];

        Assert.Equal(rules, RuleMerging.Merge(rules));
        Ability ability = Build(rules);
        Assert.Same(ability, RuleMerging.Merged(ability));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    public void Merged_abilities_answer_as_the_rules_they_came_from(int seed)
    {
        Random random = new(seed);
        string Pick(string[] values) => values[random.Next(values.Length)];
        JsonNode Id() => Ids[random.Next(Ids.Length)].ToString();
        JsonObject? Condition() => random.Next(7) switch
        {
            0 => new JsonObject { ["id"] = Id() },
            1 => new JsonObject { ["id"] = new JsonObject { ["$in"] = new JsonArray(Id(), Id()) } },
            2 => new JsonObject { ["directoryId"] = Directories[random.Next(Directories.Length)].ToString() },
            3 => new JsonObject { ["status"] = Pick(["Active", "Inactive", "Locked"]) },
            4 => new JsonObject { ["id"] = new JsonObject { ["$eq"] = Id() } },
            5 => new JsonObject { ["id"] = new JsonObject { ["$nin"] = new JsonArray(Id()) } },
            _ => null,
        };

        List<RawRule> rules = [];
        for (int i = 0; i < 60; i++)
        {
            string[] actions = random.Next(5) == 0 ? ["manage"] : [.. Actions.Take(3).Where(_ => random.Next(2) == 0).DefaultIfEmpty("read").Distinct()];
            string[]? fields = random.Next(4) switch { 0 => ["displayName"], 1 => ["email", "status"], _ => null };
            bool deny = random.Next(8) == 0;
            rules.Add(new RawRule { Action = actions, Subject = ["Account"], Conditions = deny ? Condition() ?? new JsonObject { ["id"] = Id() } : Condition(), Fields = fields, Inverted = deny });
        }

        Ability original = Build(rules);
        Ability merged = RuleMerging.Merged(original);
        Assert.True(merged.Rules.Count < original.Rules.Count, $"{merged.Rules.Count} of {original.Rules.Count}");

        List<Account> accounts = [];
        foreach (Guid id in Ids.Append(Guid.NewGuid()))
        {
            foreach (AccountStatus status in Enum.GetValues<AccountStatus>())
            {
                accounts.Add(new Account(id, $"u{random.Next(1000)}") { DirectoryId = Directories[random.Next(Directories.Length)], Status = status });
            }
        }

        foreach (string action in Actions)
        {
            foreach (Account account in accounts)
            {
                foreach (string? field in FieldsAsked)
                {
                    Assert.Equal(original.Can(action, account, field), merged.Can(action, account, field));
                    if (field is not null)
                    {
                        Assert.Equal(original.Can(action, account, field, FieldMatch.Named), merged.Can(action, account, field, FieldMatch.Named));
                    }
                }
            }

            Func<Account, bool> before = original.Filter<Account>(action).Compile(), after = merged.Filter<Account>(action).Compile();
            Assert.Equal(accounts.Select(before), accounts.Select(after));
        }
    }
}
