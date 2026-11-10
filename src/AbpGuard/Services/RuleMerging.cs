using System.Text.Json.Nodes;
using Casl;

namespace AbpGuard.Services;

/// <summary>
/// Allow rules that differ only in the value one condition path must have, merged into one rule whose path must be any
/// of their values. A person in 289 projects had 578 record rules, so every query of theirs carried 576 parameters
/// and cost about 100 ms before it reached the database (M10's load test); merged, one array. Under deny-overrides
/// (<see cref="AbilitySubjects.Options"/>) an allow rule's place among the rules means nothing, so the merged rule allows
/// exactly what the rules it replaces did; deny rules and every other rule are left as they are.
/// </summary>
public static class RuleMerging
{
    /// <summary>The ability with its mergeable allow rules merged, or the same ability when there are none.</summary>
    public static Ability Merged(Ability ability)
    {
        IReadOnlyList<RawRule> rules = ability.Rules;
        List<RawRule> merged = Merge(rules);
        return merged.Count == rules.Count ? ability : new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options).AddRange(merged, null).Build();
    }

    /// <summary>The rules with each set of mergeable allow rules replaced, where its first one was, by one rule.</summary>
    internal static List<RawRule> Merge(IReadOnlyList<RawRule> rules)
    {
        List<RawRule> result = [];
        Dictionary<string, Group> groups = new(StringComparer.Ordinal);
        foreach (RawRule rule in rules)
        {
            if (rule.Inverted || Single(rule.Conditions) is not { } condition)
            {
                result.Add(rule);
                continue;
            }

            string key = Key(rule, condition.Path);
            if (!groups.TryGetValue(key, out Group? group))
            {
                groups[key] = group = new Group(result.Count, condition.Path);
                result.Add(rule);
            }

            group.Rules++;
            foreach (JsonNode value in condition.Values)
            {
                if (group.Seen.Add(value.ToJsonString()))
                {
                    group.Values.Add(value.DeepClone());
                }
            }
        }

        foreach (Group group in groups.Values.Where(g => g.Rules > 1))
        {
            result[group.Index] = result[group.Index] with
            {
                Conditions = new JsonObject { [group.Path] = new JsonObject { ["$in"] = new JsonArray([.. group.Values]) } },
            };
        }

        return result;
    }

    private sealed class Group(int index, string path)
    {
        public int Index { get; } = index;

        public string Path { get; } = path;

        public int Rules { get; set; }

        public List<JsonNode> Values { get; } = [];

        public HashSet<string> Seen { get; } = new(StringComparer.Ordinal);
    }

    /// <summary>
    /// A condition on one path that's an equality or a membership of plain values: { "projectId": "…" },
    /// { "projectId": { "$eq": "…" } } or { "projectId": { "$in": ["…", …] } }. Anything else isn't merged.
    /// </summary>
    private static (string Path, List<JsonNode> Values)? Single(JsonObject? conditions)
    {
        if (conditions is not { Count: 1 } || conditions.First() is not (string path, JsonNode node) || path.StartsWith('$'))
        {
            return null;
        }

        switch (node)
        {
            case JsonValue value when Plain(value):
                return (path, [value]);
            case JsonObject { Count: 1 } op when op.First() is ("$eq", JsonValue value) && Plain(value):
                return (path, [value]);
            case JsonObject { Count: 1 } op when op.First() is ("$in", JsonArray items) && items.Count > 0 && items.All(i => i is JsonValue v && Plain(v)):
                return (path, [.. items.Select(i => i!)]);
            default:
                return null;
        }
    }

    private static bool Plain(JsonValue value) =>
        value.GetValueKind() is System.Text.Json.JsonValueKind.String or System.Text.Json.JsonValueKind.Number
            or System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False;

    /// <summary>Rules merge when they allow the same actions on the same subjects for the same fields, on the same path.</summary>
    private static string Key(RawRule rule, string path) => string.Join('\u001f',
        string.Join(',', rule.Action.Order(StringComparer.Ordinal)),
        string.Join(',', (rule.Subject ?? []).Order(StringComparer.Ordinal)),
        rule.Fields is null ? "\u0000" : string.Join(',', rule.Fields.Order(StringComparer.Ordinal)),
        rule.Reason ?? "\u0000",
        path);
}
