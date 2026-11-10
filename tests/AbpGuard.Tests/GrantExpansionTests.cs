using System.Text.Json.Nodes;
using AbpGuard.Services;
using Xunit;

namespace AbpGuard.Tests;

/// <summary>Widened grants: read-only copies of rules, and placeholders that hold lists.</summary>
public class GrantExpansionTests
{
    [Fact]
    public void Read_only_keeps_reading_and_managing_as_reading()
    {
        JsonObject rule = JsonNode.Parse(AbilityFactory.ReadOnly("""{ "action": ["read", "update"], "subject": "Record" }""")!)!.AsObject();
        Assert.Equal("read", rule["action"]!.GetValue<string>());
        Assert.Equal("read", JsonNode.Parse(AbilityFactory.ReadOnly("""{ "action": "manage", "subject": "Project" }""")!)!["action"]!.GetValue<string>());
        Assert.Null(AbilityFactory.ReadOnly("""{ "action": ["create", "comment"], "subject": "Record" }"""));
    }

    [Fact]
    public void Read_only_keeps_deny_rules()
    {
        JsonObject rule = JsonNode.Parse(AbilityFactory.ReadOnly("""{ "action": "read", "subject": "Record", "inverted": true }""")!)!.AsObject();
        Assert.True(rule["inverted"]!.GetValue<bool>());
    }

    [Fact]
    public void A_list_valued_placeholder_becomes_in()
    {
        string json = """{ "action": "read", "subject": "Record", "conditions": { "projectId": "${grant.projectId}", "reporterId": "${user.id}", "$or": [ { "id": "${grant.projectId}" } ] } }""";
        JsonObject rule = JsonNode.Parse(AbilityFactory.ListValued(json, new HashSet<string> { "projectId" }))!.AsObject();
        Assert.Equal("${grant.projectId}", rule["conditions"]!["projectId"]!["$in"]!.GetValue<string>());
        Assert.Equal("${user.id}", rule["conditions"]!["reporterId"]!.GetValue<string>());
        Assert.Equal("${grant.projectId}", rule["conditions"]!["$or"]![0]!["id"]!["$in"]!.GetValue<string>());
    }

    [Fact]
    public void Without_lists_the_rule_is_unchanged()
    {
        string json = """{ "action": "read", "subject": "Record", "conditions": { "projectId": "${grant.projectId}" } }""";
        Assert.Equal(json, AbilityFactory.ListValued(json, new HashSet<string>()));
    }
}
