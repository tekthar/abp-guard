using System.Text.Json.Nodes;
using AbpGuard.Services;
using Xunit;

namespace AbpGuard.Tests;

/// <summary>Which rules a role given to anonymous visitors may have (0.9.0): limited to its place at the top, never people, never manage.</summary>
public class AnonymousRulesTests
{
    private static readonly JsonObject Scope = new() { ["projectId"] = "p1" };

    [Theory]
    [InlineData("""{"action":"read","subject":"Record","conditions":{"projectId":"${grant.projectId}"}}""")]
    [InlineData("""{"action":["read","comment"],"subject":"Record","conditions":{"projectId":{"$eq":"${grant.projectId}"},"state":"open"}}""")]
    [InlineData("""{"action":"read","subject":"Record","conditions":{"$and":[{"projectId":"${grant.projectId}"},{"$or":[{"a":1},{"b":2}]}]}}""")]
    [InlineData("""{"action":"read","subject":"Record","conditions":{"projectId":{"$in":"${grant.projectId}"}}}""")]
    [InlineData("""{"action":"read","subject":"Account","inverted":true}""")] // a deny only narrows
    public void A_rule_that_keeps_to_its_place_may_reach_anonymous_visitors(string rule) =>
        Assert.Null(AnonymousGrants.Problem(rule, Scope, null));

    [Theory]
    [InlineData("""{"action":"read","subject":"Record"}""", "isn't limited")]
    [InlineData("""{"action":"read","subject":"Record","conditions":{"state":"open"}}""", "isn't limited")]
    [InlineData("""{"action":"read","subject":"Record","conditions":{"$or":[{"projectId":"${grant.projectId}"},{"public":true}]}}""", "isn't limited")]
    [InlineData("""{"action":"read","subject":"Record","conditions":{"$not":{"projectId":"${grant.projectId}"}}}""", "isn't limited")]
    [InlineData("""{"action":"read","subject":"Record","conditions":{"projectId":"${grant.other}"}}""", "isn't limited")]
    [InlineData("""{"action":"manage","subject":"Record","conditions":{"projectId":"${grant.projectId}"}}""", "manages")]
    [InlineData("""{"action":["read","manage"],"subject":"Record","conditions":{"projectId":"${grant.projectId}"}}""", "manages")]
    [InlineData("""{"action":"read","subject":"Account","conditions":{"id":"${grant.projectId}"}}""", "people")]
    [InlineData("""{"action":"read","subject":"all","conditions":{"projectId":"${grant.projectId}"}}""", "everything")]
    [InlineData("""{"action":"read","subject":["Record","Role"],"conditions":{"projectId":"${grant.projectId}"}}""", "Role")]
    public void A_rule_that_could_reach_past_its_place_is_refused(string rule, string why) =>
        Assert.Contains(why, AnonymousGrants.Problem(rule, Scope, null));

    [Fact]
    public void A_place_that_names_its_subjects_opens_only_those()
    {
        const string comments = """{"action":"read","subject":"Comment","conditions":{"projectId":"${grant.projectId}"}}""";
        Assert.Null(AnonymousGrants.Problem(comments, Scope, ["Record", "Comment"]));
        Assert.Contains("doesn't", AnonymousGrants.Problem(comments, Scope, ["Record"]));
    }
}
