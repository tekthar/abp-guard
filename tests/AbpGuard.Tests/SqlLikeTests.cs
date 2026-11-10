namespace AbpGuard.Tests;

/// <summary>Guard's own LIKE patterns: someone's %, _ and \ match themselves.</summary>
public class SqlLikeTests
{
    [Fact]
    public void Wildcards_in_someones_text_match_themselves()
    {
        Assert.Equal(@"50\%\_off\\", SqlLike.Exactly(@"50%_off\"));
        Assert.Equal(@"%a\_b%", SqlLike.Containing("a_b"));
    }
}
