namespace AbpGuard.Tests;

/// <summary>Guard's events: its outbox carries exactly the contracts' *Eto records, as the host's catalog finds them.</summary>
public class GuardEventTests
{
    [Fact]
    public void The_outbox_carries_every_Eto_of_the_contracts_and_nothing_else()
    {
        Type[] exported = typeof(GuardEvent).Assembly.GetExportedTypes();
        HashSet<Type> etos = exported.Where(t => t.IsClass && !t.IsAbstract && t.Name.EndsWith("Eto", StringComparison.Ordinal)).ToHashSet();
        HashSet<Type> carried = exported.Where(AbpGuardModule.Carries).ToHashSet();

        Assert.Equal(10, etos.Count);
        Assert.Equal(etos, carried);
        Assert.False(AbpGuardModule.Carries(typeof(GuardEvent)));
        Assert.False(AbpGuardModule.Carries(typeof(string)));
    }
}
