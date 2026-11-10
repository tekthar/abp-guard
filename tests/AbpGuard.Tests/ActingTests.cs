using System.Security.Claims;
using System.Text.RegularExpressions;
using Casl;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using AbpGuard.Services;
using AbpGuard.Acting;
using Xunit;

namespace AbpGuard.Tests;

/// <summary>
/// The acting context: who a request acts as, read from the token in one place; the request's limits on
/// that person's ability, wherever it's asked for; and the actor kept on the rows a request writes.
/// </summary>
public partial class ActingTests
{
    private static readonly Guid Subject = Guid.NewGuid();
    private static readonly Guid Actor = Guid.NewGuid();

    private static ActingContext Acting(params Claim[] claims) =>
        new(new HttpContextAccessor { HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")) } });

    [Fact]
    public void A_token_names_its_subject_and_no_actor()
    {
        ActingContext acting = Acting(new Claim("sub", Subject.ToString()), new Claim("name", "ann"));
        Assert.Equal(Subject, acting.SubjectId);
        Assert.Equal("ann", acting.SubjectName);
        Assert.Null(acting.ActorId);
        Assert.Null(acting.Mode);
        Assert.True(acting.SignedIn);
    }

    [Fact]
    public void An_act_claim_names_the_actor()
    {
        ActingContext acting = Acting(new Claim("sub", Subject.ToString()), new Claim(ActingContext.ActClaim, $"{{\"sub\":\"{Actor}\"}}"),
            new Claim(new GuardNames().ModeClaim, ActingModes.Impersonation));
        Assert.Equal(Subject, acting.SubjectId);
        Assert.Equal(Actor, acting.ActorId);
        Assert.Equal(ActingModes.Impersonation, acting.Mode);
    }

    [Fact]
    public void A_visitor_acts_as_no_one()
    {
        ActingContext acting = new(new HttpContextAccessor { HttpContext = new DefaultHttpContext() });
        Assert.Null(acting.SubjectId);
        Assert.False(acting.SignedIn);
    }

    private sealed class NothingLimit : IAbilityLimit
    {
        public Ability Apply(Ability ability, ActingContext acting) => AbilityFactory.None;
    }

    [Fact]
    public void The_requests_limits_apply_to_its_subject_only()
    {
        ActingContext acting = Acting(new Claim("sub", Subject.ToString()));
        Ability own = new AbilityBuilder(GuardSubjects.Registry, GuardSubjects.Options).Build();
        Assert.Same(AbilityFactory.None, AbilityFactory.Limit(own, Subject, acting, [new NothingLimit()]));
        Assert.Same(own, AbilityFactory.Limit(own, Guid.NewGuid(), acting, [new NothingLimit()]));
        Assert.Same(own, AbilityFactory.Limit(own, Subject, acting, []));
    }

    private sealed class Row : IActed
    {
        public Guid Id { get; set; }
        public string? Text { get; set; }
        public Guid? ActingAccountId { get; set; }
        public string? ActingMode { get; set; }
    }

    private sealed class Decision : IActed
    {
        public Guid Id { get; set; }
        public string? Text { get; set; }
        public Guid? ActingAccountId { get; set; }
        public string? ActingMode { get; set; }
        bool IActed.ActedOnChange => true;
    }

    private sealed class Rows(DbContextOptions<Rows> options) : DbContext(options)
    {
        public DbSet<Row> Items => Set<Row>();
        public DbSet<Decision> Decisions => Set<Decision>();
    }

    private static Rows Context() => new(new DbContextOptionsBuilder<Rows>().UseNpgsql("Host=localhost;Database=none").Options);

    [Fact]
    public void Rows_a_request_adds_keep_the_actor()
    {
        using Rows db = Context();
        Row added = new() { Id = Guid.NewGuid() };
        db.Items.Add(added);
        Row changed = new() { Id = Guid.NewGuid() };
        db.Items.Attach(changed);
        changed.Text = "edited";
        Decision decided = new() { Id = Guid.NewGuid() };
        db.Decisions.Attach(decided);
        decided.Text = "approved";
        Row set = new() { Id = Guid.NewGuid(), ActingAccountId = Subject, ActingMode = ActingModes.Delegation };
        db.Items.Add(set);

        ActedRows.Stamp(db.ChangeTracker, Acting(new Claim("sub", Subject.ToString()), new Claim(ActingContext.ActClaim, $"{{\"sub\":\"{Actor}\"}}")));

        Assert.Equal(Actor, added.ActingAccountId);
        Assert.Equal(ActingModes.Impersonation, added.ActingMode);
        Assert.Null(changed.ActingAccountId); // an edit isn't the act the row records
        Assert.Equal(Actor, decided.ActingAccountId); // a decision is
        Assert.Equal(Subject, set.ActingAccountId); // what the code set stays
        Assert.Equal(ActingModes.Delegation, set.ActingMode);
    }

    [Fact]
    public void Without_an_actor_nothing_is_stamped()
    {
        using Rows db = Context();
        Row added = new() { Id = Guid.NewGuid() };
        db.Items.Add(added);
        ActedRows.Stamp(db.ChangeTracker, Acting(new Claim("sub", Subject.ToString())));
        Assert.Null(added.ActingAccountId);
        Assert.Null(added.ActingMode);
    }

    [GeneratedRegex("""FindFirst(Value)?\((\s*"sub"|\s*ClaimTypes\.NameIdentifier)""")]
    private static partial Regex ReadsSubject();

    /// <summary>
    /// One way to who a request is: the host reads the token's subject only in the acting context, so a
    /// token's limits (and later an impersonation's) can't be skipped by a path that reads it itself. Plugins build
    /// a Caller from it; the host's services then apply the limits when that Caller is the request's subject.
    /// </summary>
    [Fact]
    public void Only_the_acting_context_reads_who_the_token_is_for()
    {
        string root = AppContext.BaseDirectory;
        // The repository's root, the app's or Guard's own: where a solution file sits beside src.
        while (!(Directory.Exists(Path.Combine(root, "src")) && Directory.EnumerateFiles(root, "*.slnx").Any()))
        {
            root = Path.GetDirectoryName(root) ?? throw new InvalidOperationException("No solution file beside src above the test folder.");
        }

        string allowed = Path.Combine("src", "AbpGuard.Acting", "ActingContext.cs");
        List<string> readers = Directory.EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            .Where(f => ReadsSubject().IsMatch(File.ReadAllText(f)))
            .Select(f => Path.GetRelativePath(root, f))
            .Where(f => f != allowed)
            .ToList();
        Assert.True(readers.Count == 0, "Read the request's account from ActingContext instead: " + string.Join(", ", readers));
    }
}
