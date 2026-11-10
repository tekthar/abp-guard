using AbpGuard.Domain;
using AbpGuard.Services;

namespace AbpGuard.Tests;

/// <summary>Nested membership, across directories, with cycles in synced data tolerated and new cycles refused.</summary>
public class MembershipTests
{
    private readonly Guid _internal = Guid.NewGuid();
    private readonly Guid _corp = Guid.NewGuid();
    private readonly Dictionary<Guid, Group> _groups = [];
    private readonly List<GroupMembership> _memberships = [];

    private Group Group(string name, Guid directory)
    {
        Group group = new(Guid.NewGuid(), directory, name, isLocal: directory == _internal);
        _groups[group.Id] = group;
        return group;
    }

    private void Nest(Group parent, Group child, MembershipSource source = MembershipSource.Directory) =>
        _memberships.Add(new GroupMembership(Guid.NewGuid(), parent.Id, MemberType.Group, child.Id, source));

    private void AddUser(Group group, Guid directoryUserId) =>
        _memberships.Add(new GroupMembership(Guid.NewGuid(), group.Id, MemberType.DirectoryUser, directoryUserId, MembershipSource.Directory));

    private void AddAccount(Group group, Guid accountId) =>
        _memberships.Add(new GroupMembership(Guid.NewGuid(), group.Id, MemberType.Account, accountId, MembershipSource.Manual));

    private MembershipGraph.Snapshot Snapshot() => new([_internal, _corp], _groups, _memberships);

    private static Account ActiveAccount(Guid directoryUserId) =>
        new(Guid.NewGuid(), "jsmith") { DirectoryUserId = directoryUserId, Status = AccountStatus.Active };

    [Fact]
    public void Groups_are_reached_through_any_depth_with_their_path()
    {
        Group backend = Group("backend", _corp), engineering = Group("engineering", _corp), allStaff = Group("all-staff", _corp);
        Group usersGroup = Group("users", _internal);
        Nest(engineering, backend);
        Nest(allStaff, engineering);
        Nest(usersGroup, allStaff, MembershipSource.Manual); // cross-directory: an internal group contains an LDAP group
        Guid jsmith = Guid.NewGuid();
        AddUser(backend, jsmith);

        var groups = MembershipGraph.ResolveEffectiveGroups(Snapshot(), ActiveAccount(jsmith), new HashSet<Guid> { jsmith });

        Assert.Equal(["backend"], groups.Single(g => g.Group == backend).Path);
        Assert.True(groups.Single(g => g.Group == backend).Direct);
        Assert.Equal(["backend", "engineering", "all-staff", "users"], groups.Single(g => g.Group == usersGroup).Path);
        Assert.False(groups.Single(g => g.Group == usersGroup).Direct);
    }

    [Fact]
    public void A_directory_group_takes_everyone_from_its_directory_without_rows()
    {
        Group corpEveryone = Group("Corp (everyone)", _corp);
        corpEveryone.Kind = GroupKinds.Directory;
        Group internalEveryone = Group("Internal (everyone)", _internal);
        internalEveryone.Kind = GroupKinds.Directory;
        Group customers = Group("customers", _internal);
        Nest(customers, corpEveryone, MembershipSource.Manual); // granting a role to a whole directory, through a group
        Guid user = Guid.NewGuid();

        var groups = MembershipGraph.ResolveEffectiveGroups(Snapshot(), ActiveAccount(user), new HashSet<Guid> { user }, new HashSet<Guid> { _corp });

        Assert.Contains(groups, g => g.Group == corpEveryone && g.Direct);
        Assert.Equal(["Corp (everyone)", "customers"], groups.Single(g => g.Group == customers).Path);
        Assert.DoesNotContain(groups, g => g.Group == internalEveryone);
        Assert.DoesNotContain(_memberships, m => m.GroupId == corpEveryone.Id);
    }

    [Fact]
    public void The_shortest_path_wins()
    {
        Group a = Group("a", _corp), b = Group("b", _corp), top = Group("top", _corp);
        Nest(b, a);
        Nest(top, b);
        Nest(top, a); // a is also directly in top
        Guid user = Guid.NewGuid();
        AddUser(a, user);

        var groups = MembershipGraph.ResolveEffectiveGroups(Snapshot(), ActiveAccount(user), new HashSet<Guid> { user });

        Assert.Equal(["a", "top"], groups.Single(g => g.Group == top).Path);
    }

    [Fact]
    public void Memberships_added_in_Guard_count_for_the_account()
    {
        Group admins = Group("admins", _internal);
        Account account = ActiveAccount(Guid.NewGuid());
        AddAccount(admins, account.Id);

        var groups = MembershipGraph.ResolveEffectiveGroups(Snapshot(), account, new HashSet<Guid>());

        Assert.Contains(groups, g => g.Group == admins);
    }

    [Fact]
    public void A_cycle_in_synced_data_does_not_hang_and_is_reported_once()
    {
        Group a = Group("a", _corp), b = Group("b", _corp);
        Nest(a, b);
        Nest(b, a);
        Guid user = Guid.NewGuid();
        AddUser(a, user);

        var groups = MembershipGraph.ResolveEffectiveGroups(Snapshot(), ActiveAccount(user), new HashSet<Guid> { user });

        Assert.Equal(2, groups.Count);
    }

    [Fact]
    public void Descendants_carry_their_path_up_to_the_group()
    {
        Group engineering = Group("engineering", _corp), backend = Group("backend", _corp), usersGroup = Group("users", _internal);
        Nest(engineering, backend);
        Nest(usersGroup, engineering, MembershipSource.Manual);

        var paths = MembershipGraph.DescendantGroupPaths(Snapshot(), usersGroup.Id);

        Assert.Equal(["backend", "engineering", "users"], paths[backend.Id]);
    }

    [Fact]
    public void Adding_a_group_that_already_contains_the_parent_is_a_loop()
    {
        Group usersGroup = Group("users", _internal), teamA = Group("team-a", _internal);
        Nest(teamA, usersGroup, MembershipSource.Manual); // team-a contains users

        List<string>? loop = MembershipGraph.FindCycle(Snapshot(), parentGroupId: usersGroup.Id, childGroupId: teamA.Id);

        Assert.Equal(["users", "team-a", "users"], loop);
    }

    [Fact]
    public void A_group_inside_itself_is_a_loop()
    {
        Group g = Group("g", _internal);

        Assert.Equal(["g", "g"], MembershipGraph.FindCycle(Snapshot(), g.Id, g.Id));
    }

    [Fact]
    public void Unrelated_groups_are_safe_to_nest()
    {
        Group a = Group("a", _internal), b = Group("b", _internal);

        Assert.Null(MembershipGraph.FindCycle(Snapshot(), a.Id, b.Id));
    }
}
