using System.ComponentModel.DataAnnotations;
using System.Linq.Expressions;
using Volo.Abp.Application.Dtos;
using Volo.Abp.Validation;

namespace AbpGuard.Controllers;

/// <summary>
/// A page of accounts, as ABP's lists page (<see cref="PagedAndSortedResultRequestDto"/>): the list's search as
/// <see cref="Filter"/>, its status, <c>SkipCount</c>, <c>MaxResultCount</c> (25 unless given, at most ABP's 1,000)
/// and <c>Sorting</c> by username, displayName, email, status, createdAt or lastLoginAt.
/// </summary>
public sealed class AccountPageInput : PagedAndSortedResultRequestDto
{
    public AccountPageInput() => MaxResultCount = GuardPaging.DefaultPageSize;

    /// <summary>Part of a username, a name in any of its languages, or an address.</summary>
    public string? Filter { get; set; }

    /// <summary>Only accounts in this status (active, disabled…), as the list takes it.</summary>
    public string? Status { get; set; }
}

/// <summary>
/// A page of groups, as ABP's lists page: the list's search as <see cref="Filter"/>, its directory and kind, and
/// <c>Sorting</c> by name, kind or directory.
/// </summary>
public sealed class GroupPageInput : PagedAndSortedResultRequestDto
{
    public GroupPageInput() => MaxResultCount = GuardPaging.DefaultPageSize;

    /// <summary>Part of the group's name.</summary>
    public string? Filter { get; set; }

    public Guid? DirectoryId { get; set; }

    public string? Kind { get; set; }
}

/// <summary>
/// Sorting a page by the fields its list allows: <c>field</c> or <c>field desc</c>, several by commas, then by id, so
/// a page holds still while names change. Any other field is a validation error (400), never ignored.
/// </summary>
public static class GuardPaging
{
    public const int DefaultPageSize = 25;

    public static IQueryable<T> Sort<T>(IQueryable<T> query, string? sorting, IReadOnlyDictionary<string, LambdaExpression> fields,
        string fallback, Expression<Func<T, Guid>> id)
    {
        List<(LambdaExpression Key, bool Descending)> keys = [];
        foreach (string part in (string.IsNullOrWhiteSpace(sorting) ? fallback : sorting).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string[] words = part.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            bool descending = words.Length == 2 && words[1].Equals("desc", StringComparison.OrdinalIgnoreCase);
            bool ascending = words.Length == 1 || words.Length == 2 && words[1].Equals("asc", StringComparison.OrdinalIgnoreCase);
            if (!(ascending || descending) || !fields.TryGetValue(words[0], out LambdaExpression? key))
            {
                string allowed = string.Join(", ", fields.Keys);
                throw new AbpValidationException($"Sort by one of {allowed}, each \"asc\" or \"desc\".",
                    [new ValidationResult($"\"{part}\" isn't a sort this list takes: {allowed}.", [nameof(PagedAndSortedResultRequestDto.Sorting)])]);
            }

            keys.Add((key, descending));
        }

        keys.Add((id, false));
        Expression expression = query.Expression;
        for (int i = 0; i < keys.Count; i++)
        {
            string method = (i == 0 ? "OrderBy" : "ThenBy") + (keys[i].Descending ? "Descending" : "");
            expression = Expression.Call(typeof(Queryable), method, [typeof(T), keys[i].Key.ReturnType], expression, Expression.Quote(keys[i].Key));
        }

        return query.Provider.CreateQuery<T>(expression);
    }

    /// <summary>A sortable field: its key's own type is kept, so the database sorts it as it is.</summary>
    public static LambdaExpression By<T, TKey>(Expression<Func<T, TKey>> key) => key;
}
