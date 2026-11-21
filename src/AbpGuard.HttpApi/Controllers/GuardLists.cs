using System.Text;
using Volo.Abp.Application.Dtos;

namespace AbpGuard.Controllers;

/// <summary>
/// A page of a list in ABP's shape (<c>totalCount</c>, <c>items</c>), and, when the list is grouped (0.9.0), every
/// group's total under the same filters, across pages: the rows come sorted by the group first, so a screen draws a
/// header where the group changes and the count beside it is true.
/// </summary>
public class GuardPagedResultDto<T> : PagedResultDto<T>
{
    public GuardPagedResultDto()
    {
    }

    public GuardPagedResultDto(long totalCount, IReadOnlyList<T> items, List<ListGroupDto>? groups) : base(totalCount, items) => Groups = groups;

    /// <summary>The groups in the list's order, with how many rows each has; null when the list isn't grouped.</summary>
    public List<ListGroupDto>? Groups { get; set; }
}

/// <summary>One group of a grouped list: its key (a status, a directory's id, a kind), its name, and how many rows it has.</summary>
public sealed record ListGroupDto(string Key, string Label, int Count);

/// <summary>
/// A list as CSV (0.9.0): UTF-8 with a byte-order mark, so spreadsheet programs read every language, and every cell
/// that starts like a formula (<c>=</c>, <c>+</c>, <c>-</c>, <c>@</c>, a tab or a carriage return) behind a <c>'</c>, so none
/// runs as one.
/// </summary>
public static class GuardCsv
{
    /// <summary>The most rows an export holds.</summary>
    public const int MaxRows = 100_000;

    public static byte[] Write(IReadOnlyList<string> header, IEnumerable<IReadOnlyList<string?>> rows)
    {
        StringBuilder csv = new();
        Line(csv, header);
        foreach (IReadOnlyList<string?> row in rows)
        {
            Line(csv, row);
        }

        return [.. Encoding.UTF8.GetPreamble(), .. Encoding.UTF8.GetBytes(csv.ToString())];
    }

    /// <summary>A cell as CSV: quoted when it holds a comma, a quote or a line break; behind a <c>'</c> when it starts like a formula.</summary>
    public static string Cell(string? value)
    {
        string text = value ?? "";
        if (text.Length > 0 && text[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
        {
            text = "'" + text;
        }

        return text.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + text.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : text;
    }

    /// <summary>A time as people and spreadsheets read it: UTC, to the second.</summary>
    public static string? Time(DateTime? at) => at?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

    private static void Line(StringBuilder csv, IReadOnlyList<string?> cells)
    {
        for (int i = 0; i < cells.Count; i++)
        {
            if (i > 0)
            {
                csv.Append(',');
            }

            csv.Append(Cell(cells[i]));
        }

        csv.Append("\r\n");
    }
}
