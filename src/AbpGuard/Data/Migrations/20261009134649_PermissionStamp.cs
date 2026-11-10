using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class PermissionStamp : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "permission_stamp",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false),
                    Version = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_permission_stamp", x => x.Id);
                });

            migrationBuilder.InsertData(
                schema: "guard",
                table: "permission_stamp",
                columns: new[] { "Id", "Version" },
                values: new object[] { 1, 0L });

            // ADR 0041: every write to what abilities are built from moves the stamp on, in the same transaction.
            migrationBuilder.Sql("""
                CREATE FUNCTION guard.permissions_changed() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    UPDATE guard.permission_stamp SET "Version" = "Version" + 1 WHERE "Id" = 1;
                    RETURN NULL;
                END $$;
                """);
            foreach ((string table, string events) in Watched)
            {
                migrationBuilder.Sql($"""
                    CREATE TRIGGER permissions_changed AFTER {events} ON guard.{table}
                    FOR EACH STATEMENT EXECUTE FUNCTION guard.permissions_changed();
                    """);
            }
        }

        /// <summary>The tables abilities are built from, and the writes to them that matter.</summary>
        private static readonly (string Table, string Events)[] Watched =
        [
            ("accounts", "INSERT OR DELETE OR UPDATE OF \"Status\", \"Username\", \"NormalizedUsername\", \"DirectoryId\", \"DirectoryUserId\""),
            ("directory_users", "INSERT OR DELETE OR UPDATE OF \"NormalizedUsername\", \"DirectoryId\""),
            ("directories", "INSERT OR DELETE OR UPDATE OF \"IsActive\""),
            ("groups", "INSERT OR DELETE OR UPDATE"),
            ("memberships", "INSERT OR DELETE OR UPDATE"),
            ("roles", "INSERT OR DELETE OR UPDATE"),
            ("role_rules", "INSERT OR DELETE OR UPDATE"),
            ("role_grants", "INSERT OR DELETE OR UPDATE"),
        ];

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            foreach ((string table, _) in Watched)
            {
                migrationBuilder.Sql($"DROP TRIGGER IF EXISTS permissions_changed ON guard.{table};");
            }

            migrationBuilder.Sql("DROP FUNCTION IF EXISTS guard.permissions_changed();");

            migrationBuilder.DropTable(
                name: "permission_stamp",
                schema: "guard");
        }
    }
}
