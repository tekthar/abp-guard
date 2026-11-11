using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class NamesByLanguageForDirectoriesGroupsRoles : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Descriptions",
                schema: "guard",
                table: "roles",
                type: "jsonb",
                nullable: false,
                defaultValueSql: "'{}'::jsonb");

            migrationBuilder.AddColumn<string>(
                name: "Names",
                schema: "guard",
                table: "roles",
                type: "jsonb",
                nullable: false,
                defaultValueSql: "'{}'::jsonb");

            migrationBuilder.AddColumn<string>(
                name: "Names",
                schema: "guard",
                table: "groups",
                type: "jsonb",
                nullable: false,
                defaultValueSql: "'{}'::jsonb");

            migrationBuilder.AddColumn<string>(
                name: "Names",
                schema: "guard",
                table: "directories",
                type: "jsonb",
                nullable: false,
                defaultValueSql: "'{}'::jsonb");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Descriptions",
                schema: "guard",
                table: "roles");

            migrationBuilder.DropColumn(
                name: "Names",
                schema: "guard",
                table: "roles");

            migrationBuilder.DropColumn(
                name: "Names",
                schema: "guard",
                table: "groups");

            migrationBuilder.DropColumn(
                name: "Names",
                schema: "guard",
                table: "directories");
        }
    }
}
