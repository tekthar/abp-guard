using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class PersonNamesByLanguage : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "DisplayNames",
                schema: "guard",
                table: "accounts",
                type: "jsonb",
                nullable: false,
                defaultValueSql: "'{}'::jsonb");

            migrationBuilder.AddColumn<string>(
                name: "OtherNames",
                schema: "guard",
                table: "accounts",
                type: "character varying(2048)",
                maxLength: 2048,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DisplayNames",
                schema: "guard",
                table: "accounts");

            migrationBuilder.DropColumn(
                name: "OtherNames",
                schema: "guard",
                table: "accounts");
        }
    }
}
