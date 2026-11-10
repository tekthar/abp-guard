using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class GrantScopeKey : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ScopeKey",
                schema: "guard",
                table: "role_grants",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_role_grants_ScopeKey",
                schema: "guard",
                table: "role_grants",
                column: "ScopeKey");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_role_grants_ScopeKey",
                schema: "guard",
                table: "role_grants");

            migrationBuilder.DropColumn(
                name: "ScopeKey",
                schema: "guard",
                table: "role_grants");
        }
    }
}
