using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class AgentAccounts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsAgent",
                schema: "guard",
                table: "accounts",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddCheckConstraint(
                name: "CK_accounts_agent_is_service",
                schema: "guard",
                table: "accounts",
                sql: "NOT \"IsAgent\" OR \"IsService\"");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "CK_accounts_agent_is_service",
                schema: "guard",
                table: "accounts");

            migrationBuilder.DropColumn(
                name: "IsAgent",
                schema: "guard",
                table: "accounts");
        }
    }
}
