using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class CustomersAndSignUp : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Attributes",
                schema: "guard",
                table: "groups",
                type: "jsonb",
                nullable: false,
                defaultValue: "{}");

            migrationBuilder.AddColumn<string>(
                name: "EmailDomains",
                schema: "guard",
                table: "groups",
                type: "jsonb",
                nullable: false,
                defaultValue: "[]");

            migrationBuilder.AddColumn<string>(
                name: "Kind",
                schema: "guard",
                table: "groups",
                type: "character varying(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "standard");

            migrationBuilder.AddColumn<DateTime>(
                name: "PendingSince",
                schema: "guard",
                table: "directory_users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "signup_settings",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    DirectoryId = table.Column<Guid>(type: "uuid", nullable: true),
                    EmailDomains = table.Column<string>(type: "jsonb", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_signup_settings", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_groups_Kind",
                schema: "guard",
                table: "groups",
                column: "Kind");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "signup_settings",
                schema: "guard");

            migrationBuilder.DropIndex(
                name: "IX_groups_Kind",
                schema: "guard",
                table: "groups");

            migrationBuilder.DropColumn(
                name: "Attributes",
                schema: "guard",
                table: "groups");

            migrationBuilder.DropColumn(
                name: "EmailDomains",
                schema: "guard",
                table: "groups");

            migrationBuilder.DropColumn(
                name: "Kind",
                schema: "guard",
                table: "groups");

            migrationBuilder.DropColumn(
                name: "PendingSince",
                schema: "guard",
                table: "directory_users");
        }
    }
}
