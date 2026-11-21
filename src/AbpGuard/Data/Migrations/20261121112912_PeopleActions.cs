using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class PeopleActions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "DeactivatedLocally",
                schema: "guard",
                table: "accounts",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTime>(
                name: "InvitedAt",
                schema: "guard",
                table: "accounts",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "InvitedBy",
                schema: "guard",
                table: "accounts",
                type: "uuid",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DeactivatedLocally",
                schema: "guard",
                table: "accounts");

            migrationBuilder.DropColumn(
                name: "InvitedAt",
                schema: "guard",
                table: "accounts");

            migrationBuilder.DropColumn(
                name: "InvitedBy",
                schema: "guard",
                table: "accounts");
        }
    }
}
