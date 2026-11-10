using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class SecurityAudit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "ActingAccountId",
                schema: "guard",
                table: "security_events",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ActingMode",
                schema: "guard",
                table: "security_events",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "SessionId",
                schema: "guard",
                table: "security_events",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "TargetId",
                schema: "guard",
                table: "security_events",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TargetName",
                schema: "guard",
                table: "security_events",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TargetType",
                schema: "guard",
                table: "security_events",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "security_settings",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RetentionDays = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_settings", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_security_events_AccountId",
                schema: "guard",
                table: "security_events",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_security_events_TargetId",
                schema: "guard",
                table: "security_events",
                column: "TargetId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "security_settings",
                schema: "guard");

            migrationBuilder.DropIndex(
                name: "IX_security_events_AccountId",
                schema: "guard",
                table: "security_events");

            migrationBuilder.DropIndex(
                name: "IX_security_events_TargetId",
                schema: "guard",
                table: "security_events");

            migrationBuilder.DropColumn(
                name: "ActingAccountId",
                schema: "guard",
                table: "security_events");

            migrationBuilder.DropColumn(
                name: "ActingMode",
                schema: "guard",
                table: "security_events");

            migrationBuilder.DropColumn(
                name: "SessionId",
                schema: "guard",
                table: "security_events");

            migrationBuilder.DropColumn(
                name: "TargetId",
                schema: "guard",
                table: "security_events");

            migrationBuilder.DropColumn(
                name: "TargetName",
                schema: "guard",
                table: "security_events");

            migrationBuilder.DropColumn(
                name: "TargetType",
                schema: "guard",
                table: "security_events");
        }
    }
}
