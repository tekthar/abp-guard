using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class TwoFactor : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "AdminsTwoFactorSeeded",
                schema: "guard",
                table: "security_settings",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "TwoFactor",
                schema: "guard",
                table: "groups",
                type: "character varying(16)",
                maxLength: 16,
                nullable: false,
                defaultValue: "off");

            migrationBuilder.CreateTable(
                name: "recovery_codes",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: false),
                    Hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_recovery_codes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "second_factors",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: false),
                    Kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ProtectedSecret = table.Column<string>(type: "text", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ConfirmedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastUsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastStep = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_second_factors", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "sign_in_tickets",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: false),
                    TicketHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Client = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Scopes = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Ip = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Attempts = table.Column<int>(type: "integer", nullable: false),
                    ProvedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_sign_in_tickets", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_recovery_codes_AccountId",
                schema: "guard",
                table: "recovery_codes",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_second_factors_AccountId",
                schema: "guard",
                table: "second_factors",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_sign_in_tickets_ExpiresAt",
                schema: "guard",
                table: "sign_in_tickets",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_sign_in_tickets_TicketHash",
                schema: "guard",
                table: "sign_in_tickets",
                column: "TicketHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "recovery_codes",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "second_factors",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "sign_in_tickets",
                schema: "guard");

            migrationBuilder.DropColumn(
                name: "AdminsTwoFactorSeeded",
                schema: "guard",
                table: "security_settings");

            migrationBuilder.DropColumn(
                name: "TwoFactor",
                schema: "guard",
                table: "groups");
        }
    }
}
