using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class TwoFactorCodes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "SecondFactorMethods",
                schema: "guard",
                table: "security_settings",
                type: "jsonb",
                nullable: false,
                defaultValueSql: "'[]'::jsonb");

            migrationBuilder.CreateTable(
                name: "sent_codes",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: false),
                    Method = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    CodeHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_sent_codes", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_sent_codes_AccountId_Method",
                schema: "guard",
                table: "sent_codes",
                columns: new[] { "AccountId", "Method" });

            migrationBuilder.CreateIndex(
                name: "IX_sent_codes_ExpiresAt",
                schema: "guard",
                table: "sent_codes",
                column: "ExpiresAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "sent_codes",
                schema: "guard");

            migrationBuilder.DropColumn(
                name: "SecondFactorMethods",
                schema: "guard",
                table: "security_settings");
        }
    }
}
