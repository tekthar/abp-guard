using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class PrivacyNotice : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "consent_withdrawals",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: false),
                    StoreKey = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    At = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    HandledAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    HandledBy = table.Column<Guid>(type: "uuid", nullable: true),
                    Note = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_consent_withdrawals", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "privacy_acceptances",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: true),
                    Address = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: true),
                    Version = table.Column<int>(type: "integer", nullable: false),
                    Where = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    At = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Ip = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_privacy_acceptances", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "privacy_notices",
                schema: "guard",
                columns: table => new
                {
                    Number = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Texts = table.Column<string>(type: "jsonb", nullable: false),
                    PublishedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    PublishedBy = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_privacy_notices", x => x.Number);
                });

            migrationBuilder.CreateIndex(
                name: "IX_consent_withdrawals_AccountId",
                schema: "guard",
                table: "consent_withdrawals",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_privacy_acceptances_AccountId",
                schema: "guard",
                table: "privacy_acceptances",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_privacy_acceptances_Address",
                schema: "guard",
                table: "privacy_acceptances",
                column: "Address");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "consent_withdrawals",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "privacy_acceptances",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "privacy_notices",
                schema: "guard");
        }
    }
}
