using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class AccountMerges : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "MailTo",
                schema: "guard",
                table: "accounts",
                type: "character varying(320)",
                maxLength: 320,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "MergedIntoId",
                schema: "guard",
                table: "accounts",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "account_emails",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: false),
                    Email = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: false),
                    NormalizedEmail = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: false),
                    Source = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    VerifiedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    AddedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    AddedBy = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_account_emails", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "account_merges",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SourceId = table.Column<Guid>(type: "uuid", nullable: false),
                    SurvivorId = table.Column<Guid>(type: "uuid", nullable: false),
                    SourceUsername = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    SourceDisplayName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    SourceEmail = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: true),
                    SourceDirectoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    SurvivorUsername = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    ActorId = table.Column<Guid>(type: "uuid", nullable: true),
                    Reason = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    StartedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FinishedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Steps = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_account_merges", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_accounts_MergedIntoId",
                schema: "guard",
                table: "accounts",
                column: "MergedIntoId");

            migrationBuilder.CreateIndex(
                name: "IX_account_emails_AccountId_NormalizedEmail",
                schema: "guard",
                table: "account_emails",
                columns: new[] { "AccountId", "NormalizedEmail" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_account_emails_verified",
                schema: "guard",
                table: "account_emails",
                column: "NormalizedEmail",
                unique: true,
                filter: "\"VerifiedAt\" IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_account_merges_SourceId",
                schema: "guard",
                table: "account_merges",
                column: "SourceId");

            migrationBuilder.CreateIndex(
                name: "IX_account_merges_StartedAt",
                schema: "guard",
                table: "account_merges",
                column: "StartedAt");

            migrationBuilder.CreateIndex(
                name: "IX_account_merges_SurvivorId",
                schema: "guard",
                table: "account_merges",
                column: "SurvivorId");

            // ADR 0041: an account merged into another (ADR 0044) loses its rights, so that write moves the stamp too.
            migrationBuilder.Sql(Trigger("\"Status\", \"Username\", \"NormalizedUsername\", \"DirectoryId\", \"DirectoryUserId\", \"MergedIntoId\""));
        }

        private static string Trigger(string columns) => $"""
            DROP TRIGGER IF EXISTS permissions_changed ON guard.accounts;
            CREATE TRIGGER permissions_changed AFTER INSERT OR DELETE OR UPDATE OF {columns} ON guard.accounts
            FOR EACH STATEMENT EXECUTE FUNCTION guard.permissions_changed();
            """;

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(Trigger("\"Status\", \"Username\", \"NormalizedUsername\", \"DirectoryId\", \"DirectoryUserId\""));

            migrationBuilder.DropTable(
                name: "account_emails",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "account_merges",
                schema: "guard");

            migrationBuilder.DropIndex(
                name: "IX_accounts_MergedIntoId",
                schema: "guard",
                table: "accounts");

            migrationBuilder.DropColumn(
                name: "MailTo",
                schema: "guard",
                table: "accounts");

            migrationBuilder.DropColumn(
                name: "MergedIntoId",
                schema: "guard",
                table: "accounts");
        }
    }
}
