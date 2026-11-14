using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class Passkeys : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "RecoveryAuthTime",
                schema: "guard",
                table: "sessions",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "StrongAuthTime",
                schema: "guard",
                table: "sessions",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "StrongAuthTime",
                schema: "guard",
                table: "session_handoffs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "passkey_challenges",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: false),
                    ChallengeHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Purpose = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Binding = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Options = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_passkey_challenges", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "passkeys",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: false),
                    CredentialId = table.Column<byte[]>(type: "bytea", maxLength: 1023, nullable: false),
                    PublicKey = table.Column<byte[]>(type: "bytea", nullable: false),
                    SignCount = table.Column<long>(type: "bigint", nullable: false),
                    AaGuid = table.Column<Guid>(type: "uuid", nullable: false),
                    Transports = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    BackupEligible = table.Column<bool>(type: "boolean", nullable: false),
                    BackedUp = table.Column<bool>(type: "boolean", nullable: false),
                    Name = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    LastUsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_passkeys", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_passkey_challenges_AccountId",
                schema: "guard",
                table: "passkey_challenges",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_passkey_challenges_ChallengeHash",
                schema: "guard",
                table: "passkey_challenges",
                column: "ChallengeHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_passkey_challenges_ExpiresAt",
                schema: "guard",
                table: "passkey_challenges",
                column: "ExpiresAt");

            migrationBuilder.CreateIndex(
                name: "IX_passkeys_AccountId",
                schema: "guard",
                table: "passkeys",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_passkeys_CredentialId",
                schema: "guard",
                table: "passkeys",
                column: "CredentialId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "passkey_challenges",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "passkeys",
                schema: "guard");

            migrationBuilder.DropColumn(
                name: "RecoveryAuthTime",
                schema: "guard",
                table: "sessions");

            migrationBuilder.DropColumn(
                name: "StrongAuthTime",
                schema: "guard",
                table: "sessions");

            migrationBuilder.DropColumn(
                name: "StrongAuthTime",
                schema: "guard",
                table: "session_handoffs");
        }
    }
}
