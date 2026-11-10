using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "guard");

            migrationBuilder.CreateTable(
                name: "accounts",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Username = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    NormalizedUsername = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    DisplayName = table.Column<string>(type: "text", nullable: false),
                    Email = table.Column<string>(type: "text", nullable: true),
                    Status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    StatusReason = table.Column<string>(type: "text", nullable: true),
                    DirectoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    DirectoryUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    LockedLocally = table.Column<bool>(type: "boolean", nullable: false),
                    LastLoginAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_accounts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "directories",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Type = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Order = table.Column<int>(type: "integer", nullable: false),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false),
                    AuthenticationEnabled = table.Column<bool>(type: "boolean", nullable: false),
                    SettingsJson = table.Column<string>(type: "jsonb", nullable: false),
                    ProtectedSecrets = table.Column<string>(type: "text", nullable: true),
                    SyncIntervalMinutes = table.Column<int>(type: "integer", nullable: true),
                    LastSyncAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastSyncSucceeded = table.Column<bool>(type: "boolean", nullable: true),
                    LastSyncMessage = table.Column<string>(type: "text", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_directories", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "directory_users",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DirectoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    ExternalId = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Username = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    NormalizedUsername = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    DisplayName = table.Column<string>(type: "text", nullable: true),
                    Email = table.Column<string>(type: "text", nullable: true),
                    IsActive = table.Column<bool>(type: "boolean", nullable: false),
                    PasswordHash = table.Column<string>(type: "text", nullable: true),
                    LastSyncedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_directory_users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "groups",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DirectoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    ExternalId = table.Column<string>(type: "text", nullable: true),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    NormalizedName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    IsLocal = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_groups", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "memberships",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    GroupId = table.Column<Guid>(type: "uuid", nullable: false),
                    MemberType = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    MemberId = table.Column<Guid>(type: "uuid", nullable: false),
                    Source = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_memberships", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "security_events",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Time = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Type = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Username = table.Column<string>(type: "text", nullable: true),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: true),
                    Detail = table.Column<string>(type: "text", nullable: true),
                    Ip = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_events", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "sync_runs",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DirectoryId = table.Column<Guid>(type: "uuid", nullable: false),
                    StartedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    FinishedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    Succeeded = table.Column<bool>(type: "boolean", nullable: true),
                    UsersAdded = table.Column<int>(type: "integer", nullable: false),
                    UsersUpdated = table.Column<int>(type: "integer", nullable: false),
                    UsersDeactivated = table.Column<int>(type: "integer", nullable: false),
                    GroupsSynced = table.Column<int>(type: "integer", nullable: false),
                    MembershipsSynced = table.Column<int>(type: "integer", nullable: false),
                    Error = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_sync_runs", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_accounts_NormalizedUsername",
                schema: "guard",
                table: "accounts",
                column: "NormalizedUsername",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_directories_Order",
                schema: "guard",
                table: "directories",
                column: "Order");

            migrationBuilder.CreateIndex(
                name: "IX_directory_users_DirectoryId_ExternalId",
                schema: "guard",
                table: "directory_users",
                columns: new[] { "DirectoryId", "ExternalId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_directory_users_DirectoryId_NormalizedUsername",
                schema: "guard",
                table: "directory_users",
                columns: new[] { "DirectoryId", "NormalizedUsername" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_directory_users_NormalizedUsername",
                schema: "guard",
                table: "directory_users",
                column: "NormalizedUsername");

            migrationBuilder.CreateIndex(
                name: "IX_groups_DirectoryId_NormalizedName",
                schema: "guard",
                table: "groups",
                columns: new[] { "DirectoryId", "NormalizedName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_memberships_GroupId_MemberType_MemberId_Source",
                schema: "guard",
                table: "memberships",
                columns: new[] { "GroupId", "MemberType", "MemberId", "Source" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_memberships_MemberType_MemberId",
                schema: "guard",
                table: "memberships",
                columns: new[] { "MemberType", "MemberId" });

            migrationBuilder.CreateIndex(
                name: "IX_security_events_Time",
                schema: "guard",
                table: "security_events",
                column: "Time");

            migrationBuilder.CreateIndex(
                name: "IX_sync_runs_DirectoryId_StartedAt",
                schema: "guard",
                table: "sync_runs",
                columns: new[] { "DirectoryId", "StartedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "accounts",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "directories",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "directory_users",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "groups",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "memberships",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "security_events",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "sync_runs",
                schema: "guard");
        }
    }
}
