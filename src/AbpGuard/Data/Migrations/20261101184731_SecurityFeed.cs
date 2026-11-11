using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class SecurityFeed : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "security_alerts",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false),
                    CheckedUpTo = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    Sent = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_alerts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "security_feed",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false),
                    Url = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    ProtectedSecret = table.Column<string>(type: "text", nullable: true),
                    CursorTime = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CursorId = table.Column<Guid>(type: "uuid", nullable: true),
                    LastSentAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastError = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    FailingSince = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_security_feed", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "security_alerts",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "security_feed",
                schema: "guard");
        }
    }
}
