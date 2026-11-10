using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class SessionHandoffs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ParentAuthorizationId",
                schema: "guard",
                table: "sessions",
                type: "character varying(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "session_handoffs",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CodeHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: false),
                    AuthorizationId = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    AuthTime = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UsedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_session_handoffs", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_sessions_ParentAuthorizationId",
                schema: "guard",
                table: "sessions",
                column: "ParentAuthorizationId");

            migrationBuilder.CreateIndex(
                name: "IX_session_handoffs_CodeHash",
                schema: "guard",
                table: "session_handoffs",
                column: "CodeHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_session_handoffs_ExpiresAt",
                schema: "guard",
                table: "session_handoffs",
                column: "ExpiresAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "session_handoffs",
                schema: "guard");

            migrationBuilder.DropIndex(
                name: "IX_sessions_ParentAuthorizationId",
                schema: "guard",
                table: "sessions");

            migrationBuilder.DropColumn(
                name: "ParentAuthorizationId",
                schema: "guard",
                table: "sessions");
        }
    }
}
