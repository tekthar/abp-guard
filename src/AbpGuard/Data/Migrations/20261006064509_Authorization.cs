using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class Authorization : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "role_grants",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RoleId = table.Column<Guid>(type: "uuid", nullable: false),
                    PrincipalType = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    PrincipalId = table.Column<Guid>(type: "uuid", nullable: false),
                    ScopeJson = table.Column<string>(type: "jsonb", nullable: false),
                    ValidUntil = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    CreatedBy = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_role_grants", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "role_rules",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    RoleId = table.Column<Guid>(type: "uuid", nullable: false),
                    Order = table.Column<int>(type: "integer", nullable: false),
                    Json = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_role_rules", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "roles",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Key = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    IsSystem = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_roles", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_role_grants_PrincipalType_PrincipalId",
                schema: "guard",
                table: "role_grants",
                columns: new[] { "PrincipalType", "PrincipalId" });

            migrationBuilder.CreateIndex(
                name: "IX_role_grants_RoleId",
                schema: "guard",
                table: "role_grants",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "IX_role_rules_RoleId_Order",
                schema: "guard",
                table: "role_rules",
                columns: new[] { "RoleId", "Order" });

            migrationBuilder.CreateIndex(
                name: "IX_roles_Key",
                schema: "guard",
                table: "roles",
                column: "Key",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "role_grants",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "role_rules",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "roles",
                schema: "guard");
        }
    }
}
