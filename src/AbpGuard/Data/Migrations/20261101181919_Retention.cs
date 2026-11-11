using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class Retention : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "retention_periods",
                schema: "guard",
                columns: table => new
                {
                    RuleKey = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Days = table.Column<int>(type: "integer", nullable: true),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    UpdatedBy = table.Column<Guid>(type: "uuid", nullable: true),
                    LastSweptAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    LastCount = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_retention_periods", x => x.RuleKey);
                });

            migrationBuilder.CreateTable(
                name: "retention_settings",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false),
                    ConfirmedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ConfirmedBy = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_retention_settings", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "retention_periods",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "retention_settings",
                schema: "guard");
        }
    }
}
