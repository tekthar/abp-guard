using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class PrivacyRecord : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "privacy_settings",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false),
                    ControllerName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    ControllerContact = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    OfficerName = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    OfficerContact = table.Column<string>(type: "character varying(500)", maxLength: 500, nullable: true),
                    Destinations = table.Column<string>(type: "jsonb", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedBy = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_privacy_settings", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "privacy_stores",
                schema: "guard",
                columns: table => new
                {
                    StoreKey = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    LegalBasis = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    Sensitive = table.Column<bool>(type: "boolean", nullable: true),
                    Notes = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    UpdatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    UpdatedBy = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_privacy_stores", x => x.StoreKey);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "privacy_settings",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "privacy_stores",
                schema: "guard");
        }
    }
}
