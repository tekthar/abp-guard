using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class Erasure : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "ErasedAt",
                schema: "guard",
                table: "accounts",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "erasures",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Number = table.Column<int>(type: "integer", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: true),
                    Subject = table.Column<string>(type: "jsonb", nullable: true),
                    State = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Stores = table.Column<string>(type: "jsonb", nullable: false),
                    Reason = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    DeclinedReason = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true),
                    RequestedBy = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    DecidedBy = table.Column<Guid>(type: "uuid", nullable: true),
                    StartedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    FinishedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_erasures", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "legal_holds",
                schema: "guard",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AccountId = table.Column<Guid>(type: "uuid", nullable: true),
                    Address = table.Column<string>(type: "character varying(320)", maxLength: 320, nullable: true),
                    Reason = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: false),
                    Until = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    CreatedBy = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                    ReleasedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                    ReleasedBy = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_legal_holds", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_erasures_AccountId",
                schema: "guard",
                table: "erasures",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_erasures_Number",
                schema: "guard",
                table: "erasures",
                column: "Number",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_erasures_State",
                schema: "guard",
                table: "erasures",
                column: "State");

            migrationBuilder.CreateIndex(
                name: "IX_legal_holds_AccountId",
                schema: "guard",
                table: "legal_holds",
                column: "AccountId");

            migrationBuilder.CreateIndex(
                name: "IX_legal_holds_Address",
                schema: "guard",
                table: "legal_holds",
                column: "Address");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "erasures",
                schema: "guard");

            migrationBuilder.DropTable(
                name: "legal_holds",
                schema: "guard");

            migrationBuilder.DropColumn(
                name: "ErasedAt",
                schema: "guard",
                table: "accounts");
        }
    }
}
