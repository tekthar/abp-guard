using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class AppsMayRegister : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "AppsMayRegister",
                schema: "guard",
                table: "security_settings",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            // A site upgraded to this keeps apps registering themselves, as it did; a new site's seeder makes its row off.
            // A site from before the settings' row was made at start-up (it has accounts, no row) gets one.
            migrationBuilder.Sql("UPDATE guard.security_settings SET \"AppsMayRegister\" = true;");
            migrationBuilder.Sql("""
                INSERT INTO guard.security_settings ("Id", "AdminsTwoFactorSeeded", "AppsMayRegister", "RetentionDays", "StepUpMinutes", "TokenMaxDays", "SecondFactorMethods")
                SELECT '5ec0a0d1-0000-4000-8000-000000000001', false, true, 730, 10, 90, '[]'::jsonb
                WHERE NOT EXISTS (SELECT 1 FROM guard.security_settings) AND EXISTS (SELECT 1 FROM guard.accounts);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AppsMayRegister",
                schema: "guard",
                table: "security_settings");
        }
    }
}
