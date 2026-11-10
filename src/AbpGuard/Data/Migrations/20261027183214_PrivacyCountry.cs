using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class PrivacyCountry : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Country",
                schema: "guard",
                table: "privacy_settings",
                type: "character varying(200)",
                maxLength: 200,
                nullable: true);

            // What a site recorded before (ADR 0082, step 2b) said "outside the Kingdom": its country is Saudi Arabia, and
            // each destination's outsideKingdom is now its outsideCountry.
            migrationBuilder.Sql("""
                UPDATE guard.privacy_settings SET "Country" = 'Saudi Arabia', "Destinations" = COALESCE((
                    SELECT jsonb_object_agg(d.key, (d.value - 'outsideKingdom') || jsonb_build_object('outsideCountry', COALESCE(d.value -> 'outsideKingdom', 'false'::jsonb)))
                    FROM jsonb_each("Destinations") d), '{}'::jsonb);
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("""
                UPDATE guard.privacy_settings SET "Destinations" = COALESCE((
                    SELECT jsonb_object_agg(d.key, (d.value - 'outsideCountry') || jsonb_build_object('outsideKingdom', COALESCE(d.value -> 'outsideCountry', 'false'::jsonb)))
                    FROM jsonb_each("Destinations") d), '{}'::jsonb);
                """);
            migrationBuilder.DropColumn(
                name: "Country",
                schema: "guard",
                table: "privacy_settings");
        }
    }
}
