using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <inheritdoc />
    public partial class AccountPictures : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Picture",
                schema: "guard",
                table: "accounts",
                type: "character varying(300)",
                maxLength: 300,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Picture",
                schema: "guard",
                table: "accounts");
        }
    }
}
