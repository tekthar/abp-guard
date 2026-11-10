using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AbpGuard.Data.Migrations
{
    /// <summary>
    /// A personal access token's ProjectIds is Guard's ResourceIds (ADR 0087): the model's name only. The table and its
    /// column ProjectIds don't change, so there's nothing to do; the migration keeps the model and its snapshot together.
    /// </summary>
    public partial class ResourceIds : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {

        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {

        }
    }
}
