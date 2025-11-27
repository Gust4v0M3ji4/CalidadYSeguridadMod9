using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace peliculasweb.Migrations
{
    /// <inheritdoc />
    public partial class CorregirModelosPersona : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Trabajador_Biografia",
                table: "Persona");

            migrationBuilder.DropColumn(
                name: "Trabajador_ImagenRuta",
                table: "Persona");

            migrationBuilder.AlterColumn<string>(
                name: "Biografia",
                table: "Persona",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "nvarchar(max)",
                oldNullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "Biografia",
                table: "Persona",
                type: "nvarchar(max)",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AddColumn<string>(
                name: "Trabajador_Biografia",
                table: "Persona",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Trabajador_ImagenRuta",
                table: "Persona",
                type: "nvarchar(max)",
                nullable: true);
        }
    }
}
