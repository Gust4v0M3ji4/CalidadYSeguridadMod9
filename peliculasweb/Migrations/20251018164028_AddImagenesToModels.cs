using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace peliculasweb.Migrations
{
    /// <inheritdoc />
    public partial class AddImagenesToModels : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Imagen",
                table: "Peliculas");

            migrationBuilder.AddColumn<string>(
                name: "ImagenRuta",
                table: "Persona",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Trabajador_ImagenRuta",
                table: "Persona",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ImagenRuta",
                table: "Peliculas",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ImagenRuta",
                table: "Cines",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ImagenRuta",
                table: "Persona");

            migrationBuilder.DropColumn(
                name: "Trabajador_ImagenRuta",
                table: "Persona");

            migrationBuilder.DropColumn(
                name: "ImagenRuta",
                table: "Peliculas");

            migrationBuilder.DropColumn(
                name: "ImagenRuta",
                table: "Cines");

            migrationBuilder.AddColumn<string>(
                name: "Imagen",
                table: "Peliculas",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }
    }
}
