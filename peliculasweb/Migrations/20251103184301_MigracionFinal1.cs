using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace peliculasweb.Migrations
{
    /// <inheritdoc />
    public partial class MigracionFinal1 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "DirectorId",
                table: "Peliculas",
                type: "int",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "Directores",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Nombre = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    FechaNacimiento = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Nacionalidad = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Biografia = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ImagenRuta = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Directores", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Peliculas_DirectorId",
                table: "Peliculas",
                column: "DirectorId");

            migrationBuilder.AddForeignKey(
                name: "FK_Peliculas_Directores_DirectorId",
                table: "Peliculas",
                column: "DirectorId",
                principalTable: "Directores",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Peliculas_Directores_DirectorId",
                table: "Peliculas");

            migrationBuilder.DropTable(
                name: "Directores");

            migrationBuilder.DropIndex(
                name: "IX_Peliculas_DirectorId",
                table: "Peliculas");

            migrationBuilder.DropColumn(
                name: "DirectorId",
                table: "Peliculas");
        }
    }
}
