using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace peliculasweb.Models
{
    public class Genero
    {
        public int Id { get; set; }
        [Required]
        public string? Nombre { get; set; }
        [Required]
        public string? Descripcion { get; set; }
        public List<Pelicula> Peliculas { get; set; } = new();
    }
}