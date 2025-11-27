using System;
using System.ComponentModel.DataAnnotations;

namespace peliculasweb.Models
{
    public class Review
    {
        public int Id { get; set; }
        [Required]
        public string? NombreUsuario { get; set; }
        [Required]
        public string? Comentario { get; set; }
        public int Puntuacion { get; set; }
        public DateTime Fecha { get; set; }

        public int PeliculaId { get; set; }
        public Pelicula? Pelicula { get; set; }
    }
}