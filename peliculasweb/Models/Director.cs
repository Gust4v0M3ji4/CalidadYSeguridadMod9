using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations.Schema;

namespace peliculasweb.Models
{
    public class Director
    {
        public int Id { get; set; }

        [Required]
        public string? Nombre { get; set; }

        public DateTime FechaNacimiento { get; set; }

        [Required]
        public string? Nacionalidad { get; set; }

        public string? Biografia { get; set; }

        [Display(Name = "Imagen")]
        public string? ImagenRuta { get; set; }

        [NotMapped]
        public IFormFile? ImagenArchivo { get; set; }

        public ICollection<Pelicula> Peliculas { get; set; } = new List<Pelicula>();
    }
}