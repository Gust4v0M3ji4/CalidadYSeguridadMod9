using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations.Schema;

namespace peliculasweb.Models
{
    public class Pelicula
    {
        public int Id { get; set; }
        [Required]
        public string? Titulo { get; set; }
        [Required]
        public string? Sinopsis { get; set; }
        public int Duracion { get; set; } // en minutos
        public DateTime FechaEstreno { get; set; }

        [Display(Name = "Imagen")]
        public string? ImagenRuta { get; set; }

        [NotMapped]
        public IFormFile? ImagenArchivo { get; set; }

        public int GeneroId { get; set; }
        public Genero? Genero { get; set; }

        public int? DirectorId { get; set; }
        public Director? Director { get; set; }

        public ICollection<PeliculaTrabajador> PeliculaTrabajadores { get; set; } = new List<PeliculaTrabajador>();
        public ICollection<PeliculaActor> PeliculaActores { get; set; } = new List<PeliculaActor>();
        public ICollection<Review> Reviews { get; set; } = new List<Review>();
        public ICollection<Proyeccion> Proyecciones { get; set; } = new List<Proyeccion>();
    }
}