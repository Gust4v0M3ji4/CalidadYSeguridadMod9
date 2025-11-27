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

        // A3: Validación mejorada para prevenir inyecciones
        [Required(ErrorMessage = "El título es requerido")]
        [StringLength(200, ErrorMessage = "El título no puede exceder 200 caracteres")]
        [RegularExpression(@"^[a-zA-Z0-9\s\-:,.'áéíóúÁÉÍÓÚñÑ¿?¡!]+$",
            ErrorMessage = "El título solo puede contener letras, números, espacios y puntuación básica")]
        public string? Titulo { get; set; }

        [Required(ErrorMessage = "La sinopsis es requerida")]
        [StringLength(2000, ErrorMessage = "La sinopsis no puede exceder 2000 caracteres")]
        public string? Sinopsis { get; set; }

        [Required(ErrorMessage = "La duración es requerida")]
        [Range(1, 600, ErrorMessage = "La duración debe estar entre 1 y 600 minutos")]
        public int Duracion { get; set; } // en minutos

        [Required(ErrorMessage = "La fecha de estreno es requerida")]
        [DataType(DataType.Date)]
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