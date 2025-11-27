using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations.Schema;

#pragma warning disable CS8618

namespace peliculasweb.Models
{
    public class Cine
    {
        public int Id { get; set; }

        [Required]
        public string? Nombre { get; set; }

        [Required]
        public string? Direccion { get; set; }

        [Required]
        public string? Region { get; set; }

        [Required]
        public string? Descripcion { get; set; }

        public List<Proyeccion> Proyecciones { get; set; } = new();

        [Display(Name = "Imagen")]
        public string? ImagenRuta { get; set; }

        [NotMapped]
        public IFormFile? ImagenArchivo { get; set; }
    }
}

#pragma warning restore CS8618