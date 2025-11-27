using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace peliculasweb.Models
{
    public class Trabajador : Persona
    {
        [Required]
        public string? Rol { get; set; }
        public List<PeliculaTrabajador> PeliculaTrabajadores { get; set; } = new();

        [NotMapped]
        public IFormFile? ImagenArchivo { get; set; }
    }
}