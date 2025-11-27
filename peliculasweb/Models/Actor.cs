using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations.Schema;

namespace peliculasweb.Models
{
    public class Actor : Persona
    {
        public ICollection<PeliculaActor> PeliculaActores { get; set; } = new List<PeliculaActor>();

        [NotMapped]
        public IFormFile? ImagenArchivo { get; set; }
    }
}