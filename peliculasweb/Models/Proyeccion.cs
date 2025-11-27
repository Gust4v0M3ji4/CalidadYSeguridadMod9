using System;

namespace peliculasweb.Models
{
    public class Proyeccion
    {
        public int Id { get; set; }
        public DateTime FechaInicio { get; set; }
        public DateTime FechaFin { get; set; }

        public int PeliculaId { get; set; }
        public Pelicula? Pelicula { get; set; }

        public int CineId { get; set; }
        public Cine? Cine { get; set; }
    }
}