namespace peliculasweb.Models
{
    public class PeliculaTrabajador
    {
        public int PeliculaId { get; set; }
        public Pelicula? Pelicula { get; set; }

        public int TrabajadorId { get; set; }
        public Trabajador? Trabajador { get; set; }
    }
}