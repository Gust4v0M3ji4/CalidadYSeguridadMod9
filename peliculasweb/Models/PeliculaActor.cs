namespace peliculasweb.Models
{
    public class PeliculaActor
    {
        public int PeliculaId { get; set; }
        public Pelicula? Pelicula { get; set; }

        public int ActorId { get; set; }
        public Actor? Actor { get; set; }
    }
}