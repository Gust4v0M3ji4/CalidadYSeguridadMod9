using Microsoft.EntityFrameworkCore;
using peliculasweb.Models;

namespace peliculasweb.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<Genero> Generos { get; set; }
        public DbSet<Director> Directores { get; set; }
        public DbSet<Trabajador> Trabajadores { get; set; }
        public DbSet<Actor> Actores { get; set; }
        public DbSet<Pelicula> Peliculas { get; set; }
        public DbSet<Cine> Cines { get; set; }
        public DbSet<Proyeccion> Proyecciones { get; set; }
        public DbSet<Review> Reviews { get; set; }
        public DbSet<PeliculaTrabajador> PeliculaTrabajadores { get; set; }
        public DbSet<PeliculaActor> PeliculaActores { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Relación muchos a muchos: Pelicula <-> Actor
            modelBuilder.Entity<PeliculaActor>()
                .HasKey(pa => new { pa.PeliculaId, pa.ActorId });

            modelBuilder.Entity<PeliculaActor>()
                .HasOne(pa => pa.Pelicula)
                .WithMany(p => p.PeliculaActores)
                .HasForeignKey(pa => pa.PeliculaId);

            modelBuilder.Entity<PeliculaActor>()
                .HasOne(pa => pa.Actor)
                .WithMany(a => a.PeliculaActores)
                .HasForeignKey(pa => pa.ActorId);

            // Relación muchos a muchos: Pelicula <-> Trabajador
            modelBuilder.Entity<PeliculaTrabajador>()
                .HasKey(pt => new { pt.PeliculaId, pt.TrabajadorId });

            modelBuilder.Entity<PeliculaTrabajador>()
                .HasOne(pt => pt.Pelicula)
                .WithMany(p => p.PeliculaTrabajadores)
                .HasForeignKey(pt => pt.PeliculaId);

            modelBuilder.Entity<PeliculaTrabajador>()
                .HasOne(pt => pt.Trabajador)
                .WithMany(t => t.PeliculaTrabajadores)
                .HasForeignKey(pt => pt.TrabajadorId);

            // Herencia TPH para Persona
            modelBuilder.Entity<Actor>().HasBaseType<Persona>();
            modelBuilder.Entity<Trabajador>().HasBaseType<Persona>();
        }
    }
}