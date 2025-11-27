using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using peliculasweb.Data;
using peliculasweb.Models;

namespace peliculasweb.Controllers
{
    // A2: Aplicar Rate Limiting al controlador para prevenir DoS y enumeración masiva
    [EnableRateLimiting("fixed")]
    public class PeliculasController : Controller
    {
        private readonly AppDbContext _context;

        public PeliculasController(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Index(string searchString, int? generoId)
        {
            var peliculas = _context.Peliculas.Include(p => p.Genero).Include(p => p.Director).AsQueryable();

            if (!string.IsNullOrEmpty(searchString))
            {
                peliculas = peliculas.Where(p => p.Titulo != null && p.Titulo.Contains(searchString));
            }

            if (generoId.HasValue)
            {
                peliculas = peliculas.Where(p => p.GeneroId == generoId.Value);
            }

            ViewData["CurrentFilter"] = searchString;
            ViewData["GeneroId"] = generoId;
            ViewData["Generos"] = new SelectList(_context.Generos, "Id", "Nombre");

            return View(await peliculas.ToListAsync());
        }

        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
                return NotFound();

            var pelicula = await _context.Peliculas
                .Include(p => p.Genero)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (pelicula == null)
                return NotFound();

            return View(pelicula);
        }

        public IActionResult Create()
        {
            ViewData["GeneroId"] = new SelectList(_context.Generos, "Id", "Nombre");
            ViewData["DirectorId"] = new SelectList(_context.Directores, "Id", "Nombre");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,Titulo,Sinopsis,Duracion,FechaEstreno,ImagenRuta,GeneroId,DirectorId")] Pelicula pelicula)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    var files = HttpContext.Request.Form.Files;
                    if (files.Count > 0)
                    {
                        var file = files[0];

                        // A3: Validar extensión de archivo permitida
                        var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif" };
                        var extension = Path.GetExtension(file.FileName).ToLower();

                        if (!allowedExtensions.Contains(extension))
                        {
                            ModelState.AddModelError("ImagenArchivo", "Solo se permiten archivos de imagen (JPG, JPEG, PNG, GIF)");
                            ViewData["GeneroId"] = new SelectList(_context.Generos, "Id", "Nombre", pelicula.GeneroId);
                            ViewData["DirectorId"] = new SelectList(_context.Directores, "Id", "Nombre", pelicula.DirectorId);
                            return View(pelicula);
                        }

                        // A3: Validar tipo MIME del archivo
                        var allowedMimeTypes = new[] { "image/jpeg", "image/png", "image/gif", "image/jpg" };
                        if (!allowedMimeTypes.Contains(file.ContentType.ToLower()))
                        {
                            ModelState.AddModelError("ImagenArchivo", "El tipo de archivo no es válido");
                            ViewData["GeneroId"] = new SelectList(_context.Generos, "Id", "Nombre", pelicula.GeneroId);
                            ViewData["DirectorId"] = new SelectList(_context.Directores, "Id", "Nombre", pelicula.DirectorId);
                            return View(pelicula);
                        }

                        // A3: Validar tamaño del archivo (5MB max)
                        if (file.Length > 5 * 1024 * 1024)
                        {
                            ModelState.AddModelError("ImagenArchivo", "El archivo no debe exceder 5MB");
                            ViewData["GeneroId"] = new SelectList(_context.Generos, "Id", "Nombre", pelicula.GeneroId);
                            ViewData["DirectorId"] = new SelectList(_context.Directores, "Id", "Nombre", pelicula.DirectorId);
                            return View(pelicula);
                        }

                        var directoryPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/imagenes/peliculas");
                        if (!Directory.Exists(directoryPath))
                            Directory.CreateDirectory(directoryPath);

                        // A3: Usar GUID para nombre de archivo (previene path traversal y sobrescritura)
                        var fileName = Guid.NewGuid() + extension;
                        var filePath = Path.Combine(directoryPath, fileName);

                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            await file.CopyToAsync(stream);
                        }
                        pelicula.ImagenRuta = "/imagenes/peliculas/" + fileName;
                    }

                    _context.Add(pelicula);
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", "Error al guardar la imagen: " + ex.Message);
                }
            }
            ViewData["GeneroId"] = new SelectList(_context.Generos, "Id", "Nombre", pelicula.GeneroId);
            ViewData["DirectorId"] = new SelectList(_context.Directores, "Id", "Nombre", pelicula.DirectorId);
            return View(pelicula);
        }

        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
                return NotFound();

            var pelicula = await _context.Peliculas.FindAsync(id);
            if (pelicula == null)
                return NotFound();

            ViewData["GeneroId"] = new SelectList(_context.Generos, "Id", "Nombre", pelicula.GeneroId);
            ViewData["DirectorId"] = new SelectList(_context.Directores, "Id", "Nombre", pelicula.DirectorId);
            return View(pelicula);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Titulo,Sinopsis,Duracion,FechaEstreno,ImagenRuta,GeneroId,DirectorId")] Pelicula pelicula)
        {
            if (id != pelicula.Id)
                return NotFound();

            if (ModelState.IsValid)
            {
                try
                {
                    var peliculaOriginal = await _context.Peliculas.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id);
                    string? imagenAnterior = peliculaOriginal?.ImagenRuta;

                    var files = HttpContext.Request.Form.Files;
                    if (files.Count > 0)
                    {
                        var file = files[0];
                        var directoryPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/imagenes/peliculas");
                        if (!Directory.Exists(directoryPath))
                            Directory.CreateDirectory(directoryPath);

                        var fileName = Guid.NewGuid() + Path.GetExtension(file.FileName);
                        var filePath = Path.Combine(directoryPath, fileName);

                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            await file.CopyToAsync(stream);
                        }
                        pelicula.ImagenRuta = "/imagenes/peliculas/" + fileName;

                        // Eliminar imagen anterior
                        if (!string.IsNullOrEmpty(imagenAnterior))
                        {
                            var rutaAnterior = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", imagenAnterior.TrimStart('/'));
                            if (System.IO.File.Exists(rutaAnterior))
                                System.IO.File.Delete(rutaAnterior);
                        }
                    }

                    _context.Update(pelicula);
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", "Error al guardar la imagen: " + ex.Message);
                }
            }
            ViewData["GeneroId"] = new SelectList(_context.Generos, "Id", "Nombre", pelicula.GeneroId);
            ViewData["DirectorId"] = new SelectList(_context.Directores, "Id", "Nombre", pelicula.DirectorId);
            return View(pelicula);
        }

        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
                return NotFound();

            var pelicula = await _context.Peliculas
                .Include(p => p.Genero)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (pelicula == null)
                return NotFound();

            return View(pelicula);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var pelicula = await _context.Peliculas.FindAsync(id);
            if (pelicula != null)
            {
                if (!string.IsNullOrEmpty(pelicula.ImagenRuta))
                {
                    var rutaCompleta = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", pelicula.ImagenRuta.TrimStart('/'));
                    if (System.IO.File.Exists(rutaCompleta))
                        System.IO.File.Delete(rutaCompleta);
                }
                _context.Peliculas.Remove(pelicula);
            }
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool PeliculaExists(int id)
        {
            return _context.Peliculas.Any(e => e.Id == id);
        }
    }
}