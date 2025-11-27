using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using peliculasweb.Data;
using peliculasweb.Models;

namespace peliculasweb.Controllers
{
    // A2: Aplicar Rate Limiting para prevenir enumeración masiva
    [EnableRateLimiting("fixed")]
    public class ActoresController : Controller
    {
        private readonly AppDbContext _context;

        public ActoresController(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Index()
        {
            return View(await _context.Actores.ToListAsync());
        }

        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
                return NotFound();

            var actor = await _context.Actores.FirstOrDefaultAsync(m => m.Id == id);
            if (actor == null)
                return NotFound();

            return View(actor);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Biografia,Id,Nombre,FechaNacimiento,Nacionalidad")] Actor actor)
        {
            System.Diagnostics.Debug.WriteLine("Entrando a Create POST de Actores");

            if (ModelState.IsValid)
            {
                try
                {
                    var files = HttpContext.Request.Form.Files;
                    System.Diagnostics.Debug.WriteLine($"Archivos recibidos: {files.Count}");

                    if (files.Count > 0 && files[0] != null && files[0].Length > 0)
                    {
                        var file = files[0];
                        System.Diagnostics.Debug.WriteLine("Procesando imagen: " + file.FileName);

                        var directoryPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/imagenes/actores");
                        if (!Directory.Exists(directoryPath))
                        {
                            Directory.CreateDirectory(directoryPath);
                            System.Diagnostics.Debug.WriteLine("Directorio de imágenes creado.");
                        }

                        var fileName = Guid.NewGuid() + Path.GetExtension(file.FileName);
                        var filePath = Path.Combine(directoryPath, fileName);

                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            await file.CopyToAsync(stream);
                        }
                        actor.ImagenRuta = "/imagenes/actores/" + fileName;
                        System.Diagnostics.Debug.WriteLine("Imagen guardada en: " + actor.ImagenRuta);
                    }
                    else
                    {
                        System.Diagnostics.Debug.WriteLine("No se recibió ninguna imagen. Se guardará sin imagen.");
                        actor.ImagenRuta = null;
                    }

                    _context.Add(actor);
                    await _context.SaveChangesAsync();
                    System.Diagnostics.Debug.WriteLine("Actor guardado. Redirigiendo a Index.");
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine("ERROR en try/catch del Create: " + ex.ToString());
                    ModelState.AddModelError("", "Error al guardar el actor: " + ex.Message);
                }
            }
            else
            {
                System.Diagnostics.Debug.WriteLine("ModelState inválido");
                foreach (var value in ModelState.Values)
                {
                    foreach (var error in value.Errors)
                    {
                        System.Diagnostics.Debug.WriteLine("ModelState error: " + error.ErrorMessage);
                    }
                }
            }

            // Si llega aquí es porque hubo error
            return View(actor);
        }

        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
                return NotFound();

            var actor = await _context.Actores.FindAsync(id);
            if (actor == null)
                return NotFound();

            return View(actor);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Biografia,Id,Nombre,FechaNacimiento,Nacionalidad,ImagenRuta")] Actor actor)
        {
            if (id != actor.Id)
                return NotFound();

            if (ModelState.IsValid)
            {
                try
                {
                    var actorOriginal = await _context.Actores.AsNoTracking().FirstOrDefaultAsync(a => a.Id == id);
                    string? imagenAnterior = actorOriginal?.ImagenRuta;

                    var files = HttpContext.Request.Form.Files;
                    if (files.Count > 0 && files[0] != null && files[0].Length > 0)
                    {
                        var file = files[0];
                        var directoryPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/imagenes/actores");
                        if (!Directory.Exists(directoryPath))
                            Directory.CreateDirectory(directoryPath);

                        var fileName = Guid.NewGuid() + Path.GetExtension(file.FileName);
                        var filePath = Path.Combine(directoryPath, fileName);

                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            await file.CopyToAsync(stream);
                        }
                        actor.ImagenRuta = "/imagenes/actores/" + fileName;

                        // Eliminar imagen anterior
                        if (!string.IsNullOrEmpty(imagenAnterior))
                        {
                            var rutaAnterior = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", imagenAnterior.TrimStart('/'));
                            if (System.IO.File.Exists(rutaAnterior))
                                System.IO.File.Delete(rutaAnterior);
                        }
                    }

                    _context.Update(actor);
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", "Error al guardar la imagen: " + ex.Message);
                }
            }
            return View(actor);
        }

        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
                return NotFound();

            var actor = await _context.Actores.FirstOrDefaultAsync(m => m.Id == id);
            if (actor == null)
                return NotFound();

            return View(actor);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var actor = await _context.Actores.FindAsync(id);
            if (actor != null)
            {
                // Eliminar imagen física
                if (!string.IsNullOrEmpty(actor.ImagenRuta))
                {
                    var rutaCompleta = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", actor.ImagenRuta.TrimStart('/'));
                    if (System.IO.File.Exists(rutaCompleta))
                        System.IO.File.Delete(rutaCompleta);
                }
                _context.Actores.Remove(actor);
            }
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool ActorExists(int id)
        {
            return _context.Actores.Any(e => e.Id == id);
        }
    }
}