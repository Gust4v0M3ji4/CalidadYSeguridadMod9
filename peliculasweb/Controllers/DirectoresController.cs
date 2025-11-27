using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using peliculasweb.Data;
using peliculasweb.Models;

namespace peliculasweb.Controllers
{
    public class DirectoresController : Controller
    {
        private readonly AppDbContext _context;

        public DirectoresController(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Index()
        {
            return View(await _context.Directores.ToListAsync());
        }

        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
                return NotFound();

            var director = await _context.Directores.FirstOrDefaultAsync(m => m.Id == id);
            if (director == null)
                return NotFound();

            return View(director);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Biografia,Id,Nombre,FechaNacimiento,Nacionalidad")] Director director)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    var files = HttpContext.Request.Form.Files;
                    if (files.Count > 0 && files[0] != null && files[0].Length > 0)
                    {
                        var file = files[0];
                        var directoryPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/imagenes/directores");
                        if (!Directory.Exists(directoryPath))
                            Directory.CreateDirectory(directoryPath);

                        var fileName = Guid.NewGuid() + Path.GetExtension(file.FileName);
                        var filePath = Path.Combine(directoryPath, fileName);

                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            await file.CopyToAsync(stream);
                        }
                        director.ImagenRuta = "/imagenes/directores/" + fileName;
                    }

                    _context.Add(director);
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", "Error al guardar el director: " + ex.Message);
                }
            }
            return View(director);
        }

        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
                return NotFound();

            var director = await _context.Directores.FindAsync(id);
            if (director == null)
                return NotFound();

            return View(director);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Biografia,Id,Nombre,FechaNacimiento,Nacionalidad,ImagenRuta")] Director director)
        {
            if (id != director.Id)
                return NotFound();

            if (ModelState.IsValid)
            {
                try
                {
                    var directorOriginal = await _context.Directores.AsNoTracking().FirstOrDefaultAsync(d => d.Id == id);
                    string? imagenAnterior = directorOriginal?.ImagenRuta;

                    var files = HttpContext.Request.Form.Files;
                    if (files.Count > 0 && files[0] != null && files[0].Length > 0)
                    {
                        var file = files[0];
                        var directoryPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/imagenes/directores");
                        if (!Directory.Exists(directoryPath))
                            Directory.CreateDirectory(directoryPath);

                        var fileName = Guid.NewGuid() + Path.GetExtension(file.FileName);
                        var filePath = Path.Combine(directoryPath, fileName);

                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            await file.CopyToAsync(stream);
                        }
                        director.ImagenRuta = "/imagenes/directores/" + fileName;

                        // Eliminar imagen anterior
                        if (!string.IsNullOrEmpty(imagenAnterior))
                        {
                            var rutaAnterior = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", imagenAnterior.TrimStart('/'));
                            if (System.IO.File.Exists(rutaAnterior))
                                System.IO.File.Delete(rutaAnterior);
                        }
                    }

                    _context.Update(director);
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", "Error al guardar la imagen: " + ex.Message);
                }
            }
            return View(director);
        }

        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
                return NotFound();

            var director = await _context.Directores.FirstOrDefaultAsync(m => m.Id == id);
            if (director == null)
                return NotFound();

            return View(director);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var director = await _context.Directores.FindAsync(id);
            if (director != null)
            {
                if (!string.IsNullOrEmpty(director.ImagenRuta))
                {
                    var rutaCompleta = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", director.ImagenRuta.TrimStart('/'));
                    if (System.IO.File.Exists(rutaCompleta))
                        System.IO.File.Delete(rutaCompleta);
                }
                _context.Directores.Remove(director);
            }
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool DirectorExists(int id)
        {
            return _context.Directores.Any(e => e.Id == id);
        }
    }
}