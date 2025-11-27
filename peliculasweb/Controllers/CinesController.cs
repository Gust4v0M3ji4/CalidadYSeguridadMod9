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
    public class CinesController : Controller
    {
        private readonly AppDbContext _context;

        public CinesController(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Index()
        {
            return View(await _context.Cines.ToListAsync());
        }

        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
                return NotFound();

            var cine = await _context.Cines.FirstOrDefaultAsync(m => m.Id == id);
            if (cine == null)
                return NotFound();

            return View(cine);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,Nombre,Direccion,Region,Descripcion,ImagenRuta")] Cine cine)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    var files = HttpContext.Request.Form.Files;
                    if (files.Count > 0)
                    {
                        var file = files[0];
                        var directoryPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/imagenes/cines");
                        if (!Directory.Exists(directoryPath))
                            Directory.CreateDirectory(directoryPath);

                        var fileName = Guid.NewGuid() + Path.GetExtension(file.FileName);
                        var filePath = Path.Combine(directoryPath, fileName);

                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            await file.CopyToAsync(stream);
                        }
                        cine.ImagenRuta = "/imagenes/cines/" + fileName;
                    }

                    _context.Add(cine);
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", "Error al guardar la imagen: " + ex.Message);
                }
            }
            return View(cine);
        }

        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
                return NotFound();

            var cine = await _context.Cines.FindAsync(id);
            if (cine == null)
                return NotFound();

            return View(cine);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Nombre,Direccion,Region,Descripcion,ImagenRuta")] Cine cine)
        {
            if (id != cine.Id)
                return NotFound();

            if (ModelState.IsValid)
            {
                try
                {
                    var cineOriginal = await _context.Cines.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id);
                    string? imagenAnterior = cineOriginal?.ImagenRuta;

                    var files = HttpContext.Request.Form.Files;
                    if (files.Count > 0)
                    {
                        var file = files[0];
                        var directoryPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/imagenes/cines");
                        if (!Directory.Exists(directoryPath))
                            Directory.CreateDirectory(directoryPath);

                        var fileName = Guid.NewGuid() + Path.GetExtension(file.FileName);
                        var filePath = Path.Combine(directoryPath, fileName);

                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            await file.CopyToAsync(stream);
                        }
                        cine.ImagenRuta = "/imagenes/cines/" + fileName;

                        // Eliminar imagen anterior
                        if (!string.IsNullOrEmpty(imagenAnterior))
                        {
                            var rutaAnterior = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", imagenAnterior.TrimStart('/'));
                            if (System.IO.File.Exists(rutaAnterior))
                                System.IO.File.Delete(rutaAnterior);
                        }
                    }

                    _context.Update(cine);
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", "Error al guardar la imagen: " + ex.Message);
                }
            }
            return View(cine);
        }

        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
                return NotFound();

            var cine = await _context.Cines.FirstOrDefaultAsync(m => m.Id == id);
            if (cine == null)
                return NotFound();

            return View(cine);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var cine = await _context.Cines.FindAsync(id);
            if (cine != null)
            {
                if (!string.IsNullOrEmpty(cine.ImagenRuta))
                {
                    var rutaCompleta = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", cine.ImagenRuta.TrimStart('/'));
                    if (System.IO.File.Exists(rutaCompleta))
                        System.IO.File.Delete(rutaCompleta);
                }
                _context.Cines.Remove(cine);
            }
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool CineExists(int id)
        {
            return _context.Cines.Any(e => e.Id == id);
        }
    }
}