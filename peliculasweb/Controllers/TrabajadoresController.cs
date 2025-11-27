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
    public class TrabajadoresController : Controller
    {
        private readonly AppDbContext _context;

        public TrabajadoresController(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Index()
        {
            return View(await _context.Trabajadores.ToListAsync());
        }

        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
                return NotFound();

            var trabajador = await _context.Trabajadores.FirstOrDefaultAsync(m => m.Id == id);
            if (trabajador == null)
                return NotFound();

            return View(trabajador);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Biografia,Rol,Id,Nombre,FechaNacimiento,Nacionalidad,ImagenRuta")] Trabajador trabajador)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    var files = HttpContext.Request.Form.Files;
                    if (files.Count > 0)
                    {
                        var file = files[0];
                        var directoryPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/imagenes/trabajadores");
                        if (!Directory.Exists(directoryPath))
                            Directory.CreateDirectory(directoryPath);

                        var fileName = Guid.NewGuid() + Path.GetExtension(file.FileName);
                        var filePath = Path.Combine(directoryPath, fileName);

                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            await file.CopyToAsync(stream);
                        }
                        trabajador.ImagenRuta = "/imagenes/trabajadores/" + fileName;
                    }

                    _context.Add(trabajador);
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", "Error al guardar la imagen: " + ex.Message);
                }
            }
            return View(trabajador);
        }

        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
                return NotFound();

            var trabajador = await _context.Trabajadores.FindAsync(id);
            if (trabajador == null)
                return NotFound();

            return View(trabajador);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Biografia,Rol,Id,Nombre,FechaNacimiento,Nacionalidad,ImagenRuta")] Trabajador trabajador)
        {
            if (id != trabajador.Id)
                return NotFound();

            if (ModelState.IsValid)
            {
                try
                {
                    var trabajadorOriginal = await _context.Trabajadores.AsNoTracking().FirstOrDefaultAsync(t => t.Id == id);
                    string? imagenAnterior = trabajadorOriginal?.ImagenRuta;

                    var files = HttpContext.Request.Form.Files;
                    if (files.Count > 0)
                    {
                        var file = files[0];
                        var directoryPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot/imagenes/trabajadores");
                        if (!Directory.Exists(directoryPath))
                            Directory.CreateDirectory(directoryPath);

                        var fileName = Guid.NewGuid() + Path.GetExtension(file.FileName);
                        var filePath = Path.Combine(directoryPath, fileName);

                        using (var stream = new FileStream(filePath, FileMode.Create))
                        {
                            await file.CopyToAsync(stream);
                        }
                        trabajador.ImagenRuta = "/imagenes/trabajadores/" + fileName;

                        // Eliminar imagen anterior
                        if (!string.IsNullOrEmpty(imagenAnterior))
                        {
                            var rutaAnterior = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", imagenAnterior.TrimStart('/'));
                            if (System.IO.File.Exists(rutaAnterior))
                                System.IO.File.Delete(rutaAnterior);
                        }
                    }

                    _context.Update(trabajador);
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", "Error al guardar la imagen: " + ex.Message);
                }
            }
            return View(trabajador);
        }

        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
                return NotFound();

            var trabajador = await _context.Trabajadores.FirstOrDefaultAsync(m => m.Id == id);
            if (trabajador == null)
                return NotFound();

            return View(trabajador);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var trabajador = await _context.Trabajadores.FindAsync(id);
            if (trabajador != null)
            {
                if (!string.IsNullOrEmpty(trabajador.ImagenRuta))
                {
                    var rutaCompleta = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", trabajador.ImagenRuta.TrimStart('/'));
                    if (System.IO.File.Exists(rutaCompleta))
                        System.IO.File.Delete(rutaCompleta);
                }
                _context.Trabajadores.Remove(trabajador);
            }
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool TrabajadorExists(int id)
        {
            return _context.Trabajadores.Any(e => e.Id == id);
        }
    }
}