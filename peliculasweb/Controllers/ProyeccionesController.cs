using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using peliculasweb.Data;
using peliculasweb.Models;

namespace peliculasweb.Controllers
{
    public class ProyeccionesController : Controller
    {
        private readonly AppDbContext _context;

        public ProyeccionesController(AppDbContext context)
        {
            _context = context;
        }

        // GET: Proyecciones
        public async Task<IActionResult> Index()
        {
            var appDbContext = _context.Proyecciones.Include(p => p.Cine).Include(p => p.Pelicula);
            return View(await appDbContext.ToListAsync());
        }

        // GET: Proyecciones/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var proyeccion = await _context.Proyecciones
                .Include(p => p.Cine)
                .Include(p => p.Pelicula)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (proyeccion == null)
            {
                return NotFound();
            }

            return View(proyeccion);
        }

        // GET: Proyecciones/Create
        public IActionResult Create()
        {
            ViewData["CineId"] = new SelectList(_context.Cines, "Id", "Nombre");
            ViewData["PeliculaId"] = new SelectList(_context.Peliculas, "Id", "Titulo");
            return View();
        }

        // POST: Proyecciones/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,FechaInicio,FechaFin,PeliculaId,CineId")] Proyeccion proyeccion)
        {
            if (ModelState.IsValid)
            {
                _context.Add(proyeccion);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            ViewData["CineId"] = new SelectList(_context.Cines, "Id", "Nombre", proyeccion.CineId);
            ViewData["PeliculaId"] = new SelectList(_context.Peliculas, "Id", "Titulo", proyeccion.PeliculaId);
            return View(proyeccion);
        }

        // GET: Proyecciones/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var proyeccion = await _context.Proyecciones.FindAsync(id);
            if (proyeccion == null)
            {
                return NotFound();
            }
            ViewData["CineId"] = new SelectList(_context.Cines, "Id", "Nombre", proyeccion.CineId);
            ViewData["PeliculaId"] = new SelectList(_context.Peliculas, "Id", "Titulo", proyeccion.PeliculaId);
            return View(proyeccion);
        }

        // POST: Proyecciones/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,FechaInicio,FechaFin,PeliculaId,CineId")] Proyeccion proyeccion)
        {
            if (id != proyeccion.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(proyeccion);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!ProyeccionExists(proyeccion.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            ViewData["CineId"] = new SelectList(_context.Cines, "Id", "Nombre", proyeccion.CineId);
            ViewData["PeliculaId"] = new SelectList(_context.Peliculas, "Id", "Titulo", proyeccion.PeliculaId);
            return View(proyeccion);
        }

        // GET: Proyecciones/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var proyeccion = await _context.Proyecciones
                .Include(p => p.Cine)
                .Include(p => p.Pelicula)
                .FirstOrDefaultAsync(m => m.Id == id);
            if (proyeccion == null)
            {
                return NotFound();
            }

            return View(proyeccion);
        }

        // POST: Proyecciones/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var proyeccion = await _context.Proyecciones.FindAsync(id);
            if (proyeccion != null)
            {
                _context.Proyecciones.Remove(proyeccion);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool ProyeccionExists(int id)
        {
            return _context.Proyecciones.Any(e => e.Id == id);
        }
    }
}
