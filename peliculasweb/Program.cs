using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http.Features;
using peliculasweb.Data; // <-- Asegúrate que el namespace coincida

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// A2: Implementar Rate Limiting para prevenir DoS y enumeración rápida
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("fixed", opt =>
    {
        opt.PermitLimit = 100;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = 0;
    });
});

// Configurar límite de tamaño de archivos para uploads (A3)
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 5 * 1024 * 1024; // 5 MB
});

var app = builder.Build();

// Aplicar migraciones automáticamente en Docker
if (app.Environment.IsDevelopment())
{
    using (var scope = app.Services.CreateScope())
    {
        var services = scope.ServiceProvider;
        try
        {
            var context = services.GetRequiredService<AppDbContext>();
            // Aplica migraciones pendientes automáticamente
            context.Database.Migrate();
            Console.WriteLine("✅ Migraciones aplicadas correctamente");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error aplicando migraciones: {ex.Message}");
        }
    }
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // A2: Forzar HTTPS en producción
    app.UseHsts();
}
else
{
    // En desarrollo, mostrar página de excepción detallada
    app.UseDeveloperExceptionPage();
}

// LOG FATAL ERRORS TO FILE!
AppDomain.CurrentDomain.UnhandledException += (sender, eventArgs) =>
{
    File.WriteAllText("fatal_error.log", eventArgs.ExceptionObject?.ToString() ?? "Unknown fatal error");
};

// A2: Forzar HTTPS (solo en producción para no romper desarrollo local)
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
}

// A2: Agregar headers de seguridad
app.Use(async (context, next) =>
{
    // Prevenir clickjacking
    context.Response.Headers.Append("X-Frame-Options", "DENY");

    // Prevenir MIME sniffing
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");

    // Habilitar protección XSS del navegador
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");

    // Controlar referrer
    context.Response.Headers.Append("Referrer-Policy", "no-referrer");

    // A3: Content Security Policy para mitigar XSS
    context.Response.Headers.Append("Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");

    // Ocultar información del servidor
    context.Response.Headers.Remove("Server");
    context.Response.Headers.Remove("X-Powered-By");

    await next();
});// A2: Aplicar Rate Limiting
app.UseRateLimiter();

app.UseStaticFiles();
app.UseRouting();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();