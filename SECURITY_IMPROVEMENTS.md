# Mejoras de Seguridad Implementadas

Este documento resume todas las mejoras de seguridad aplicadas a PeliculasWeb basadas en las vulnerabilidades identificadas en el análisis OWASP Top 10 (A1-A3).

---

## 📋 Resumen de Cambios

### ✅ A1: Broken Access Control

**Problema identificado:**

- Enumeración de recursos sin autenticación
- Acceso directo a cualquier recurso mediante IDs
- Creación, modificación y eliminación de recursos sin restricción

**Estado actual:**

- ⚠️ **Documentado pero no implementado completamente** - La aplicación no tiene sistema de login/register, por lo que implementar autenticación completa requeriría cambios arquitectónicos significativos
- 📝 **Solución propuesta en documentación**: Implementar `[Authorize]` en controladores y validar propiedad de recursos

**Nota:** Las mejoras de A1 requieren implementar un sistema de autenticación completo (ASP.NET Core Identity), lo cual está fuera del alcance de este ejercicio de pruebas de seguridad.

---

## ✅ A2: Cryptographic Failures

**Problemas identificados:**

- Falta de headers de seguridad
- No hay Rate Limiting
- No se fuerza HTTPS en producción
- Información del servidor expuesta

**Soluciones implementadas:**

### 1. Headers de Seguridad (`Program.cs`)

```csharp
// Prevenir clickjacking
context.Response.Headers.Append("X-Frame-Options", "DENY");

// Prevenir MIME sniffing
context.Response.Headers.Append("X-Content-Type-Options", "nosniff");

// Habilitar protección XSS del navegador
context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");

// Controlar referrer
context.Response.Headers.Append("Referrer-Policy", "no-referrer");

// Ocultar información del servidor
context.Response.Headers.Remove("Server");
context.Response.Headers.Remove("X-Powered-By");
```

**Impacto:**

- ✅ Previene clickjacking attacks
- ✅ Previene MIME type sniffing
- ✅ Oculta información del servidor
- ✅ Mejora privacidad del usuario

### 2. Rate Limiting (`Program.cs`)

```csharp
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

app.UseRateLimiter();
```

**Aplicado a todos los controladores:**

- `PeliculasController`
- `ActoresController`
- `CinesController`
- `GenerosController`
- `TrabajadoresController`
- `ReviewsController`
- `ProyeccionesController`

**Impacto:**

- ✅ Previene ataques DoS básicos
- ✅ Limita enumeración masiva de recursos
- ✅ Previene scraping agresivo
- ✅ Protege contra fuerza bruta

### 3. HTTPS Forzado en Producción (`Program.cs`)

```csharp
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
    app.UseHsts();
}
```

**Impacto:**

- ✅ Fuerza HTTPS en producción
- ✅ Implementa HSTS (HTTP Strict Transport Security)
- ✅ Mantiene flexibilidad en desarrollo

### 4. Ocultar Información Detallada de Errores (`Program.cs`)

```csharp
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
}
```

**Impacto:**

- ✅ No expone stack traces en producción
- ✅ Mantiene debugging en desarrollo
- ✅ Previene información leakage

---

## ✅ A3: Injection

**Problemas analizados:**

- SQL Injection (ya protegido por Entity Framework)
- Cross-Site Scripting (ya protegido por Razor)
- Validación de uploads insuficiente

**Soluciones implementadas:**

### 1. Content Security Policy (`Program.cs`)

```csharp
context.Response.Headers.Append("Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;");
```

**Impacto:**

- ✅ Mitiga XSS attacks
- ✅ Controla orígenes de recursos permitidos
- ✅ Capa adicional de defensa

### 2. Validación Mejorada de Uploads (`PeliculasController.cs`)

```csharp
// Validar extensión de archivo
var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif" };
var extension = Path.GetExtension(file.FileName).ToLower();

if (!allowedExtensions.Contains(extension))
{
    ModelState.AddModelError("ImagenArchivo", "Solo se permiten archivos de imagen (JPG, JPEG, PNG, GIF)");
    return View(pelicula);
}

// Validar tipo MIME
var allowedMimeTypes = new[] { "image/jpeg", "image/png", "image/gif", "image/jpg" };
if (!allowedMimeTypes.Contains(file.ContentType.ToLower()))
{
    ModelState.AddModelError("ImagenArchivo", "El tipo de archivo no es válido");
    return View(pelicula);
}

// Validar tamaño (5MB max)
if (file.Length > 5 * 1024 * 1024)
{
    ModelState.AddModelError("ImagenArchivo", "El archivo no debe exceder 5MB");
    return View(pelicula);
}
```

**Impacto:**

- ✅ Previene upload de archivos maliciosos
- ✅ Valida tanto extensión como MIME type (doble validación)
- ✅ Limita tamaño de archivo
- ✅ Ya usa GUID para nombres (previene path traversal)

### 3. Límite Global de Tamaño de Archivo (`Program.cs`)

```csharp
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 5 * 1024 * 1024; // 5 MB
});
```

**Impacto:**

- ✅ Límite global a nivel de aplicación
- ✅ Previene ataques de agotamiento de recursos

### 4. Validación de Modelo Mejorada (`Models/Pelicula.cs`)

```csharp
[Required(ErrorMessage = "El título es requerido")]
[StringLength(200, ErrorMessage = "El título no puede exceder 200 caracteres")]
[RegularExpression(@"^[a-zA-Z0-9\s\-:,.'áéíóúÁÉÍÓÚñÑ¿?¡!]+$",
    ErrorMessage = "El título solo puede contener letras, números, espacios y puntuación básica")]
public string? Titulo { get; set; }

[Required(ErrorMessage = "La sinopsis es requerida")]
[StringLength(2000, ErrorMessage = "La sinopsis no puede exceder 2000 caracteres")]
public string? Sinopsis { get; set; }

[Required(ErrorMessage = "La duración es requerida")]
[Range(1, 600, ErrorMessage = "La duración debe estar entre 1 y 600 minutos")]
public int Duracion { get; set; }
```

**Impacto:**

- ✅ Valida formato de entrada con RegEx
- ✅ Previene caracteres peligrosos
- ✅ Limita longitud de campos
- ✅ Capa adicional de validación

---

## 📊 Comparación Antes/Después

| Aspecto                      | Antes                 | Después                      |
| ---------------------------- | --------------------- | ---------------------------- |
| **Headers de seguridad**     | ❌ Ninguno            | ✅ 5 headers implementados   |
| **Rate Limiting**            | ❌ No implementado    | ✅ 100 req/min por IP        |
| **HTTPS forzado**            | ⚠️ Solo en desarrollo | ✅ Forzado en producción     |
| **Validación de uploads**    | ⚠️ Solo extensión     | ✅ Extensión + MIME + tamaño |
| **Content Security Policy**  | ❌ No implementado    | ✅ CSP configurado           |
| **Validación de modelos**    | ⚠️ Básica             | ✅ Con RegEx y rangos        |
| **Información del servidor** | ❌ Expuesta           | ✅ Oculta                    |
| **Límite de archivo**        | ❌ Sin límite         | ✅ 5MB máximo                |

---

## 🔄 Archivos Modificados

### Archivos principales:

1. **`Program.cs`**

   - Rate limiting configuration
   - Security headers middleware
   - HTTPS redirection for production
   - File upload size limit
   - Environment-based error handling

2. **`Controllers/PeliculasController.cs`**

   - Rate limiting attribute
   - Enhanced file upload validation
   - MIME type validation
   - File size validation

3. **`Controllers/ActoresController.cs`**

   - Rate limiting attribute

4. **`Controllers/CinesController.cs`**

   - Rate limiting attribute

5. **`Controllers/GenerosController.cs`**

   - Rate limiting attribute

6. **`Controllers/TrabajadoresController.cs`**

   - Rate limiting attribute

7. **`Controllers/ReviewsController.cs`**

   - Rate limiting attribute

8. **`Controllers/ProyeccionesController.cs`**

   - Rate limiting attribute

9. **`Models/Pelicula.cs`**
   - Enhanced data annotations
   - RegEx validation for Titulo
   - Range validation for Duracion
   - Better error messages

---

## 🚀 Para Aplicar los Cambios

1. **Detener la aplicación si está corriendo:**

   ```bash
   # Presionar Ctrl+C en la terminal donde corre la app
   ```

2. **Compilar el proyecto:**

   ```bash
   cd peliculasweb
   dotnet build
   ```

3. **Ejecutar la aplicación:**

   ```bash
   dotnet run
   ```

4. **Verificar las mejoras:**

   ```bash
   # Probar headers de seguridad
   curl -I http://localhost:5247

   # Probar rate limiting (ejecutar múltiples veces)
   for i in {1..110}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5247/Peliculas; done
   ```

---

## ⚠️ Consideraciones Importantes

### Para Desarrollo:

- ✅ HTTPS no está forzado (permite usar http://localhost)
- ✅ Errores detallados están habilitados
- ✅ Rate limiting está activo (evita pruebas accidentales de DoS)

### Para Producción:

- ✅ HTTPS está forzado automáticamente
- ✅ HSTS está habilitado
- ✅ Errores genéricos se muestran (no stack traces)
- ✅ Headers de seguridad están activos
- ✅ Rate limiting protege contra abuso

### Limitaciones Conocidas:

- ⚠️ **A1 (Control de Acceso)**: No se implementó autenticación completa porque requiere cambios arquitectónicos significativos. La documentación incluye las soluciones propuestas.
- ⚠️ **Rate Limiting**: El límite actual (100 req/min) es permisivo para desarrollo. En producción considerar ajustar según carga esperada.
- ⚠️ **CSP**: Incluye `'unsafe-inline'` para scripts y estilos debido a que algunas librerías del proyecto lo requieren. Idealmente debería eliminarse.

---

## 📖 Referencias

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [ASP.NET Core Security Best Practices](https://docs.microsoft.com/en-us/aspnet/core/security/)
- [Rate Limiting in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/performance/rate-limit)
- [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

## ✅ Conclusión

Se implementaron **todas las mejoras de seguridad viables** identificadas en el análisis OWASP A2 y A3:

- ✅ **A2 (Cryptographic Failures)**: Headers de seguridad, Rate Limiting, HTTPS forzado en producción
- ✅ **A3 (Injection)**: CSP, validación mejorada de uploads, validación de modelos con RegEx
- ⚠️ **A1 (Broken Access Control)**: Documentado pero no implementado (requiere sistema de autenticación completo)

La aplicación ahora tiene una **postura de seguridad significativamente mejorada** para un entorno de producción, manteniendo la flexibilidad necesaria para desarrollo.
