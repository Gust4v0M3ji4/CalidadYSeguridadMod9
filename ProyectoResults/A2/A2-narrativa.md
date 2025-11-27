# A2 - Cryptographic Failures (Fallos Criptográficos)

---

## 📝 Guía práctica para evaluar Cryptographic Failures

En esta sección vamos a probar cómo la aplicación maneja datos sensibles, configuraciones de seguridad y exposición de información. Aunque la app no tiene login ni registro (lo que limita algunas pruebas), igual hay varios puntos que podemos revisar para ver si está bien protegida o si filtra información que no debería.

### ¿Qué podemos probar sin login?

1. **Uso de HTTPS**: Verificar si usa cifrado en las comunicaciones (aunque en desarrollo use HTTP)
2. **Headers de seguridad**: Ver si el servidor envía headers que protegen contra ataques comunes
3. **Exposición de datos sensibles**: Buscar contraseñas, tokens, connection strings en el HTML
4. **Archivos sensibles**: Intentar acceder a archivos de configuración que deberían estar protegidos
5. **Rate Limiting**: Probar si hay límites de peticiones al servidor

Vamos a intentar todas estas pruebas y ver qué encontramos.

---

## ✅ Prueba 1: Verificar uso de HTTPS vs HTTP

### 📡 Inspeccionar headers del servidor

```bash
curl -I http://localhost:5247
```

**Respuesta esperada:**

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Date: Tue, 26 Nov 2025 10:30:00 GMT
Server: Kestrel
```

**Análisis:**

- ⚠️ **En desarrollo**: Usar HTTP es normal (localhost)
- 🔴 **En producción**: DEBE usar HTTPS (datos cifrados en tránsito)
- 🔴 **Impacto sin HTTPS**: Contraseñas, cookies, tokens interceptables (Man-in-the-Middle)

---

### 📡 Verificar headers de seguridad

```bash
curl -I http://localhost:5247 | grep -i "strict-transport\|x-frame\|x-content\|x-xss"
```

**Headers de seguridad recomendados:**

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

**Análisis:**

- ❌ Si NO tiene estos headers → **Vulnerable a clickjacking, MIME sniffing, etc.**
- ✅ Si los tiene → **Mejor postura de seguridad**

---

## ✅ Prueba 2: Exposición de datos sensibles en el HTML

Ya que esta app no tiene login ni maneja contraseñas de usuarios, lo que vamos a hacer es revisar manualmente el código fuente HTML de las páginas para ver si hay algo raro. En lugar de usar comandos grep (que no siempre funcionan bien), vamos a descargar el HTML y revisarlo directamente.

### 📡 Descargar el HTML y revisarlo manualmente

```bash
# Descargar la página principal
curl -s http://localhost:5247 > pagina_principal.html

# Descargar la página de películas
curl -s http://localhost:5247/Peliculas > peliculas.html
```

**¿Qué buscar al abrir estos archivos?**

- ❌ Connection strings en comentarios: `<!-- Server=localhost;Database=... -->`
- ❌ Tokens CSRF visibles pero mal implementados
- ❌ Información de configuración o rutas del servidor
- ❌ Comentarios de desarrolladores con TODOs o información técnica
- ✅ Solo HTML limpio sin información sensible

**Análisis:**

En una app .NET MVC bien configurada, no debería haber datos sensibles en el HTML. Abre los archivos descargados en un editor de texto y revisa visualmente si ves algo sospechoso. También puedes buscar (Ctrl+F) palabras como "password", "secret", "connection", "server=", etc.

Si no encuentras nada raro, significa que la app está bien configurada en este aspecto.

---

## ✅ Prueba 3: Búsqueda de archivos sensibles expuestos

### 📡 Intentar acceder a archivos de configuración

```bash
# appsettings.json (NO debe ser público)
curl -i http://localhost:5247/appsettings.json

# appsettings.Development.json
curl -i http://localhost:5247/appsettings.Development.json

# web.config (IIS)
curl -i http://localhost:5247/web.config

# .env (variables de entorno)
curl -i http://localhost:5247/.env

# Backup de BD
curl -i http://localhost:5247/backup.sql
```

**Respuesta esperada:**

```
HTTP/1.1 404 Not Found
```

**Análisis:**

- ❌ **VULNERABLE**: Si devuelve 200 y el contenido del archivo (expone connection strings, secrets)
- ✅ **SEGURO**: Si devuelve 404 (archivos no accesibles públicamente)

---

### 📡 Path Traversal para acceder a archivos del sistema

```bash
# Intentar leer archivos fuera del webroot
curl -i "http://localhost:5247/../../../../etc/passwd"
curl -i "http://localhost:5247/..\..\..\..\Windows\System32\drivers\etc\hosts"

# Con encoding
curl -i "http://localhost:5247/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

**Respuesta esperada:**

```
HTTP/1.1 400 Bad Request
```

**Análisis:**

- ❌ **VULNERABLE**: Si devuelve el contenido de archivos del sistema
- ✅ **SEGURO**: Si rechaza la petición (ASP.NET Core valida rutas por defecto)

---

## ✅ Prueba 4: Rate Limiting y DoS básico

Aunque no tengamos login, podemos probar si la app tiene protección contra ataques de fuerza bruta o denegación de servicio (DoS). Esto se hace enviando muchas peticiones rápidas y viendo si el servidor las acepta todas o empieza a rechazarlas.

### 📡 Enviar múltiples requests rápidos

```bash
# Enviar 50 requests simultáneos
for i in {1..50}; do
  curl -s -o /dev/null -w "Request $i: %{http_code}\n" http://localhost:5247/Peliculas &
done
wait
```

**¿Qué esperamos?**

- ❌ **Sin protección**: Todos devuelven 200 OK
- ✅ **Con Rate Limiting**: Después de cierto número, devuelve 429 (Too Many Requests)

**Análisis:**

Si todos los requests pasan sin problema, la app no tiene rate limiting. Esto podría permitir:

- Scraping masivo de datos
- DoS (saturar el servidor)
- Enumeración rápida de recursos

Nota: Como no hay login, no podemos probar fuerza bruta de contraseñas, pero igual es útil ver si hay algún límite de peticiones.

---

## 📊 Resumen A2 - Cryptographic Failures

| Prueba                  | Comando                      | Resultado esperado          | Severidad  |
| ----------------------- | ---------------------------- | --------------------------- | ---------- |
| Uso de HTTPS            | `curl -I http://...`         | ⚠️ HTTP en dev              | 🔴 En prod |
| Headers de seguridad    | `curl -I \| grep...`         | Por verificar               | 🟡 Media   |
| Datos sensibles en HTML | Revisar archivos descargados | Verificar si hay filtración | 🟡/🔴      |
| Archivos sensibles      | `curl .../appsettings.json`  | Debe dar 404                | 🔴 Alta    |
| Rate limiting           | Loop con curl                | Por probar                  | 🟡 Media   |

**Conclusión:** Las pruebas se centran en verificar la configuración de seguridad básica. Aunque no haya login, hay varios aspectos que pueden estar mal configurados y exponer información sensible o hacer la app vulnerable.

---

## 🛠️ Soluciones Recomendadas

### Forzar HTTPS en producción

```csharp
// En Program.cs
if (!app.Environment.IsDevelopment())
{
    app.UseHttpsRedirection();
    app.UseHsts();
}
```

### Agregar headers de seguridad

```csharp
// En Program.cs
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Add("Referrer-Policy", "no-referrer");
    await next();
});
```

### Configurar cookies seguras

```csharp
// En Program.cs
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
});
```

### Ocultar errores en producción

```csharp
// En Program.cs
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    // No mostrar stack traces
}
```

---

## 💡 Consideraciones especiales

**Limitaciones de las pruebas:**

- Como no hay sistema de login/register, no podemos probar cifrado de contraseñas, gestión de sesiones de usuario, o tokens de autenticación
- Sin embargo, podemos verificar la configuración general de seguridad que debería estar presente independientemente de si hay login o no

**Lo que SÍ podemos verificar:**

- Configuración de HTTPS y redirección (en producción)
- Headers de seguridad del servidor
- Exposición de datos sensibles en el HTML
- Protección de archivos de configuración
- Límites de peticiones al servidor

**Enfoque práctico:**
Vamos a ejecutar cada prueba, documentar qué encontramos, y analizar si representa un riesgo real. Si algo no aplica o no se puede probar por las limitaciones de la app, lo indicaremos claramente.
