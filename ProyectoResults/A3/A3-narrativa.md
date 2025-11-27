# A3:2021 - Injection (Inyección)

## 🎯 ¿Qué probar?

Verificar si la app valida correctamente las entradas del usuario y previene inyección de código malicioso.

---

## ✅ Prueba 1: SQL Injection en parámetro de búsqueda

### 📡 Request básico de búsqueda

```bash
curl -i "http://localhost:5247/Peliculas?searchString=Peli1"
```

**¿Qué devuelve?**

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
...

<!DOCTYPE html>
<html>
...
[HTML con la lista de películas que contienen "matrix"]
```

**Análisis:**

- ✅ Request normal funciona correctamente
- La búsqueda usa LIKE en SQL: `WHERE Titulo LIKE '%matrix%'`

---

### 📡 Probar con comilla simple (SQLi básico)

```bash
curl -i "http://localhost:5247/Peliculas?searchString=test'"
```

**¿Qué devuelve?**

- ✅ Si devuelve 200 con HTML normal → **PROTEGIDO** (Entity Framework parametriza)
- ❌ Si devuelve error SQL → **VULNERABLE**

**Ejemplo de error vulnerable:**

```
HTTP/1.1 500 Internal Server Error

System.Data.SqlClient.SqlException: Incorrect syntax near 'test''.
Unclosed quotation mark after the character string ''.
```

**Análisis:**

- ✅ **En esta app**: Entity Framework usa consultas parametrizadas por defecto
- ✅ El código del controlador: `p.Titulo.Contains(searchString)` se traduce a parámetros seguros
- 🟢 **Resultado**: NO vulnerable a SQLi en búsqueda

---

### 📡 Payloads clásicos de SQL Injection

Para verificar sin revisar todo el HTML, vamos a usar comandos más directos que nos muestren solo lo relevante.

**1. Comparar búsqueda normal vs SQL injection (contar resultados):**

```bash
# Búsqueda normal (debería dar 0 si no existe)
curl -s -G --data-urlencode "searchString=ZZZZZZZ" "http://localhost:5247/Peliculas" | grep -c "card-title"

# Con SQL injection (si es vulnerable, devolverá TODAS las películas)
curl -s -G --data-urlencode "searchString=' OR '1'='1" "http://localhost:5247/Peliculas" | grep -c "card-title"
```

Si ambos dan 0 → **PROTEGIDO** (Entity Framework parametriza correctamente)  
Si el segundo da más resultados → **VULNERABLE**

**2. Buscar errores SQL en la respuesta:**

```bash
# Probar con comilla simple y buscar mensajes de error
curl -s -G --data-urlencode "searchString='" "http://localhost:5247/Peliculas" | grep -iE "sql|error|exception|database"
```

Si no devuelve nada → **PROTEGIDO**  
Si muestra errores SQL → **VULNERABLE**

**3. Time-based SQLi (verificar tiempo de respuesta):**

```bash
# Ver tiempo de respuesta normal
curl -s -o /dev/null -w "HTTP: %{http_code} | Tiempo: %{time_total}s\n" -G --data-urlencode "searchString=Matrix" "http://localhost:5247/Peliculas"

# Con payload de delay
curl -s -o /dev/null -w "HTTP: %{http_code} | Tiempo: %{time_total}s\n" -G --data-urlencode "searchString=' AND WAITFOR DELAY '00:00:05'--" "http://localhost:5247/Peliculas"
```

Si el segundo tarda 5+ segundos más → **VULNERABLE**  
Si tarda lo mismo → **PROTEGIDO**

**4. Otros payloads clásicos:**

```bash
# UNION SELECT
curl -s -G --data-urlencode "searchString=' UNION SELECT NULL,NULL,NULL--" "http://localhost:5247/Peliculas" | grep -c "card-title"

# Comentar query
curl -s -G --data-urlencode "searchString=' OR 1=1--" "http://localhost:5247/Peliculas" | grep -c "card-title"

# Stacked queries
curl -s -G --data-urlencode "searchString='; DROP TABLE Peliculas--" "http://localhost:5247/Peliculas" | grep -iE "sql|error"
```

**Análisis:**

- ✅ **En esta app**: Entity Framework usa consultas parametrizadas por defecto
- ✅ El código del controlador: `p.Titulo.Contains(searchString)` se traduce a parámetros seguros
- 🟢 **Resultado esperado**: NO vulnerable a SQLi en búsqueda

---

### 📡 SQLi en parámetros de ID (tipo entero)

```bash
# 1. ID normal
curl -i "http://localhost:5247/Peliculas/Details/1"

# 2. ID con inyección SQL
curl -i "http://localhost:5247/Peliculas/Details/1' OR '1'='1"

# 3. ID con UNION
curl -i "http://localhost:5247/Peliculas/Details/1 UNION SELECT NULL,NULL,NULL"

# 4. ID con stacked query
curl -i "http://localhost:5247/Peliculas/Details/1;DROP TABLE Peliculas--"
```

**Respuesta esperada:**

```
HTTP/1.1 400 Bad Request
Content-Type: text/html

<title>Bad Request</title>
...
The value '1' OR '1'='1' is not valid for Id.
```

**Análisis:**

- ✅ ASP.NET Core valida que el parámetro `int? id` sea realmente un entero
- ✅ Rechaza payloads de SQLi en parámetros tipo `int`
- 🟢 **Resultado**: NO vulnerable a SQLi en IDs

---

## ✅ Prueba 2: Cross-Site Scripting (XSS)

### 📡 XSS Reflejado (Reflected XSS) en búsqueda

```bash
# Payload básico de XSS
curl -i "http://localhost:5247/Peliculas?searchString=<script>alert('XSS')</script>"
```

**¿Qué devuelve?**
Guarda la respuesta para analizarla:

```bash
curl -s "http://localhost:5247/Peliculas?searchString=<script>alert('XSS')</script>" > xss_test.html
```

Abre `xss_test.html` y busca:

```html
<!-- ❌ VULNERABLE: Si ves esto tal cual -->
<h3>
  Resultados para:
  <script>
    alert("XSS");
  </script>
</h3>

<!-- ✅ SEGURO: Si ves esto escapado -->
<h3>Resultados para: &lt;script&gt;alert('XSS')&lt;/script&gt;</h3>
```

**Análisis:**

- ❌ Si el script aparece sin escapar → **VULNERABLE A XSS**
- ✅ Si aparece como `&lt;script&gt;` → **PROTEGIDO** (HTML encoding)

**Verificar manualmente:**
Abre cada archivo HTML en el navegador:

- ❌ Si ejecuta el alert → **VULNERABLE**
- ✅ Si solo muestra el texto → **PROTEGIDO**

---

### 📡 XSS Almacenado (Stored XSS) en formularios

**Paso 1:** Crear una película con payload XSS en el título

```bash
# Obtener token y cookies
TOKEN=$(curl -s -c xss_cookies.txt http://localhost:5247/Peliculas/Create | grep -oP '__RequestVerificationToken.*?value="\K[^"]+')

# Crear película con XSS en el título
curl -X POST http://localhost:5247/Peliculas/Create \
  -b xss_cookies.txt \
  -d "__RequestVerificationToken=$TOKEN" \
  -d "Titulo=<script>alert('XSS Almacenado')</script>" \
  -d "Descripcion=Esta es una prueba de XSS" \
  -d "FechaLanzamiento=2025-11-26" \
  -d "Duracion=90" \
  -d "GeneroId=1" \
  -d "DirectorId=1" \
  -L -s -o stored_xss_result.html
```

**Paso 2:** Verificar si el XSS se ejecuta

```bash
# Ver la lista de películas
curl -s http://localhost:5247/Peliculas > peliculas_list.html
```

Abre `peliculas_list.html` en el navegador:

- ❌ Si aparece un alert → **VULNERABLE A XSS ALMACENADO** (muy grave)
- ✅ Si solo muestra el texto escapado → **PROTEGIDO**

**También revisa el HTML generado:**

```bash
grep "<script>alert" peliculas_list.html
```

## ✅ Prueba 3: Seguridad en upload de archivos

### 📡 Crear un archivo de imagen de prueba

```bash
# Crear una imagen PNG válida (1x1 pixel)
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82' > test.png
```

---

### 📡 Subir el archivo de imagen

```bash
# Subir archivo con todos los campos necesarios
curl -X POST http://localhost:5247/Peliculas/Create -b upload_cookies.txt -F "__RequestVerificationToken=$TOKEN" -F "Titulo=Test Image" -F "Sinopsis=Test" -F "FechaEstreno=2025-01-01" -F "Duracion=120" -F "GeneroId=1" -F "DirectorId=1" -F "ImagenArchivo=@test.png" -L -o response.html
```

**Qué observar:**

- El progreso del upload (% Total, % Received)
- Si completa exitosamente (100% en ambos)

---

### 📡 Verificar que la película se creó con la imagen

```bash
# Buscar la película y la ruta de la imagen
grep -i "test image\|error\|invalid" response.html
```

**Resultado esperado:**

```html
<img src="/imagenes/peliculas/13fc67dd-ef8e-4df7-bf36-a84cf2c09eda.png" class="card-img-top" alt="Imagen de Test Image"
<h5 class="card-title">Test Image</h5>
```

**Análisis:**

- ✅ La imagen se subió exitosamente
- ✅ Se generó un GUID único para el nombre del archivo (previene path traversal)
- ✅ Se guardó en la subcarpeta `/imagenes/peliculas/`

---

### 📡 Ver la estructura de carpetas donde se guardó

```bash
ls -la peliculasweb/wwwroot/imagenes/
```

**Resultado esperado:**

```
drwxr-xr-x 1 ASUS 197121 0 Nov 26 19:44 actores/
drwxr-xr-x 1 ASUS 197121 0 Nov  3 18:16 cines/
drwxr-xr-x 1 ASUS 197121 0 Nov 27 00:52 peliculas/
drwxr-xr-x 1 ASUS 197121 0 Nov  3 18:16 trabajadores/
```

**Análisis:**

- ✅ Carpetas organizadas por tipo de entidad
- ✅ Las imágenes no se guardan en la raíz de `/imagenes/`

---

### 📡 Intentar acceder directamente con el nombre original

```bash
curl -i http://localhost:5247/imagenes/test.png
```

**Resultado esperado:**

```
HTTP/1.1 404 Not Found
```

**Análisis:**

- ✅ **PROTEGIDO**: No se puede acceder usando el nombre original del archivo
- ✅ El servidor renombra los archivos con GUID, lo que previene:
  - Path traversal (`../../../etc/passwd`)
  - Sobrescritura de archivos existentes
  - Nombres maliciosos con caracteres especiales

**Conclusión:** El sistema de upload está bien protegido, usa nombres únicos (GUID) y organiza los archivos en subcarpetas específicas.

---

## 📊 Resumen A3 - Injection

| Prueba             | Comando                               | Resultado Esperado             | Severidad |
| ------------------ | ------------------------------------- | ------------------------------ | --------- |
| SQLi en búsqueda   | `curl "...?searchString=' OR 1=1--"`  | ✅ Protegido (EF parametriza)  | 🟢 N/A    |
| SQLi en ID         | `curl ".../Details/1' OR '1'='1"`     | ✅ Protegido (validación tipo) | 🟢 N/A    |
| XSS reflejado      | `curl "...?searchString=<script>..."` | ⚠️ Verificar encoding          | 🟡/🔴     |
| XSS almacenado     | POST con `<script>` en Título         | ⚠️ Verificar encoding          | 🔴 Alta   |
| XSS en descripción | POST con `<img onerror=...>`          | ⚠️ Verificar encoding          | 🔴 Alta   |

**Conclusión:**

- ✅ **SQLi**: Protegido por Entity Framework
- ⚠️ **XSS**: Depende de cómo Razor renderiza `@Model.Titulo` (por defecto escapa HTML, pero verificar)

---

## 🛠️ Soluciones Recomendadas

### Prevenir XSS en vistas Razor

```html
<!-- Razor escapa automáticamente por defecto -->
@Model.Titulo
<!-- Ya está escapado -->

<!-- Si necesitas HTML raw (¡CUIDADO!) -->
@Html.Raw(Model.Descripcion)
<!-- NO hacer esto con entrada de usuario -->

<!-- Forzar encoding explícito -->
@Html.Encode(Model.Titulo)
```

### Validar y sanitizar entradas

```csharp
[HttpPost]
public async Task<IActionResult> Create(Pelicula pelicula)
{
    // Sanitizar entrada (opcional, Razor ya escapa)
    pelicula.Titulo = System.Net.WebUtility.HtmlEncode(pelicula.Titulo);

    // Validar con Data Annotations
    if (!ModelState.IsValid)
    {
        return View(pelicula);
    }

    await _context.SaveChangesAsync();
    return RedirectToAction(nameof(Index));
}
```

### Data Annotations para validación

```csharp
public class Pelicula
{
    [Required]
    [StringLength(200)]
    [RegularExpression(@"^[a-zA-Z0-9\s\-:]+$", ErrorMessage = "Solo letras, números y espacios")]
    public string Titulo { get; set; }

    [StringLength(2000)]
    public string? Descripcion { get; set; }
}
```

### Content Security Policy (CSP)

```csharp
// En Program.cs
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");
    await next();
});
```

---

## 📸 Capturas para el Informe

1. Screenshot de `curl "http://localhost:5247/Peliculas?searchString=' OR 1=1--"` mostrando que no es vulnerable
2. Screenshot de payload XSS en el navegador (si ejecuta o si escapa)
3. Screenshot del HTML generado mostrando `&lt;script&gt;` escapado
4. Screenshot de película creada con XSS en el título
5. Screenshot del código con validación y sanitización implementada
