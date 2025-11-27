# PeliculasWeb - Evaluación de Seguridad OWASP

#

## 📚 Laboratorios y Resultados

- [A1: Narrativa del laboratorio](ProyectoResults/A1/A1-narrativa.md)
- [A1: Resultados y evidencias](ProyectoResults/A1/resultados.md)

Este proyecto es una aplicación de ejemplo ASP.NET Core (+ SQL Server) **evaluada y mejorada desde una perspectiva de seguridad web**, siguiendo el Top Ten OWASP (A1-A3) para laboratorios universitarios.

Porfavor para revisar la documentacion de cada proceso con imagenes revisar la carpeta ProyectoResults y cada una de sus problematicas ahi hay una narrativa como problema y su solucion aplicada.

---

## 🔒 Enfoque de Seguridad

El objetivo principal es **identificar y corregir vulnerabilidades** reales que puedan existir en la aplicación, documentando el proceso para cada una de las tres primeras categorías del OWASP Top Ten 2021:

- **A1: Broken Access Control** (Control de Acceso Roto)
- **A2: Cryptographic Failures** (Fallos Criptográficos)
- **A3: Injection** (Inyección: SQLi, XSS)

### ¿Qué incluye este laboratorio?

- **Explicación de cada riesgo** (qué es, cómo se explota)
- **Pruebas de explotación** usando herramientas externas:
  - `curl`/Postman para requests manuales y automatizados
  - Burp Suite Community / OWASP ZAP para ataques automáticos/web
  - Inspección de headers y cookies desde el navegador y línea de comandos
- **Evidencias**: Resultados, capturas de pantalla o fragmentos de respuesta
- **Corrección**: Código actualizado que previene la vulnerabilidad detectada
- **Reevaluación**: Demostración de que quedó mitigado el problema

---

## ⚡ ¿Cómo hacer las pruebas?

1. **Clona el repositorio y ejecuta la app**  
   Puedes ejecutarla localmente con .NET o usando Docker si prefieres (opcional).

   - Ejemplo rápido:
     ```
     dotnet run --project peliculasweb
     # Accede a http://localhost:5247
     ```

2. **Usa las herramientas sugeridas para atacar la app**

   - Revisa los archivos de pruebas en la carpeta `/owasp/` o `/lab/`:
     - Ejemplos de comandos cURL
     - Scripts de enumeración de recursos
     - Payloads de SQL Injection y XSS
   - Analiza la respuesta. Si encuentras problemas, documéntalo.

3. **Corrige el código donde aplique**

   - Implementa autenticación/roles, validación de entradas, uso de HTTPS, headers de seguridad, sanitización, etc.
   - Deja comentarios o commits referenciando la vulnerabilidad corregida.

4. **Verifica que la corrección sea efectiva**
   - Vuelve a realizar la prueba. Si el riesgo desapareció, ¡éxito!
   - Documenta la respuesta/toma capturas.

---

## 🧩 Contenido clave del repositorio

- `/README.md` → Esta guía.
- `/owasp/` o `/lab/` → Encuentra laboratorios, instrucciones paso a paso y correcciones.
- `/peliculasweb/` → Código fuente ASP.NET Core.
- (Opcional) `/capturas/` → Imágenes de pruebas o resultados.

---

## 🛠️ Herramientas recomendadas

- **Línea de comandos:** curl, grep, bash loops
- **Testing API:** Postman
- **Escaneo Web:** Burp Suite Community, OWASP ZAP
- **Análisis de código:** SonarQube, dotnet analyzers
- **Navegador:** Para inspeccionar tráfico, cookies y recursos
