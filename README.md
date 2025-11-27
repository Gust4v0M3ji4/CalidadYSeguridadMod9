# 🐳 Películas Web - Docker Setup

Sistema de gestión cinematográfica construido con ASP.NET Core 8.0 y SQL Server 2022, completamente containerizado con Docker.

---

## 📋 Requisitos Previos

- **Docker Desktop** instalado y corriendo
  - Windows/Mac: https://www.docker.com/products/docker-desktop
  - Linux: `sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin`

**Verificar instalación:**

```bash
docker --version
docker-compose --version
```

---

## 🚀 Inicio Rápido (3 Pasos)

### 1️⃣ Clonar o descargar el proyecto

```bash
git clone [tu-repo]
cd peliculasweb
```

### 2️⃣ Iniciar la aplicación

```bash
docker-compose up -d
```

### 3️⃣ Acceder a la aplicación

Abre tu navegador en: **http://localhost:8080**

¡Eso es todo! 🎉

---

## 📦 ¿Qué Incluye?

| Servicio     | Descripción               | Puerto |
| ------------ | ------------------------- | ------ |
| **Web App**  | ASP.NET Core 8.0 MVC      | 8080   |
| **Database** | SQL Server 2022 Developer | 1433   |

### Características Automáticas

- ✅ Base de datos se crea automáticamente
- ✅ Migraciones se aplican al iniciar
- ✅ Datos persisten entre reinicios
- ✅ Imágenes subidas se guardan en volumen
- ✅ Healthcheck de base de datos

---

## 🎮 Comandos Principales

### Iniciar

```bash
docker-compose up -d
```

- `-d` = modo detached (en segundo plano)

### Ver logs

```bash
# Todos los servicios
docker-compose logs -f

# Solo la aplicación
docker-compose logs -f web

# Solo la base de datos
docker-compose logs -f db
```

### Ver estado

```bash
docker-compose ps
```

### Detener

```bash
docker-compose stop
```

### Reiniciar

```bash
docker-compose restart
```

### Detener y eliminar contenedores

```bash
docker-compose down
```

### Eliminar TODO (contenedores + datos)

```bash
docker-compose down -v
```

⚠️ **Advertencia:** Esto elimina la base de datos

---

## 🔧 Configuración

### Cambiar Puerto de la Aplicación

Edita `docker-compose.yml`:

```yaml
ports:
  - "8081:80" # Cambia 8080 por 8081
```

### Cambiar Contraseña de Base de Datos

Edita `docker-compose.yml` en ambos lugares:

```yaml
# En el servicio db
MSSQL_SA_PASSWORD=TuNuevaContraseña123!

# En el servicio web
ConnectionStrings__DefaultConnection=Server=db;...;Password=TuNuevaContraseña123!;...
```

---

## 🗄️ Acceso a Base de Datos

### Desde el Host (tu máquina)

```
Server: localhost,1433
Database: peliculasweb
User: sa
Password: YourStrong@Passw0rd
```

### Conexión con SQL Server Management Studio (SSMS)

1. Abre SSMS
2. Server name: `localhost,1433`
3. Authentication: SQL Server Authentication
4. Login: `sa`
5. Password: `YourStrong@Passw0rd`

### Conexión con Azure Data Studio

1. New Connection
2. Server: `localhost,1433`
3. Auth type: SQL Login
4. User: `sa`
5. Password: `YourStrong@Passw0rd`

---

## 🐛 Solución de Problemas

### La aplicación no inicia

```bash
# Ver logs para identificar el error
docker-compose logs web

# Reconstruir la imagen
docker-compose up -d --build
```

### Base de datos no conecta

```bash
# Verificar que SQL Server esté healthy
docker-compose ps

# Ver logs de SQL Server
docker-compose logs db

# Esperar 30-60 segundos para que SQL Server esté listo
```

### Puerto 8080 en uso

```bash
# Cambiar el puerto en docker-compose.yml
# O detener el proceso que usa el puerto
```

### "Cannot open database"

```bash
# Esperar más tiempo para que SQL Server termine de iniciar
# Ver logs: docker-compose logs -f db
# Buscar: "SQL Server is now ready for client connections"
```

### Empezar de cero

```bash
# Eliminar todo y reiniciar
docker-compose down -v
docker-compose up -d
```

---

## 📁 Estructura del Proyecto

```
peliculasweb/
├── Dockerfile              # Construcción de la imagen de la app
├── docker-compose.yml      # Orquestación de servicios
├── .dockerignore          # Archivos a ignorar en build
├── peliculasweb/          # Código fuente de la aplicación
│   ├── Controllers/
│   ├── Models/
│   ├── Views/
│   └── ...
└── README.md              # Este archivo
```

---

## 🔄 Workflow de Desarrollo

### Desarrollo Local (sin Docker)

```bash
cd peliculasweb
dotnet run
# http://localhost:5247
```

### Testing con Docker

```bash
docker-compose up -d
# http://localhost:8080
```

### Hacer cambios y probar

```bash
# 1. Editar código
# 2. Reconstruir
docker-compose up -d --build
```

---

## 🚢 Deployment

### Construcción para Producción

```bash
# Build de la imagen
docker build -t peliculasweb:latest .

# Tag para registry
docker tag peliculasweb:latest myregistry.azurecr.io/peliculasweb:latest

# Push a registry
docker push myregistry.azurecr.io/peliculasweb:latest
```

### Variables de Entorno para Producción

Edita `docker-compose.yml`:

```yaml
environment:
  - ASPNETCORE_ENVIRONMENT=Production
  - ConnectionStrings__DefaultConnection=[tu-connection-string-seguro]
```

---

## 📊 Monitoreo

### Ver recursos utilizados

```bash
docker stats
```

### Ver espacio usado

```bash
docker system df
```

### Limpiar recursos no usados

```bash
docker system prune -a
```

---

## 🆘 Comandos de Emergencia

```bash
# Ver todos los contenedores (incluidos detenidos)
docker ps -a

# Detener TODOS los contenedores
docker stop $(docker ps -q)

# Eliminar TODOS los contenedores
docker rm $(docker ps -aq)

# Eliminar TODAS las imágenes
docker rmi $(docker images -q)

# Limpiar TODO el sistema Docker
docker system prune -a --volumes
```

---

## ✅ Checklist de Verificación

- [ ] Docker Desktop instalado y corriendo
- [ ] Repositorio clonado/descargado
- [ ] Ejecutado `docker-compose up -d`
- [ ] Esperado 1-2 minutos para que todo inicie
- [ ] Abierto http://localhost:8080 en navegador
- [ ] Aplicación carga correctamente
- [ ] Puedo crear/editar datos
- [ ] Los datos persisten después de `docker-compose restart`

---

## 🎓 Recursos Adicionales

- **Documentación Docker Compose:** https://docs.docker.com/compose/
- **SQL Server en Docker:** https://hub.docker.com/_/microsoft-mssql-server
- **ASP.NET Core en Docker:** https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/docker/

---

## 📝 Notas Importantes

1. **Primera ejecución:** Puede tardar 5-10 minutos en descargar las imágenes de SQL Server (~1.5GB)
2. **Datos persistentes:** Los datos se guardan en volúmenes Docker y persisten entre reinicios
3. **Contraseña:** Cambia la contraseña por defecto antes de producción
4. **Puerto:** Si 8080 está ocupado, cámbialo en `docker-compose.yml`

---

## 👥 Contribuir

Para contribuir al proyecto:

1. Fork el repositorio
2. Crea una rama para tu feature
3. Haz tus cambios
4. Envía un Pull Request

---

## 📄 Licencia

[Tu licencia aquí]

---

## 🙋 Soporte

¿Problemas?

1. Revisa la sección "Solución de Problemas"
2. Verifica logs: `docker-compose logs -f`
3. Abre un issue en el repositorio

---

**¡Disfruta de tu aplicación dockerizada!** 🎬🐳
