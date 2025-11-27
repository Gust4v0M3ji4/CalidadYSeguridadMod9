# Etapa 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copiar archivo de proyecto y restaurar dependencias
COPY ["peliculasweb/peliculasweb.csproj", "peliculasweb/"]
RUN dotnet restore "peliculasweb/peliculasweb.csproj"

# Copiar todo el código fuente
COPY . .
WORKDIR "/src/peliculasweb"
RUN dotnet build "peliculasweb.csproj" -c Release -o /app/build

# Etapa 2: Publish
FROM build AS publish
RUN dotnet publish "peliculasweb.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Etapa 3: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
EXPOSE 80
EXPOSE 443

# Copiar los archivos publicados
COPY --from=publish /app/publish .

# Crear carpetas para imágenes
RUN mkdir -p /app/wwwroot/imagenes/actores && \
    mkdir -p /app/wwwroot/imagenes/cines && \
    mkdir -p /app/wwwroot/imagenes/peliculas && \
    mkdir -p /app/wwwroot/imagenes/trabajadores

ENTRYPOINT ["dotnet", "peliculasweb.dll"]
