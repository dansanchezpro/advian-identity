# Docker Deployment Guide

Este documento describe cómo desplegar el Identity Server usando Docker.

## Prerequisitos

- Docker Desktop 4.x o superior
- Docker Compose V2

## Arquitectura

El proyecto utiliza un **multi-stage build** con las siguientes características:

- **Base image**: .NET 9.0 Alpine (reducido tamaño)
- **Non-root user**: Mayor seguridad ejecutando como usuario `appuser`
- **Health checks**: Monitoreo automático del estado del contenedor
- **Optimización**: Layers cacheados para builds más rápidos

## Despliegue en Producción

### 1. Con SQL Server (Recomendado)

```bash
# Desde el directorio src/net
cd C:\SC\Code\advian-identity\src\net

# Construir y levantar los servicios
docker-compose up -d

# Ver logs
docker-compose logs -f identityserver-api

# Verificar estado
docker-compose ps
```

La API estará disponible en: `http://localhost:7000`

SQL Server estará disponible en: `localhost:1433`

### 2. Solo API (sin base de datos)

Si prefieres usar una base de datos externa:

```bash
# Construir la imagen
docker build -t identityserver-api:latest -f IdentityServer.Api/Dockerfile .

# Ejecutar el contenedor
docker run -d \
  --name identityserver-api \
  -p 7000:8080 \
  -e ASPNETCORE_ENVIRONMENT=Production \
  -e ConnectionStrings__DefaultConnection="Server=your-server;Database=IdentityServerDb;User Id=sa;Password=YourPassword;TrustServerCertificate=True;" \
  identityserver-api:latest
```

## Despliegue en Desarrollo

Para desarrollo con hot-reload:

```bash
# Usar el docker-compose de desarrollo
docker-compose -f docker-compose.dev.yml up

# La API se recargará automáticamente al detectar cambios en el código
```

## Variables de Entorno

### Producción (docker-compose.yml)

Actualiza las siguientes variables en `docker-compose.yml`:

```yaml
environment:
  # Base de datos
  - ConnectionStrings__DefaultConnection=Server=sqlserver;Database=IdentityServerDb;...

  # JWT
  - JWT__SecretKey=${JWT_SECRET_KEY}  # Usa una clave segura
  - JWT__Issuer=https://your-domain.com
  - JWT__Audience=https://your-domain.com

  # CORS
  - Cors__AllowedOrigins__0=https://your-frontend.com
  - Cors__AllowedOrigins__1=https://www.your-frontend.com

  # Autenticación externa (opcional)
  - Authentication__Google__ClientId=${GOOGLE_CLIENT_ID}
  - Authentication__Google__ClientSecret=${GOOGLE_CLIENT_SECRET}
```

### Archivo .env (Recomendado)

Crea un archivo `.env` en `src/net/`:

```env
JWT_SECRET_KEY=your-super-secret-key-here
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
SA_PASSWORD=YourStrong@Password123
```

## Comandos Útiles

### Gestión de contenedores

```bash
# Ver logs en tiempo real
docker-compose logs -f

# Reiniciar servicios
docker-compose restart

# Detener servicios
docker-compose down

# Detener y eliminar volúmenes
docker-compose down -v

# Reconstruir sin caché
docker-compose build --no-cache
```

### Inspección

```bash
# Verificar salud del contenedor
docker inspect identityserver-api | grep -A 10 Health

# Entrar al contenedor
docker exec -it identityserver-api sh

# Ver uso de recursos
docker stats identityserver-api
```

### Base de datos

```bash
# Conectar a SQL Server
docker exec -it identityserver-sqlserver /opt/mssql-tools18/bin/sqlcmd \
  -S localhost -U sa -P YourStrong@Password123 -C

# Backup de la base de datos
docker exec -it identityserver-sqlserver /opt/mssql-tools18/bin/sqlcmd \
  -S localhost -U sa -P YourStrong@Password123 -C \
  -Q "BACKUP DATABASE IdentityServerDb TO DISK = '/var/opt/mssql/backup/IdentityServerDb.bak'"
```

## Seguridad

### Antes de producción:

1. **Cambiar contraseñas**: Actualiza `SA_PASSWORD` y `JWT__SecretKey`
2. **Variables de entorno**: Usa secretos de Docker o servicios como Azure Key Vault
3. **HTTPS**: Configura certificados SSL/TLS
4. **Firewall**: Limita acceso a puertos necesarios
5. **CORS**: Configura orígenes permitidos específicos

### Ejemplo con Docker Secrets:

```bash
# Crear secretos
echo "YourSecretKey" | docker secret create jwt_secret -
echo "YourSAPassword" | docker secret create sa_password -

# Usar en docker-compose.yml
secrets:
  - jwt_secret
  - sa_password
```

## Monitoreo

El contenedor incluye un health check que verifica:
- Respuesta del endpoint `/health`
- Estado HTTP 200
- Intervalo de 30 segundos

Ver estado de salud:

```bash
docker inspect identityserver-api --format='{{.State.Health.Status}}'
```

## Troubleshooting

### El contenedor no inicia

```bash
# Ver logs detallados
docker logs identityserver-api

# Verificar puertos ocupados
netstat -ano | findstr :7000
```

### No puede conectar a SQL Server

```bash
# Verificar que SQL Server esté healthy
docker-compose ps

# Ver logs de SQL Server
docker logs identityserver-sqlserver

# Probar conexión
docker exec -it identityserver-sqlserver /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P YourStrong@Password123 -C -Q "SELECT 1"
```

### Errores de permisos

El contenedor corre como usuario no-root (`appuser`). Si hay problemas con volúmenes:

```bash
# Dar permisos al directorio
chown -R 1000:1000 /path/to/volume
```

## Recursos

- Tamaño de imagen: ~200MB (Alpine-based)
- Memoria recomendada: 512MB mínimo, 1GB recomendado
- CPU: 1 core mínimo, 2 cores recomendado

## Próximos pasos

1. Configurar CI/CD para builds automáticos
2. Implementar logging centralizado (ELK, Seq)
3. Configurar SSL/TLS con Let's Encrypt
4. Implementar rate limiting
5. Configurar backup automático de base de datos
