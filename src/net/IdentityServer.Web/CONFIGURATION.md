# Configuración del Identity Server Web UI

Este documento explica cómo configurar la URL del backend API en el proyecto Identity Server Web UI.

## Problema original

Anteriormente, la URL del backend estaba **hardcodeada** en el archivo `index.html`:

```javascript
// ❌ Antes (hardcodeado)
form.action = 'https://localhost:5000/api/auth/oidc-form-login';
```

Esto causaba problemas:
- ❌ No se podía cambiar según el ambiente (dev, staging, prod)
- ❌ Requería modificar código para cambiar la URL
- ❌ No era compatible con Docker o diferentes ambientes

## Solución implementada

Ahora la configuración se maneja mediante archivos `appsettings.json`:

### Estructura de archivos creados:

```
IdentityServer.Web/
├── wwwroot/
│   ├── appsettings.json              # Configuración base
│   ├── appsettings.Development.json  # Configuración para desarrollo
│   └── appsettings.Production.json   # Configuración para producción
└── Configuration/
    └── IdentityServerSettings.cs     # Modelo de configuración
```

## Configuración

### 1. appsettings.json (Base)

```json
{
  "IdentityServer": {
    "ApiUrl": "https://localhost:5000"
  }
}
```

### 2. appsettings.Development.json

```json
{
  "IdentityServer": {
    "ApiUrl": "https://localhost:5000"
  }
}
```

### 3. appsettings.Production.json

```json
{
  "IdentityServer": {
    "ApiUrl": "https://your-api-domain.com"
  }
}
```

## Cómo funciona

### 1. Program.cs carga la configuración

```csharp
var identityServerSettings = builder.Configuration
    .GetSection("IdentityServer")
    .Get<IdentityServerSettings>() ?? new IdentityServerSettings();

builder.Services.AddSingleton(identityServerSettings);
```

### 2. Los componentes Razor inyectan la configuración

```razor
@using IdentityServer.Web.Configuration
@inject IdentityServerSettings Settings
```

### 3. Las funciones JavaScript reciben la URL como parámetro

**Login.razor:**
```csharp
await JSRuntime.InvokeVoidAsync("submitOidcForm", Settings.ApiUrl, formData);
```

**index.html:**
```javascript
window.submitOidcForm = function(apiUrl, formData) {
    var form = document.createElement('form');
    form.action = apiUrl + '/api/auth/oidc-form-login';
    // ...
};
```

## Cambiar la URL del backend

### Para desarrollo local:

Edita `wwwroot/appsettings.Development.json`:

```json
{
  "IdentityServer": {
    "ApiUrl": "https://localhost:5000"
  }
}
```

### Para producción:

Edita `wwwroot/appsettings.Production.json`:

```json
{
  "IdentityServer": {
    "ApiUrl": "https://api.yourdomain.com"
  }
}
```

### Para Docker:

Puedes sobrescribir la configuración mediante variables de entorno o montando un archivo de configuración personalizado:

```yaml
# docker-compose.yml
services:
  identityserver-web:
    volumes:
      - ./appsettings.Production.json:/app/wwwroot/appsettings.json:ro
```

O mediante un script de inicio que modifique el archivo:

```bash
# Reemplazar la URL en el archivo de configuración
sed -i 's|https://localhost:5000|https://api.production.com|g' /app/wwwroot/appsettings.json
```

## Endpoints afectados

Las siguientes URLs ahora son configurables:

1. **Login con credenciales**: `{ApiUrl}/api/auth/oidc-form-login`
2. **Login externo (Google)**: `{ApiUrl}/api/auth/external/{provider}`
3. **Registro con Google**: `{ApiUrl}/api/auth/register-with-google`
4. **Registro manual**: `{ApiUrl}/api/auth/register-complete`

## Ambientes

Blazor WASM selecciona automáticamente el archivo de configuración según el ambiente:

- **Development**: `appsettings.Development.json`
- **Production**: `appsettings.Production.json`
- **Staging**: `appsettings.Staging.json` (si lo creas)

El ambiente se define al compilar:

```bash
# Desarrollo (default)
dotnet build

# Producción
dotnet publish -c Release
```

## Verificación

Para verificar qué URL está usando, revisa la consola del navegador:

```javascript
console.log('[UI] Submitting OIDC form to API:', apiUrl, formData);
```

Verás algo como:
```
[UI] Submitting OIDC form to API: https://localhost:5000 {...}
```

## Ventajas de la nueva implementación

✅ **Configurable por ambiente**: Dev, Staging, Production
✅ **No requiere cambios en el código**: Solo editar JSON
✅ **Compatible con Docker**: Puedes montar archivos de configuración
✅ **Type-safe**: Modelo C# fuertemente tipado
✅ **Centralizado**: Una sola fuente de verdad para la URL
✅ **Fácil debugging**: Logs muestran la URL usada

## Troubleshooting

### El UI sigue usando localhost:5000 en producción

1. Verifica que `appsettings.Production.json` tenga la URL correcta
2. Asegúrate de compilar en modo Release: `dotnet publish -c Release`
3. Revisa los logs del navegador para ver qué URL se está usando

### Error "Cannot find IdentityServerSettings"

Asegúrate de que `Program.cs` tenga:

```csharp
builder.Services.AddSingleton(identityServerSettings);
```

Y que los componentes Razor inyecten:

```razor
@inject IdentityServerSettings Settings
```

### La configuración no se carga

Verifica que los archivos JSON estén en `wwwroot/` y tengan la estructura correcta:

```json
{
  "IdentityServer": {
    "ApiUrl": "https://your-url"
  }
}
```
