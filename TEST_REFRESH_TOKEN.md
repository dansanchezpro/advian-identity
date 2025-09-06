# Refresh Token Implementation - Testing Guide

## ✅ **Implementación Completada**

### **Funcionalidades Agregadas:**

1. **Modelo RefreshToken** - Nuevo modelo en la base de datos
2. **TokenService actualizado** - Métodos para generar, validar y revocar refresh tokens
3. **Endpoint /connect/token** - Soporte para grant_type=refresh_token
4. **Discovery Document** - Incluye offline_access scope y refresh_token grant type
5. **Sample Apps** - Configuradas para solicitar offline_access scope
6. **DbSeeder** - Clientes actualizados con soporte para refresh tokens

### **Flujo Refresh Token Implementado:**

#### **1. Obtener Refresh Token (Primera vez)**
```
Scope solicitado: openid profile email offline_access
Grant type: authorization_code
Respuesta incluye: access_token + id_token + refresh_token
```

#### **2. Usar Refresh Token**
```
POST /connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
client_id=sampleapp1&
refresh_token=<refresh_token_value>
```

#### **3. Respuesta del Refresh**
```json
{
  "access_token": "new_jwt_access_token",
  "id_token": "new_jwt_id_token", 
  "refresh_token": "new_refresh_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email offline_access"
}
```

### **Características Implementadas:**

✅ **Estándar OAuth2/OIDC completo**  
✅ **Refresh token rotation** (se genera nuevo refresh token)  
✅ **Revocación automática** del refresh token usado  
✅ **Validación de scope** (permite subset de scopes originales)  
✅ **Configuración por cliente** (RefreshTokenLifetime = 30 días)  
✅ **Integración con paquetes Microsoft OIDC**  
✅ **offline_access scope** para solicitar refresh tokens  

### **Configuraciones:**

- **Access Token Lifetime**: 1 hora (3600 segundos)
- **Refresh Token Lifetime**: 30 días (2,592,000 segundos)
- **Scope requerido**: `offline_access` (agregado a todas las sample apps)
- **Grant Types soportados**: `authorization_code`, `refresh_token`

### **Testing:**

Para probar el flujo completo:

1. **Ejecutar aplicaciones:**
   ```bash
   # Terminal 1 - API
   cd src/IdentityServer.Api && dotnet run
   
   # Terminal 2 - UI  
   cd src/IdentityServer.Web && dotnet run
   
   # Terminal 3 - Sample App
   cd src/SampleApp1 && dotnet run
   ```

2. **Acceder a SampleApp1:** https://localhost:7001
3. **Login con:** admin@example.com / Admin123!
4. **Verificar en Network tab** que se reciba refresh_token
5. **Esperar a que expire access_token** (o forzar refresh)
6. **Verificar que se use refresh token automáticamente**

### **Logs de Debug:**
El sistema incluye logs detallados para debug:
- `[DEBUG] Refresh token grant - RefreshToken: {token}..., ClientId: {clientId}`
- `[DEBUG] New tokens generated via refresh - AccessToken length: {length}`
- `[DEBUG] Returning refresh token response`

## 🎯 **La implementación sigue completamente los estándares OIDC/OAuth2 y es compatible con paquetes oficiales de Microsoft.**