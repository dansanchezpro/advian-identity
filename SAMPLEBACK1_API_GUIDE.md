# SampleBack1 - Protected API Guide

## 🎯 **Overview**

SampleBack1 es una **API protegida con JWT Bearer Authentication** que demuestra cómo validar tokens emitidos por el Identity Server y permite probar el flujo completo de refresh tokens.

### **📋 Arquitectura Completa**

```
SampleApp1/2/3 (Blazor) → Identity Server → SampleBack1 API
    ↓ (get token)         ↓ (validate)       ↓ (protected endpoints)
  Access Token         RSA Key Validation    JWT Claims
  Refresh Token        OIDC Discovery        Authorization
```

---

## **🔧 Configuración SampleBack1**

### **Puerto**: https://localhost:6001

### **Dependencias**:
- `Microsoft.AspNetCore.Authentication.JwtBearer`
- `Microsoft.IdentityModel.Tokens` 
- `System.IdentityModel.Tokens.Jwt`
- `Swashbuckle.AspNetCore` (Swagger)

### **Configuración JWT**:
```csharp
// Validación automática con Identity Server
Authority: "https://localhost:5000"
MetadataAddress: "/.well-known/openid_configuration"
RequireHttpsMetadata: true
ValidateIssuer: true
ValidateIssuerSigningKey: true (RSA256)
ClockSkew: TimeSpan.Zero // Sin tolerancia de tiempo
```

---

## **🛡️ Endpoints Disponibles**

### **1. Public Endpoint** (Sin autenticación)
```
GET /api/api/public
```
- ✅ **Acceso**: Público (no requiere token)
- 📝 **Uso**: Verificar que la API está funcionando

### **2. Protected Endpoint** (Requiere autenticación)
```
GET /api/api/protected
Authorization: Bearer {access_token}
```
- 🔒 **Acceso**: Requiere token válido
- 📄 **Respuesta**: Información del usuario y claims del token

### **3. User Info Endpoint**
```
GET /api/api/user-info  
Authorization: Bearer {access_token}
```
- 🔒 **Acceso**: Requiere token válido
- 📄 **Respuesta**: Información detallada del usuario extraída del JWT

### **4. Weather Endpoint**  
```
GET /api/api/weather
Authorization: Bearer {access_token}
```
- 🔒 **Acceso**: Requiere token válido
- 📄 **Respuesta**: Datos meteorológicos personalizados para el usuario

### **5. Test Refresh Token Endpoint**
```
POST /api/api/test-refresh
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "testData": "string",
  "requestTime": "2025-01-01T00:00:00Z"
}
```
- 🔒 **Acceso**: Requiere token válido
- 📄 **Uso**: Probar que el refresh token funciona automáticamente

---

## **🧪 Testing desde SampleApp1**

### **Interfaz de Testing**
- **URL**: https://localhost:7001/api-test
- **Funciones**:
  - ✅ Call Public Endpoint (sin auth)
  - 🔒 Call Protected Endpoint (con token)
  - 👤 Call User Info Endpoint (datos JWT)
  - 🌤️ Call Weather Endpoint (datos personalizados)
  - 🔄 Test Refresh Token (POST con JSON)

### **Validación Automática de Tokens**
```csharp
// El paquete Microsoft OIDC maneja automáticamente:
1. Obtener access_token del Identity Server
2. Incluir token en headers: Authorization: Bearer {token}
3. Refresh automático cuando el token expira
4. Retry de requests después del refresh
```

---

## **📊 Flujo Completo de Refresh Token**

### **Escenario de Testing**:

1. **Login inicial** en SampleApp1
   - Usuario obtiene: `access_token` + `refresh_token`
   - Lifetime: Access token = 1 hora, Refresh token = 30 días

2. **Llamada a API protegida** (token válido)
   ```
   GET /api/api/protected
   Authorization: Bearer {valid_access_token}
   → 200 OK + user data
   ```

3. **Simulación de token expirado**
   - Esperar 1 hora O modificar lifetime en configuración
   - Token access expira

4. **Refresh automático**
   ```
   // El paquete Microsoft OIDC automáticamente:
   POST /connect/token (Identity Server)
   grant_type=refresh_token
   refresh_token={current_refresh_token}
   
   // Respuesta:
   - Nuevo access_token 
   - Nuevo refresh_token (rotación)
   - Token anterior se revoca
   ```

5. **Retry de API call**
   ```
   GET /api/api/protected  
   Authorization: Bearer {new_access_token}
   → 200 OK + user data
   ```

---

## **🔍 Logs de Debug**

### **SampleBack1 Logs**:
```
[SAMPLEBACK1] Received token: eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bH...
[SAMPLEBACK1] Token validated for user: admin@example.com (ID: 1)
[SAMPLEBACK1] Protected endpoint accessed by user: admin@example.com
```

### **Identity Server Logs**:
```
[DEBUG] Refresh token grant - RefreshToken: a1b2c3d4...ClientId: sampleapp1
[DEBUG] New tokens generated via refresh - AccessToken length: 1245
[DEBUG] Returning refresh token response
```

---

## **⚙️ Configuración CORS**

SampleBack1 permite requests desde:
- `https://localhost:7001` (SampleApp1)
- `https://localhost:7002` (SampleApp2) 
- `https://localhost:7003` (SampleApp3)
- `https://localhost:7000` (Identity UI)

---

## **🚀 Cómo Ejecutar Todo**

### **Opción 1: Script automático**
```bash
start-all.bat
```

### **Opción 2: Manual**
```bash
# Terminal 1 - Identity Server API
cd src/IdentityServer.Api && dotnet run

# Terminal 2 - Identity Server UI  
cd src/IdentityServer.Web && dotnet run

# Terminal 3 - SampleBack1 API
cd src/SampleBack1 && dotnet run

# Terminal 4 - SampleApp1
cd src/SampleApp1 && dotnet run
```

### **URLs**:
- **Identity API**: https://localhost:5000
- **Identity UI**: https://localhost:7000
- **SampleApp1**: https://localhost:7001
- **SampleBack1**: https://localhost:6001
- **Swagger**: https://localhost:6001/swagger

---

## **🎯 Casos de Uso**

### **1. Desarrollo de APIs protegidas**
- Patrón de validación JWT estándar
- Integración con Identity Server custom
- Manejo automático de refresh tokens

### **2. Testing de Refresh Tokens**
- Validar funcionamiento automático
- Probar rotación de tokens
- Debugging de expiración/renovación

### **3. Integración con paquetes Microsoft OIDC**
- Compatibilidad completa
- Refresh transparente al usuario
- Manejo de errores 401/403

---

## **✅ Características Implementadas**

- 🔒 **JWT Bearer Authentication** con RSA256
- 🔄 **Automatic Token Refresh** (transparente)
- 🌐 **CORS configurado** para SPAs
- 📊 **Logging detallado** para debugging
- 🧪 **Swagger UI** para testing manual
- 👥 **User Claims extraction** desde JWT
- 📝 **Multiple endpoint patterns** (GET/POST)
- ⚡ **Performance optimizado** con HttpClient

**La implementación demuestra el flujo completo de OAuth2/OIDC con refresh tokens funcionando perfectamente con paquetes oficiales de Microsoft.**