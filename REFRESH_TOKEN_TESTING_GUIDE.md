# 🔄 Refresh Token Testing Guide - 5 Minute Tokens

## 🎯 **Configuración para Testing**

### **⏰ Access Token Lifetime: 5 minutos**
- **Antes**: 1 hora (3600 segundos) 
- **Ahora**: 5 minutos (300 segundos)
- **Refresh Token**: Sigue siendo 30 días

### **🔍 Nuevo Endpoint para Monitoring**
```
GET /api/api/token-info
```
- Muestra tiempo restante del token
- Formato amigable: "4m 32s"  
- Indica si el token ha expirado

---

## **🧪 Pasos para Probar el Refresh Token**

### **1. Iniciar todas las aplicaciones**
```bash
start-all.bat
```

### **2. Login inicial**
1. Ir a: https://localhost:7001
2. Click "Login" 
3. Credenciales: `admin@example.com` / `Admin123!`
4. ✅ Usuario autenticado con token válido

### **3. Acceder a página de testing**
1. Click "Test Protected API" o ir a: https://localhost:7001/api-test
2. Verás 6 botones de testing

### **4. Verificar token inicial**
1. Click **"Check Token Expiry"**
2. Verás algo como:
   ```json
   {
     "token": {
       "issued_at": "2025-01-01 10:00:00 UTC",
       "expires_at": "2025-01-01 10:05:00 UTC", 
       "time_remaining": "4m 58s",
       "seconds_remaining": 298,
       "is_expired": false
     }
   }
   ```

### **5. Probar endpoints mientras token es válido**
1. Click **"Call Protected Endpoint"** → ✅ 200 OK
2. Click **"Call User Info Endpoint"** → ✅ 200 OK  
3. Click **"Call Weather Endpoint"** → ✅ 200 OK

### **6. Esperar expiración (5 minutos)**
- Puedes hacer otras cosas
- Click **"Check Token Expiry"** cada minuto para ver countdown
- Cuando veas `"is_expired": true` → es hora de probar!

### **7. Probar refresh automático**
1. Token expirado → Click **"Call Protected Endpoint"**
2. **¿Qué debe pasar?**:
   - El paquete Microsoft OIDC detecta token expirado
   - Automáticamente usa refresh token: `POST /connect/token`
   - Obtiene nuevo access token + nuevo refresh token
   - Reintenta el request original
   - ✅ 200 OK (transparente al usuario)

### **8. Verificar nuevo token**
1. Click **"Check Token Expiry"** después del refresh
2. Verás nuevo token con tiempo completo:
   ```json
   {
     "token": {
       "issued_at": "2025-01-01 10:05:30 UTC", // ← Nuevo timestamp
       "expires_at": "2025-01-01 10:10:30 UTC", // ← Nueva expiración
       "time_remaining": "4m 59s",              // ← Tiempo resetado
       "is_expired": false
     }
   }
   ```

---

## **📊 Logs a Observar**

### **En la consola del Identity Server API:**
```
[DEBUG] Refresh token grant - RefreshToken: a1b2c3d4...ClientId: sampleapp1
[DEBUG] User not found for refresh token // Si hay error
[DEBUG] New tokens generated via refresh - AccessToken length: 1245
[DEBUG] Returning refresh token response
```

### **En la consola del SampleBack1 API:**
```
[SAMPLEBACK1] Authentication failed: The token is expired
[SAMPLEBACK1] Received token: eyJhbGciOiJSUzI1NiIs... // Nuevo token
[SAMPLEBACK1] Token validated for user: admin@example.com (ID: 1)
[SAMPLEBACK1] Protected endpoint accessed by user: admin@example.com
```

### **En el navegador (Network tab):**
1. **Primer request**: 401 Unauthorized (token expirado)
2. **Request automático**: `POST /connect/token` (refresh)  
3. **Retry request**: 200 OK (con nuevo token)

---

## **🔄 Ciclo Completo de Testing**

### **Escenario 1: Token válido**
```
User → SampleApp1 → SampleBack1 → ✅ 200 OK
       (5min token)  (valid JWT)
```

### **Escenario 2: Token expirado + Refresh automático**
```
User → SampleApp1 → SampleBack1 → ❌ 401 Unauthorized
       (expired)     (expired JWT)
           ↓
       OIDC Client detects 401
           ↓  
       POST /connect/token (refresh_token grant)
           ↓
       Identity Server → New tokens
           ↓
       Retry request → SampleBack1 → ✅ 200 OK
                      (new JWT)
```

---

## **🎯 Casos de Uso para Probar**

### **🟢 Casos Exitosos:**
1. **Token válido** → Todos los endpoints funcionan
2. **Token expirado** → Refresh automático + retry exitoso  
3. **Múltiples requests** → Solo el primero trigger refresh
4. **Navegación entre pages** → Token renovado se mantiene

### **🔴 Casos de Error:**
1. **Refresh token expirado** (después de 30 días) → Redirect a login
2. **Refresh token revocado** → Error + redirect a login
3. **Usuario deshabilitado** → Error en refresh

---

## **⚙️ Configuración Avanzada**

### **Para testing más rápido (1 minuto):**
```csharp
// En DbSeeder.cs
AccessTokenLifetime = 60, // 1 minuto
```

### **Para testing ultra rápido (30 segundos):**  
```csharp
// En DbSeeder.cs
AccessTokenLifetime = 30, // 30 segundos
```

### **Para volver a producción:**
```csharp
// En DbSeeder.cs  
AccessTokenLifetime = 3600, // 1 hora
```

---

## **🏆 Resultados Esperados**

Al completar el testing deberías ver:

✅ **Token expira a los 5 minutos exactos**  
✅ **Refresh automático sin intervención del usuario**  
✅ **Requests retry exitosamente después del refresh**  
✅ **Nuevo token con tiempo completo (5 min)**  
✅ **Logs detallados en todas las consolas**  
✅ **Network tab muestra el flujo completo**  

**🎯 ¡El sistema de refresh tokens funciona perfectamente siguiendo estándares OAuth2/OIDC!**

---

## **📝 Notas de Troubleshooting**

- **Si no ves refresh**: Verificar que `offline_access` esté en los scopes
- **Si hay errores 401 constantes**: Verificar configuración de RSA keys
- **Si refresh falla**: Verificar logs del Identity Server para detalles
- **Si token no expira**: Verificar que AccessTokenLifetime sea 300 segundos

**¡Listo para probar el refresh token en acción! 🚀**