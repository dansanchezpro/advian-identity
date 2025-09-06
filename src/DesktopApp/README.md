# 🖥️ IdentityServer Desktop App

Una aplicación de escritorio Electron que se integra con el **Custom Identity Server** usando OAuth2/OIDC para autenticación segura.

## 🎯 **Funcionalidades**

### **🔐 Autenticación OIDC Completa**
- Authorization Code Flow con PKCE
- Refresh Token automático (30 días)
- Almacenamiento seguro de tokens (keytar)
- SSO entre aplicaciones web, móvil y desktop

### **🏠 Dashboard Principal**
- Información del usuario autenticado
- Pruebas de API protegidas (SampleBack1)
- Monitoreo de expiración de tokens en tiempo real
- Testing completo de refresh token

### **🛡️ Integración con APIs Protegidas**
- Llamadas a endpoints protegidos con JWT Bearer
- Refresh automático de tokens expirados
- Manejo de errores y reintentos

---

## 🚀 **Instalación y Setup**

### **Prerrequisitos**
```bash
# Node.js y npm ya instalados
```

### **Instalación**
```bash
cd src/DesktopApp
npm install
```

### **Configuración del Identity Server**
El cliente desktop ya está configurado en el `DbSeeder.cs`:
```csharp
ClientId: "desktopapp"
RedirectUris: ["http://localhost:8080/callback", "desktopapp://auth"]
Scopes: ["openid", "profile", "email", "offline_access"]
```

---

## 🖥️ **Ejecución**

### **1. Iniciar Identity Server**
```bash
# Desde la raíz del proyecto
start-all.bat

# O manualmente:
cd src/IdentityServer.Api && dotnet run
cd src/IdentityServer.Web && dotnet run  
cd src/SampleBack1 && dotnet run
```

### **2. Iniciar Desktop App**
```bash
cd src/DesktopApp

# Modo desarrollo
npm run dev

# Modo producción
npm start

# Compilar aplicación
npm run build         # Para todas las plataformas
npm run build-win     # Solo Windows
npm run build-mac     # Solo macOS
npm run build-linux   # Solo Linux
```

---

## 🔧 **Configuración Técnica**

### **OIDC Configuration**
```javascript
{
  authority: 'https://localhost:5000',
  clientId: 'desktopapp',
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  redirectUri: 'http://localhost:8080/callback'
}
```

### **Token Lifetimes**
- **Access Token**: 5 minutos (para testing)
- **Refresh Token**: 30 días
- **Authorization Code**: 5 minutos

### **Security Features**
- PKCE (Proof Key for Code Exchange)
- Secure token storage (keytar - OS credential manager)
- Automatic token refresh
- Public client (no client secret required)

---

## 🧪 **Testing del Flujo OIDC**

### **1. Login Inicial**
1. Abrir desktop app
2. Click "Sign In"
3. Se abre navegador web → Identity Server login
4. Credenciales: `admin@example.com` / `Admin123!`
5. Autorizar y cerrar navegador
6. ✅ Usuario autenticado en la app

### **2. Testing de APIs Protegidas**
- **Test Public Endpoint**: Sin autenticación requerida
- **Test Protected Endpoint**: Con token JWT
- **Get User Info from API**: Información completa del JWT
- **Get Weather Data**: Datos personalizados
- **Get Token Info**: Estado del token con tiempo restante

### **3. Testing de Refresh Token**
1. Login y verificar token válido
2. Esperar 5 minutos para expiración
3. Llamar cualquier endpoint protegido
4. App automáticamente:
   - Detecta token expirado
   - Usa refresh token para obtener nuevo access token
   - Reintenta la llamada original
   - ✅ Request exitoso sin intervención del usuario

---

## 📂 **Estructura del Proyecto**

```
src/DesktopApp/
├── main.js                   # Proceso principal de Electron
├── package.json              # Dependencias y scripts
├── public/
│   ├── login.html           # Ventana de login
│   └── main.html            # Dashboard principal
└── src/
    └── services/
        └── AuthService.js   # Servicio OIDC y gestión de tokens
```

---

## 🔍 **Debugging**

### **Logs de Consola**
La app incluye logging detallado:
```
[Main] AuthService initialized
[AuthService] Starting login process
[Main] Received auth callback
[AuthService] Tokens stored successfully
[Main] Authentication successful
```

### **Common Issues**
1. **Network Error**: Verificar que Identity Server esté corriendo
2. **Invalid Protocol**: Verificar configuración de esquema `desktopapp://`
3. **Token Expired**: Normal, el refresh debería manejar automáticamente
4. **Keytar Issues**: Verificar permisos del sistema para credential manager

---

## ✅ **Características Implementadas**

- 🔐 **OIDC Authorization Code Flow** con PKCE
- 🔄 **Automatic Refresh Token** handling
- 🖥️ **Native Desktop Experience** con Electron
- 🌐 **Cross-Platform** (Windows/macOS/Linux)
- 🛡️ **Secure Token Storage** (OS credential manager)
- 📊 **API Testing Interface** completa
- ⏱️ **Real-time Token Monitoring** con countdown
- 📝 **Comprehensive Error Handling**
- 🔗 **Protocol Handler** para deep linking

**¡La aplicación desktop está lista para probar el flujo completo de OIDC con refresh tokens! 🚀**