# 📱 IdentityServer Mobile App

Una aplicación móvil React Native/Expo que se integra con el **Custom Identity Server** usando OAuth2/OIDC para autenticación segura.

## 🎯 **Funcionalidades**

### **🔐 Autenticación OIDC Completa**
- Authorization Code Flow con PKCE
- Refresh Token automático (30 días)
- Almacenamiento seguro de tokens (Expo SecureStore)
- SSO entre aplicaciones web y móvil

### **🏠 Pantalla de Home**
- Información del usuario autenticado
- Pruebas de API protegidas (SampleBack1)
- Monitoreo de expiración de tokens
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
# Expo CLI (opcional, se puede usar npx)
npm install -g @expo/cli
```

### **Instalación**
```bash
cd src/MobileApp
npm install
```

### **Configuración del Identity Server**
El cliente móvil ya está configurado en el `DbSeeder.cs`:
```csharp
ClientId: "mobileapp"
RedirectUris: ["mobileapp://auth", "exp://localhost:8081/--/auth"]
Scopes: ["openid", "profile", "email", "offline_access"]
```

---

## 📱 **Ejecución**

### **1. Iniciar Identity Server**
```bash
# Desde la raíz del proyecto
start-all.bat

# O manualmente:
cd src/IdentityServer.Api && dotnet run
cd src/IdentityServer.Web && dotnet run  
cd src/SampleBack1 && dotnet run
```

### **2. Iniciar App Móvil**
```bash
cd src/MobileApp

# Desarrollo web (para testing rápido)
npm run web

# Android (requiere Android Studio/emulador)
npm run android

# iOS (requiere macOS y Xcode)
npm run ios
```

---

## 🌐 **Configuración de Red**

### **Para testing con localhost:**
La app está configurada para conectarse a:
- **Identity Server**: `https://localhost:5000`
- **Protected API**: `https://localhost:6001`

### **Network Security (Android)**
- Configurado `network_security_config.xml` para permitir HTTP/localhost
- Permite conexiones a `localhost`, `10.0.2.2` (emulador), IP local

---

## 🧪 **Testing del Flujo OIDC**

### **1. Login Inicial**
1. Abrir app móvil
2. Click "Sign In with Identity Server"
3. Redirigir al navegador web → Identity Server login
4. Credenciales: `admin@example.com` / `Admin123!`
5. Autorizar y redirigir de vuelta a la app
6. ✅ Usuario autenticado en la app

### **2. Testing de APIs Protegidas**
- **Call Public Endpoint**: Sin autenticación requerida
- **Call Protected Endpoint**: Con token JWT
- **Get User Info**: Información completa del JWT
- **Get Weather Data**: Datos personalizados
- **Test Refresh Token**: Prueba POST con JSON
- **Check Token Expiry**: Monitor de tiempo restante (5 min)

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
src/MobileApp/
├── App.tsx                    # App principal con navegación
├── app.json                   # Configuración Expo
├── network_security_config.xml # Config red Android
│
├── src/
│   ├── services/
│   │   ├── AuthService.ts     # Servicio OIDC
│   │   └── AuthContext.tsx    # Context de autenticación
│   │
│   ├── screens/
│   │   ├── LoginScreen.tsx    # Pantalla de login
│   │   └── HomeScreen.tsx     # Pantalla principal
│   │
│   └── types/
│       └── auth.ts           # Tipos TypeScript
│
└── assets/                   # Recursos de la app
```

---

## 🔧 **Configuración Técnica**

### **OIDC Configuration**
```typescript
{
  authority: 'https://localhost:5000',
  clientId: 'mobileapp',
  scopes: ['openid', 'profile', 'email', 'offline_access'],
  redirectUri: 'mobileapp://auth'
}
```

### **Token Lifetimes**
- **Access Token**: 5 minutos (para testing)
- **Refresh Token**: 30 días
- **Authorization Code**: 5 minutos

### **Security Features**
- PKCE (Proof Key for Code Exchange)
- Secure token storage (Expo SecureStore)
- Automatic token refresh
- Public client (no client secret required)

---

## 🌍 **URLs de Testing**

### **Development URLs**
- **Expo Dev**: `exp://localhost:8081`
- **Web Version**: `http://localhost:8081`

### **Production URLs** (cuando se compile)
- **Deep Link**: `mobileapp://auth`
- **Android Package**: `com.identityserver.mobileapp`
- **iOS Bundle**: `com.identityserver.mobileapp`

---

## 🔍 **Debugging**

### **Logs de Consola**
La app incluye logging detallado:
```
[AuthService] Initializing...
[AuthService] Starting login flow...
[AuthService] Authorization code received
[AuthService] Refreshing tokens...
[AuthContext] Found valid stored tokens
```

### **Common Issues**
1. **Network Error**: Verificar que Identity Server esté corriendo
2. **Invalid Redirect**: Verificar configuración de esquema URL
3. **Token Expired**: Normal, el refresh debería manejar automáticamente
4. **CORS Issues**: Verificar configuración de CORS en Identity Server

---

## 🎯 **Casos de Uso**

### **1. Desarrollo Mobile-First**
- Patrón estándar para apps React Native con OIDC
- Integración con Identity Server custom
- SSO entre web y móvil

### **2. Enterprise Authentication**
- Autenticación corporativa segura
- Refresh token de larga duración
- Soporte offline con tokens almacenados

### **3. Testing de OAuth2/OIDC**
- Validación completa del flujo de refresh tokens
- Testing de expiración y renovación
- Debug de integración con APIs protegidas

---

## ✅ **Características Implementadas**

- 🔐 **OIDC Authorization Code Flow** con PKCE
- 🔄 **Automatic Refresh Token** handling
- 📱 **Native Mobile Experience** 
- 🌐 **Cross-Platform** (iOS/Android/Web)
- 🛡️ **Secure Token Storage**
- 🔗 **Deep Linking** configurado
- 📊 **API Testing Interface** completa
- 🧪 **Token Expiry Monitoring**
- 📝 **TypeScript** para type safety

**¡La aplicación móvil está lista para probar el flujo completo de OIDC con refresh tokens! 🚀**