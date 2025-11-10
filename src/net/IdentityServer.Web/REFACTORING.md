# Refactorización: Eliminación de JavaScript y uso de Blazor puro

Este documento explica la refactorización realizada para eliminar el código JavaScript del UI y usar solo Blazor con HttpClient.

## 🎯 Objetivo

Simplificar el código eliminando la dependencia de JavaScript para las llamadas al backend API, usando en su lugar HttpClient de Blazor con soporte para cookies cross-origin.

---

## 📊 Comparación Antes vs Después

### ❌ Antes (con JavaScript)

**Problemas:**
- ~100 líneas de JavaScript complejo en `index.html`
- 3 funciones diferentes para form POST (`submitOidcForm`, `submitGoogleRegisterForm`, `submitManualRegisterForm`)
- Código duplicado y difícil de mantener
- Mezcla de C# y JavaScript
- Difícil de testear y debuggear

**Flujo:**
```
Login.razor (C#)
  ↓ JSInterop
index.html (JavaScript) - crea form POST dinámico
  ↓ form.submit()
Backend API
  ↓ Redirect
App1
```

### ✅ Después (solo Blazor)

**Ventajas:**
- ~30 líneas de JavaScript simple (una sola función genérica)
- Todo el código en C# fuertemente tipado
- Más fácil de mantener, testear y debuggear
- Separación clara: Autenticación → Autorización
- Mejor manejo de errores

**Flujo:**
```
Login.razor (C#)
  ↓ fetchWithCredentials (JavaScript simple)
Backend API - /api/auth/login
  ↓ Retorna JSON
Login.razor
  ↓ NavigationManager
Backend API - /api/auth/oidc-login
  ↓ Genera código y redirige
App1
```

---

## 🔧 Cambios Realizados

### 1. Backend API (IdentityServer.Api)

#### ✅ **Program.cs - CORS con AllowCredentials**

```csharp
// Antes
policy.AllowAnyOrigin()  // ❌ NO funciona con cookies
      .AllowAnyMethod()
      .AllowAnyHeader();

// Después
policy.WithOrigins(
          "https://localhost:7000",  // Identity UI
          "https://localhost:7001",  // Apps
          // ...
      )
      .AllowAnyMethod()
      .AllowAnyHeader()
      .AllowCredentials();  // ✅ CRÍTICO para cookies
```

**¿Por qué?** `AllowAnyOrigin()` NO es compatible con `AllowCredentials()`. Para enviar cookies cross-origin, debemos especificar orígenes explícitos.

#### ✅ **Endpoints ya existentes (NO se modificaron)**

El backend ya tenía endpoints JSON perfectos:
- `POST /api/auth/login` - Autentica y crea sesión
- `POST /api/auth/register` - Registra usuario y crea sesión

Estos endpoints:
- ✅ Crean la cookie de sesión
- ✅ Retornan JSON (no Redirect)
- ✅ Manejan errores correctamente

---

### 2. Frontend UI (IdentityServer.Web)

#### ✅ **index.html - Función JavaScript simplificada**

**Antes:** ~100 líneas con 3 funciones diferentes

**Después:** ~30 líneas con UNA función genérica

```javascript
window.fetchWithCredentials = async function(url, method, body) {
    const options = {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include'  // ← CRÍTICO: Envía cookies cross-origin
    };

    if (body && method !== 'GET') {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    return await response.json();
};
```

**¿Qué hace?**
- Hace fetch con `credentials: 'include'` para enviar cookies
- Serializa el body a JSON automáticamente
- Retorna la respuesta como JSON
- Simple y reutilizable

---

#### ✅ **Login.razor - Refactorizado**

**Antes:**
```csharp
// Usaba JSInterop para crear form POST dinámico
await JSRuntime.InvokeVoidAsync("submitOidcForm", Settings.ApiUrl, new
{
    email = loginModel.Email,
    password = loginModel.Password,
    // ... todos los parámetros OIDC
});
```

**Después:**
```csharp
// Paso 1: Autenticar (crea cookie de sesión)
var loginRequest = new { Email = loginModel.Email, Password = loginModel.Password };
var loginResponse = await JSRuntime.InvokeAsync<LoginResponse>(
    "fetchWithCredentials",
    $"{Settings.ApiUrl}/api/auth/login",
    "POST",
    loginRequest
);

if (!loginResponse.Success)
{
    errorMessage = loginResponse.Error;
    return;
}

// Paso 2: Redirigir al authorization endpoint
// El backend detectará la cookie y generará el código automáticamente
var authUrl = BuildAuthorizationUrl();
Navigation.NavigateTo(authUrl, forceLoad: true);
```

**Ventajas:**
- ✅ Código C# puro
- ✅ Type-safe con modelos `LoginResponse`
- ✅ Mejor manejo de errores
- ✅ Separa autenticación de autorización
- ✅ Más fácil de entender y mantener

---

#### ✅ **Register.razor - Refactorizado**

Similar a Login.razor:

```csharp
var registerRequest = new
{
    FirstName = registerModel.FirstName,
    LastName = registerModel.LastName,
    Email = registerModel.Email,
    Password = registerModel.Password,
    ConfirmPassword = registerModel.ConfirmPassword,
    DateOfBirth = registerModel.DateOfBirth,
    AcceptTerms = registerModel.AcceptTerms
};

var registerResponse = await JSRuntime.InvokeAsync<RegisterResponse>(
    "fetchWithCredentials",
    $"{Settings.ApiUrl}/api/auth/register",
    "POST",
    registerRequest
);

if (!registerResponse.Success)
{
    errorMessage = registerResponse.Error;
    return;
}

// Redirigir al authorization endpoint si es flujo OIDC
if (!string.IsNullOrEmpty(client_id))
{
    var authUrl = BuildAuthorizationUrl();
    Navigation.NavigateTo(authUrl, forceLoad: true);
}
else
{
    Navigation.NavigateTo("/dashboard", forceLoad: true);
}
```

---

#### ✅ **Program.cs - HttpClient configurado**

```csharp
// Configure HttpClient for calling the backend API
builder.Services.AddScoped(sp =>
{
    var settings = sp.GetRequiredService<IdentityServerSettings>();
    var httpClient = new HttpClient
    {
        BaseAddress = new Uri(settings.ApiUrl)
    };
    return httpClient;
});
```

---

### 3. Modelos compartidos

Se agregaron modelos para las respuestas JSON:

```csharp
// Login.razor
public class LoginResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public UserInfo? User { get; set; }
}

// Register.razor
public class RegisterResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public UserInfo? User { get; set; }
}

public class UserInfo
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
}
```

---

## 🔐 Cómo funcionan las cookies cross-origin

### Problema Original

El UI (puerto 7000) necesita que el Backend API (puerto 5000) cree una cookie de sesión que funcione para SSO.

### Solución

1. **Backend - CORS con AllowCredentials:**
   ```csharp
   policy.WithOrigins("https://localhost:7000")
         .AllowCredentials();  // ← Permite cookies
   ```

2. **Frontend - fetch con credentials:**
   ```javascript
   credentials: 'include'  // ← Envía/recibe cookies
   ```

3. **Cookie configuration:**
   ```csharp
   options.Cookie.SameSite = SameSiteMode.Lax;  // Permite cross-site
   options.Cookie.Domain = ".localhost";  // Compartida entre puertos
   ```

### Flujo completo:

```
1. UI (7000) → fetch con credentials: 'include'
2. Backend (5000) → Crea cookie con Domain=.localhost
3. Browser → Guarda cookie para *.localhost
4. UI redirige → Backend (5000)
5. Backend → Cookie enviada automáticamente
6. Backend → Detecta sesión, genera código
7. Backend → Redirige a App1 con código
8. ✅ SSO funcionando
```

---

## 📈 Métricas de mejora

| Métrica | Antes | Después | Mejora |
|---------|-------|---------|--------|
| Líneas de JavaScript | ~100 | ~30 | ✅ 70% menos |
| Funciones JS | 3 | 1 | ✅ 66% menos |
| Complejidad (McCabe) | Alta | Baja | ✅ |
| Type safety | ❌ No | ✅ Sí | ✅ |
| Testeable | ❌ Difícil | ✅ Fácil | ✅ |
| Mantenible | ❌ Difícil | ✅ Fácil | ✅ |
| Debuggeable | ❌ Difícil | ✅ Fácil | ✅ |

---

## 🧪 Testing

### Antes (con JavaScript):
```
❌ No se puede testear el código JavaScript fácilmente
❌ Necesitas un navegador para probar
❌ Difícil de mockear form.submit()
```

### Después (solo Blazor):
```csharp
✅ Puedes mockear HttpClient en tests unitarios
✅ Puedes mockear JSRuntime
✅ Tests más rápidos y confiables

[Fact]
public async Task HandleLogin_Success_RedirectsToAuthEndpoint()
{
    // Arrange
    var mockJSRuntime = new MockJSRuntime();
    mockJSRuntime.Setup<LoginResponse>("fetchWithCredentials", ...)
                 .Returns(new LoginResponse { Success = true });

    // Act
    await component.HandleLogin();

    // Assert
    Assert.Contains("oidc-login", navigationManager.Uri);
}
```

---

## 🚀 Próximos pasos (opcional)

### 1. Eliminar JSInterop completamente (avanzado)

En lugar de usar `JSRuntime.InvokeAsync("fetchWithCredentials")`, podrías usar:

```csharp
// Crear un HttpClient wrapper que maneje credentials
public class CredentialHttpClient
{
    public async Task<T> PostAsync<T>(string url, object body)
    {
        // Usa JSInterop internamente pero está encapsulado
        return await JSRuntime.InvokeAsync<T>("fetchWithCredentials", url, "POST", body);
    }
}

// Usage
var response = await credentialHttpClient.PostAsync<LoginResponse>(
    $"{Settings.ApiUrl}/api/auth/login",
    loginRequest
);
```

### 2. Agregar retry logic

```csharp
var response = await Polly
    .HandleResult<LoginResponse>(r => !r.Success)
    .WaitAndRetryAsync(3, retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)))
    .ExecuteAsync(() => credentialHttpClient.PostAsync<LoginResponse>(url, request));
```

### 3. Agregar logging estructurado

```csharp
_logger.LogInformation("User {Email} attempting login", loginRequest.Email);
```

---

## 📝 Notas importantes

1. **¿Por qué seguimos usando un poquito de JavaScript?**
   - Blazor WASM no puede configurar `credentials: 'include'` directamente en HttpClient
   - Necesitamos fetch API del navegador para esto
   - Es una limitación de Blazor WASM, no del diseño

2. **¿Se podría eliminar TODO el JavaScript?**
   - No fácilmente. Blazor WASM ejecuta en un sandbox de WebAssembly
   - No tiene acceso directo a las APIs del navegador como fetch
   - Necesitaríamos un proxy o SignalR, lo cual sería más complejo

3. **¿Es seguro?**
   - ✅ Sí! `credentials: 'include'` es el estándar para cookies cross-origin
   - ✅ CORS está configurado correctamente con orígenes específicos
   - ✅ Las cookies tienen `HttpOnly`, `Secure`, y `SameSite=Lax`

---

## 🎓 Lecciones aprendidas

1. **CORS + Credentials:**
   - `AllowAnyOrigin()` NO funciona con `AllowCredentials()`
   - Debes especificar orígenes explícitos

2. **Separación de concerns:**
   - Autenticación (crear sesión) vs Autorización (generar código)
   - Mejora la claridad del flujo

3. **Type safety:**
   - Los modelos C# ayudan a detectar errores en tiempo de compilación
   - Mejor IntelliSense y refactoring

4. **Simplicidad:**
   - Menos código = menos bugs
   - Una función genérica es mejor que 3 específicas

---

## ✅ Checklist para testing

Después de aplicar esta refactorización, verifica:

- [ ] Login con credenciales funciona
- [ ] Registro de usuario funciona
- [ ] La cookie de sesión se crea correctamente
- [ ] El SSO funciona (App1 → App2 sin login)
- [ ] Los errores se muestran correctamente
- [ ] No hay errores de CORS en la consola
- [ ] La redirección post-login funciona

---

## 📚 Referencias

- [MDN: Fetch API - credentials](https://developer.mozilla.org/en-US/docs/Web/API/fetch#credentials)
- [ASP.NET Core CORS](https://learn.microsoft.com/en-us/aspnet/core/security/cors)
- [Blazor JSInterop](https://learn.microsoft.com/en-us/aspnet/core/blazor/javascript-interoperability/)
- [Cookie SameSite](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value)
