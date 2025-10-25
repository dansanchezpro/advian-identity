Flujo Correcto de Redirección:

  App1 → Backend API → Identity UI

  1. App1 NO va directo al UI de Login

  Cuando haces clic en "Login" en App1, Blazor WASM inicia el flujo OIDC y redirige primero al Authorization
  Endpoint del Backend API:

  App1 (https://localhost:7001)
    ↓ Blazor WASM RemoteAuthenticatorView
    ↓ PRIMERO va al BACKEND API
  GET https://localhost:5000/api/auth/oidc-login?
      client_id=sampleapp1&
      redirect_uri=https://localhost:7001/authentication/login-callback&
      response_type=code&
      scope=openid profile email&
      code_challenge=...&
      code_challenge_method=S256

  Ubicación en código:
  - Discovery document define el authorization endpoint: DiscoveryController.cs:25
  authorization_endpoint = $"{baseUrl}/api/auth/oidc-login"

  2. El Backend API decide qué hacer

  Ubicación: AuthController.cs:32-113 (método OidcLogin)

  El backend tiene 3 posibles caminos:

  Camino A: Usuario YA autenticado (SSO) ✅

  // AuthController.cs:60-78
  if (HttpContext.User.Identity?.IsAuthenticated == true)
  {
      var userIdClaim = HttpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
      if (!string.IsNullOrEmpty(userIdClaim) && int.TryParse(userIdClaim, out var userId))
      {
          // Usuario ya tiene sesión con cookie
          // GENERA EL CÓDIGO DIRECTAMENTE - NO REDIRIGE AL UI
          var code = await _tokenService.GenerateAuthorizationCodeAsync(...);

          var redirectUrl = $"{redirect_uri}?code={code}";
          return Redirect(redirectUrl); // Regresa directo a App1
      }
  }

  En este caso: Backend → App1 (con código, sin mostrar login)

  Camino B: Usuario NO autenticado → Redirige al UI ❌→🔐

  // AuthController.cs:92-112
  // No valid session found, redirect to Identity Server UI with API callback
  var identityServerUiUrl = $"{_configuration["IdentityServer:LoginUrl"]}/login";
  var loginParams = new List<string>
  {
      $"client_id={Uri.EscapeDataString(client_id)}",
      $"redirect_uri={Uri.EscapeDataString(redirect_uri)}",
      // ... todos los parámetros OIDC
  };

  var loginUrl = $"{identityServerUiUrl}?{string.Join("&", loginParams)}";
  return Redirect(loginUrl); // BACKEND redirige al UI (puerto 7000)

  En este caso: Backend → Identity UI (https://localhost:7000/login?...)

  Camino C: Silent auth fallida (prompt=none)

  // AuthController.cs:82-89
  if (prompt == "none")
  {
      // Cliente pidió autenticación silenciosa pero no hay sesión
      var errorRedirect = $"{redirect_uri}?error=login_required";
      return Redirect(errorRedirect); // Regresa a App1 con error
  }

  ---
  Entonces el flujo real es:

  ┌─────────┐
  │  App1   │ Click "Login"
  └────┬────┘
       │
       ↓ (1) GET /api/auth/oidc-login (Backend API:5000)
  ┌──────────────────┐
  │   Backend API    │ ¿Usuario tiene cookie de sesión?
  └────┬────┬────────┘
       │    │
       │    └─ SÍ → Genera código → Redirect a App1 con code ✅
       │
       └─ NO ↓ (2) Redirect a Identity UI (puerto 7000)

  ┌──────────────────┐
  │  Identity UI     │ Usuario ve formulario de login
  │ (Blazor WASM)    │
  └────┬─────────────┘
       │
       ↓ (3) POST /api/auth/oidc-form-login (Backend API:5000)

  ┌──────────────────┐
  │   Backend API    │ Valida credenciales
  │                  │ Crea cookie de sesión
  │                  │ Genera authorization code
  └────┬─────────────┘
       │
       ↓ (4) Redirect a App1 con code

  ┌─────────┐
  │  App1   │ Recibe code, intercambia por tokens
  └─────────┘

  ---
  ¿Por qué es importante que el Backend decida?

  1. El Backend tiene acceso a la cookie de sesión - Solo el backend puede verificar si hay una sesión activa (la
  cookie está configurada con HttpOnly en Program.cs:58)
  2. SSO funciona aquí - Cuando App2 llega al backend después de que iniciaste sesión en App1:
    - La cookie de sesión .IdentityServer.Auth se envía automáticamente
    - El backend detecta la sesión en AuthController.cs:60
    - Genera el código sin mostrar login
    - ¡SSO funciona! 🎉
  3. Validación centralizada - El backend valida:
    - client_id existe (AuthController.cs:53)
    - redirect_uri es válido (AuthController.cs:54)
    - scopes son permitidos (AuthController.cs:57-60)

  ---
  Confirmación en el código:

  Discovery document le dice a Blazor WASM dónde está el authorization endpoint:

  // DiscoveryController.cs:22-26
  var discoveryDocument = new
  {
      issuer = baseUrl,
      authorization_endpoint = $"{baseUrl}/api/auth/oidc-login", // ← Backend API
      token_endpoint = $"{baseUrl}/connect/token",
      // ...
  };

  Blazor WASM lo usa automáticamente:

  // SampleApp1/Program.cs:14-15
  options.ProviderOptions.Authority = "https://localhost:5000"; // Backend API
  options.ProviderOptions.MetadataUrl = "https://localhost:5000/.well-known/openid_configuration";

  Por lo tanto:
  - ✅ App1 va primero al Backend API (puerto 5000)
  - ✅ El Backend decide si redirigir al UI (puerto 7000) o generar código directamente
  - ✅ La cookie de sesión está en el Backend, por eso el Backend es quien sabe si hay sesión activa

  Perfecto resumen: "App1 → Backend → (¿hay sesión? NO → UI de Login | SÍ → código directo)"