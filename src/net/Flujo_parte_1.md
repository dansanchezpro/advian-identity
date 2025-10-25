  Análisis del Flujo de Autenticación SSO

  Basándome en el código revisado, aquí está el flujo de autenticación que han implementado. Es un Authorization
  Code Flow con PKCE siguiendo el estándar OpenID Connect (OIDC):

  Arquitectura:

  1. IdentityServer.Api (puerto 5000) - Backend OAuth/OIDC
  2. IdentityServer.Web (puerto 7000) - UI de Login/Registro (Blazor WASM)
  3. SampleApp1/2/3 (puertos 7001/7002/7003) - Aplicaciones cliente (Blazor WASM)

  ---
  Flujo Detallado:

  1. Usuario hace clic en "Login" en App1

  Ubicación: SampleApp1/Pages/Home.razor:25

  <a href="authentication/login" class="btn btn-light">Login</a>

  2. Blazor WASM inicia el flujo OIDC

  Ubicación: SampleApp1/Program.cs:11-38

  - El componente RemoteAuthenticatorView (línea SampleApp1/Pages/Authentication.razor:4) maneja automáticamente la
  autenticación
  - Blazor genera una petición de autorización a la Authority configurada (https://localhost:5000)
  - Se utiliza el Authorization Code Flow con PKCE:
    - response_type=code
    - Se genera un code_verifier aleatorio
    - Se calcula el code_challenge usando SHA256
    - code_challenge_method=S256

  3. Redirección al Authorization Endpoint

  El usuario es redirigido a:
  GET https://localhost:5000/api/auth/oidc-login?
      client_id=sampleapp1&
      redirect_uri=https://localhost:7001/authentication/login-callback&
      response_type=code&
      scope=openid profile email offline_access&
      state=<random>&
      code_challenge=<hash>&
      code_challenge_method=S256

  Ubicación: IdentityServer.Api/Controllers/DiscoveryController.cs:25 (discovery define el endpoint)
  Handler: IdentityServer.Api/Controllers/AuthController.cs:32-113 (método OidcLogin)

  4. Validación y redirección al Login UI

  Ubicación: AuthController.cs:42-112

  El API valida:
  - Que el client_id existe (AuthController.cs:53)
  - Que el redirect_uri es válido para ese cliente (AuthController.cs:54)
  - Que los scopes son permitidos (AuthController.cs:57-60)

  Verifica sesión existente:
  - Si hay una cookie de autenticación válida (.NET Authentication Cookie), genera el código directamente
  (AuthController.cs:60-78)
  - Si hay un id_token_hint válido, genera el código directamente (AuthController.cs:84-114)
  - Si prompt=none, retorna error login_required (AuthController.cs:82-89)

  Si no hay sesión: Redirige al Identity UI (Blazor):
  GET https://localhost:7000/login?
      client_id=sampleapp1&
      redirect_uri=...&
      response_type=code&
      scope=...&
      state=...&
      code_challenge=...&
      code_challenge_method=S256

  Ubicación: AuthController.cs:92-112

  5. Usuario completa el Login en Identity UI

  Ubicación: IdentityServer.Web/Pages/Login.razor

  El usuario tiene dos opciones:

  A. Login con Email/Password:
  - Formulario en Login.razor:27-52
  - Al enviar, se ejecuta HandleOidcFormSubmission() (Login.razor:451-486)
  - Se envía un POST a: https://localhost:5000/api/auth/oidc-form-login (Login.razor:474)
  - Handler: AuthController.cs:152-185 (método OidcFormLogin)

  B. Login con Google:
  - Botón en Login.razor:61-69
  - Se ejecuta HandleGoogleLogin() → HandleExternalLogin("Google") (Login.razor:506-509)
  - Redirige a: https://localhost:5000/api/auth/external/google?returnUrl=... (Login.razor:496)
  - Handler: AuthController.cs:187-238 (método ExternalLogin)
  - Redirige a Google OAuth: https://accounts.google.com/o/oauth2/v2/auth?... (AuthController.cs:207-213)
  - Google callback: https://localhost:5000/api/auth/external-callback (AuthController.cs:241-434)

  6. API valida credenciales y crea sesión

  Para Email/Password (AuthController.cs:152-185):
  1. Valida credenciales con UserService.ValidateCredentialsAsync() (AuthController.cs:155)
  2. Crea claims del usuario (AuthController.cs:161-168)
  3. Crea cookie de sesión .NET usando CookieAuthenticationDefaults (AuthController.cs:171-174)
  4. Genera el authorization code usando TokenService.GenerateAuthorizationCodeAsync() (AuthController.cs:176-178)
  5. Redirige a la app con el código: https://localhost:7001/authentication/login-callback?code=<code>&state=<state>
   (AuthController.cs:180-184)

  Para Google (AuthController.cs:241-434):
  1. Intercambia el código de Google por access_token (AuthController.cs:264)
  2. Obtiene información del usuario de Google (AuthController.cs:272)
  3. Busca/vincula el usuario en la BD (AuthController.cs:288-368)
  4. Crea cookie de sesión .NET (AuthController.cs:371-384)
  5. Genera authorization code (AuthController.cs:414-416)
  6. Redirige con el código (AuthController.cs:419-424)

  7. App1 intercambia el código por tokens

  Ubicación: Blazor WASM automático via RemoteAuthenticatorView

  La app hace un POST al token endpoint:
  POST https://localhost:5000/connect/token
  Content-Type: application/x-www-form-urlencoded

  grant_type=authorization_code&
  code=<authorization_code>&
  redirect_uri=https://localhost:7001/authentication/login-callback&
  client_id=sampleapp1&
  client_secret=<secret>&
  code_verifier=<original_verifier>

  Handler: IdentityServer.Api/Controllers/OAuthController.cs:154-189 (método Token)

  8. API valida y retorna tokens

  Ubicación: OAuthController.cs:191-274 (método HandleAuthorizationCodeGrant)

  El API:
  1. Valida el authorization code (OAuthController.cs:199)
  2. Valida el code_verifier contra el code_challenge almacenado (PKCE validation)
  3. Valida que el redirect_uri coincida (OAuthController.cs:207)
  4. Busca el usuario (OAuthController.cs:213)
  5. Genera los tokens JWT usando RSA256 (OAuthController.cs:231-240):
    - access_token - JWT firmado con RS256, contiene claims del usuario
    - id_token - JWT firmado con RS256, contiene identidad OIDC
    - refresh_token - Si se solicitó scope offline_access (OAuthController.cs:252-256)

  Respuesta:
  {
    "access_token": "eyJhbGc...",
    "id_token": "eyJhbGc...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "openid profile email",
    "refresh_token": "..." // opcional
  }

  Ubicación: OAuthController.cs:258-273

  9. App1 almacena tokens y completa el login

  Blazor WASM:
  - Almacena los tokens en sessionStorage o localStorage
  - Actualiza el AuthenticationState
  - El usuario ve su información en Home.razor:14-29
  - Los claims se muestran en Home.razor:42-50

  10. SSO - Usuario navega a App2

  Cuando el usuario abre https://localhost:7002:

  1. App2 inicia el mismo flujo OIDC
  2. Llega a /api/auth/oidc-login (AuthController.cs:32)
  3. Detecta la cookie de sesión existente (AuthController.cs:60-78)
  4. Como ya está autenticado, genera el código directamente sin mostrar login
  5. Redirige automáticamente con el código a App2
  6. App2 intercambia el código por tokens
  7. El usuario está autenticado sin volver a escribir credenciales ✅

  ---
  Características Importantes:

  1. PKCE (Proof Key for Code Exchange): Protección contra ataques de intercepción de código
    - code_challenge y code_verifier (OAuthController.cs:38-39, 195)
  2. Cookies de sesión compartidas:
    - Cookie domain: .localhost (Program.cs:61)
    - Permite SSO entre puertos
    - Configuración: Program.cs:50-62
  3. Refresh Tokens: Para renovar access tokens sin reautenticación
    - Handler: OAuthController.cs:276-341
  4. RSA256 firma de JWT: Tokens firmados criptográficamente
    - Servicio: IRsaKeyService
    - JWKS endpoint: /.well-known/jwks (DiscoveryController.cs:61-72)
  5. Discovery Document: OIDC metadata estándar
    - Endpoint: /.well-known/openid_configuration (DiscoveryController.cs:15-59)

  ---
  Flujo Resumido:

  App1 → Authorization Endpoint → Identity UI → Login (Google/Email)
    ↓
  Cookie de sesión creada (.NET Authentication)
    ↓
  Authorization Code generado → App1
    ↓
  Token Exchange → Access Token + ID Token + Refresh Token
    ↓
  Usuario autenticado en App1
    ↓
  Usuario abre App2 → Authorization Endpoint detecta cookie
    ↓
  Authorization Code generado automáticamente → App2
    ↓
  Token Exchange → Tokens para App2
    ↓
  SSO completo ✅

  Este es un flujo Authorization Code Flow con PKCE completamente compatible con OpenID Connect, con SSO basado en
  cookies compartidas entre aplicaciones.