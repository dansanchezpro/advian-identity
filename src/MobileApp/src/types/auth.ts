export interface AuthTokens {
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  expiresAt: number;
}

export interface UserInfo {
  sub: string;
  email: string;
  name: string;
  given_name: string;
  family_name: string;
}

export interface AuthState {
  isAuthenticated: boolean;
  tokens?: AuthTokens;
  user?: UserInfo;
  isLoading: boolean;
  error?: string;
}

export interface OIDCConfig {
  authority: string;
  clientId: string;
  scopes: string[];
  redirectUri: string;
  additionalParameters?: Record<string, string>;
}