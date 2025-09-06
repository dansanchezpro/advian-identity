import { makeRedirectUri } from 'expo-auth-session';
import * as AuthSession from 'expo-auth-session';
import * as WebBrowser from 'expo-web-browser';
import * as SecureStore from 'expo-secure-store';
import { AuthTokens, UserInfo, OIDCConfig } from '../types/auth';

WebBrowser.maybeCompleteAuthSession();

const STORAGE_KEYS = {
  ACCESS_TOKEN: 'access_token',
  ID_TOKEN: 'id_token', 
  REFRESH_TOKEN: 'refresh_token',
  EXPIRES_AT: 'expires_at',
  USER_INFO: 'user_info'
};

export class AuthService {
  private config: OIDCConfig;
  private discovery?: AuthSession.DiscoveryDocument;

  constructor() {
    this.config = {
      authority: 'https://localhost:5000',
      clientId: 'mobileapp',
      scopes: ['openid', 'profile', 'email', 'offline_access'],
      redirectUri: makeRedirectUri({
        scheme: 'mobileapp',
        path: 'auth'
      })
    };
  }

  async initialize(): Promise<void> {
    console.log('[AuthService] Initializing...');
    console.log('[AuthService] Redirect URI:', this.config.redirectUri);
    
    try {
      this.discovery = await AuthSession.fetchDiscoveryAsync(this.config.authority);
      console.log('[AuthService] Discovery loaded:', this.discovery.authorizationEndpoint);
    } catch (error) {
      console.error('[AuthService] Failed to load discovery:', error);
      throw new Error('Failed to initialize auth service');
    }
  }

  async login(): Promise<AuthTokens> {
    if (!this.discovery) {
      throw new Error('Auth service not initialized');
    }

    console.log('[AuthService] Starting login flow...');

    const request = new AuthSession.AuthRequest({
      clientId: this.config.clientId,
      scopes: this.config.scopes,
      redirectUri: this.config.redirectUri,
      responseType: AuthSession.ResponseType.Code,
      codeChallenge: await AuthSession.AuthRequest.createRandomCodeChallenge(),
      state: AuthSession.AuthRequest.createRandomState(),
      additionalParameters: this.config.additionalParameters || {},
    });

    const result = await request.promptAsync(this.discovery);

    if (result.type !== 'success') {
      console.error('[AuthService] Auth failed:', result);
      throw new Error(`Authentication failed: ${result.type}`);
    }

    console.log('[AuthService] Authorization code received');

    // Exchange code for tokens
    const tokens = await this.exchangeCodeForTokens(result.params.code, request);
    
    // Store tokens securely
    await this.storeTokens(tokens);
    
    // Fetch user info
    const userInfo = await this.fetchUserInfo(tokens.accessToken);
    await this.storeUserInfo(userInfo);

    console.log('[AuthService] Login successful');
    return tokens;
  }

  private async exchangeCodeForTokens(code: string, request: AuthSession.AuthRequest): Promise<AuthTokens> {
    if (!this.discovery?.tokenEndpoint) {
      throw new Error('Token endpoint not found');
    }

    console.log('[AuthService] Exchanging code for tokens...');

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      code_verifier: request.codeVerifier!,
    });

    const response = await fetch(this.discovery.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      console.error('[AuthService] Token exchange failed:', error);
      throw new Error('Failed to exchange code for tokens');
    }

    const tokenData = await response.json();
    
    const expiresAt = Date.now() + (tokenData.expires_in * 1000);
    
    return {
      accessToken: tokenData.access_token,
      idToken: tokenData.id_token,
      refreshToken: tokenData.refresh_token,
      expiresAt
    };
  }

  async refreshTokens(refreshToken: string): Promise<AuthTokens> {
    if (!this.discovery?.tokenEndpoint) {
      throw new Error('Token endpoint not found');
    }

    console.log('[AuthService] Refreshing tokens...');

    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this.config.clientId,
    });

    const response = await fetch(this.discovery.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      console.error('[AuthService] Token refresh failed:', error);
      throw new Error('Failed to refresh tokens');
    }

    const tokenData = await response.json();
    
    const expiresAt = Date.now() + (tokenData.expires_in * 1000);
    
    const newTokens = {
      accessToken: tokenData.access_token,
      idToken: tokenData.id_token,
      refreshToken: tokenData.refresh_token || refreshToken, // Use new refresh token if provided
      expiresAt
    };

    await this.storeTokens(newTokens);
    console.log('[AuthService] Tokens refreshed successfully');
    
    return newTokens;
  }

  private async fetchUserInfo(accessToken: string): Promise<UserInfo> {
    if (!this.discovery?.userInfoEndpoint) {
      throw new Error('UserInfo endpoint not found');
    }

    console.log('[AuthService] Fetching user info...');

    const response = await fetch(this.discovery.userInfoEndpoint, {
      headers: {
        'Authorization': `Bearer ${accessToken}`,
      },
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user info');
    }

    return await response.json();
  }

  async getStoredTokens(): Promise<AuthTokens | null> {
    try {
      const accessToken = await SecureStore.getItemAsync(STORAGE_KEYS.ACCESS_TOKEN);
      const idToken = await SecureStore.getItemAsync(STORAGE_KEYS.ID_TOKEN);
      const refreshToken = await SecureStore.getItemAsync(STORAGE_KEYS.REFRESH_TOKEN);
      const expiresAtStr = await SecureStore.getItemAsync(STORAGE_KEYS.EXPIRES_AT);

      if (!accessToken || !idToken || !expiresAtStr) {
        return null;
      }

      return {
        accessToken,
        idToken,
        refreshToken: refreshToken || undefined,
        expiresAt: parseInt(expiresAtStr)
      };
    } catch (error) {
      console.error('[AuthService] Failed to get stored tokens:', error);
      return null;
    }
  }

  async getStoredUserInfo(): Promise<UserInfo | null> {
    try {
      const userInfoStr = await SecureStore.getItemAsync(STORAGE_KEYS.USER_INFO);
      return userInfoStr ? JSON.parse(userInfoStr) : null;
    } catch (error) {
      console.error('[AuthService] Failed to get stored user info:', error);
      return null;
    }
  }

  private async storeTokens(tokens: AuthTokens): Promise<void> {
    await SecureStore.setItemAsync(STORAGE_KEYS.ACCESS_TOKEN, tokens.accessToken);
    await SecureStore.setItemAsync(STORAGE_KEYS.ID_TOKEN, tokens.idToken);
    await SecureStore.setItemAsync(STORAGE_KEYS.EXPIRES_AT, tokens.expiresAt.toString());
    
    if (tokens.refreshToken) {
      await SecureStore.setItemAsync(STORAGE_KEYS.REFRESH_TOKEN, tokens.refreshToken);
    }
  }

  private async storeUserInfo(userInfo: UserInfo): Promise<void> {
    await SecureStore.setItemAsync(STORAGE_KEYS.USER_INFO, JSON.stringify(userInfo));
  }

  async logout(): Promise<void> {
    console.log('[AuthService] Logging out...');
    
    // Clear stored tokens and user info
    await Promise.all([
      SecureStore.deleteItemAsync(STORAGE_KEYS.ACCESS_TOKEN),
      SecureStore.deleteItemAsync(STORAGE_KEYS.ID_TOKEN), 
      SecureStore.deleteItemAsync(STORAGE_KEYS.REFRESH_TOKEN),
      SecureStore.deleteItemAsync(STORAGE_KEYS.EXPIRES_AT),
      SecureStore.deleteItemAsync(STORAGE_KEYS.USER_INFO)
    ]);
  }

  isTokenExpired(tokens: AuthTokens): boolean {
    // Add 60 second buffer for network delay
    return Date.now() >= (tokens.expiresAt - 60000);
  }

  async getValidAccessToken(): Promise<string | null> {
    const tokens = await this.getStoredTokens();
    
    if (!tokens) {
      return null;
    }

    if (this.isTokenExpired(tokens) && tokens.refreshToken) {
      try {
        const newTokens = await this.refreshTokens(tokens.refreshToken);
        return newTokens.accessToken;
      } catch (error) {
        console.error('[AuthService] Failed to refresh token:', error);
        await this.logout(); // Clear invalid tokens
        return null;
      }
    }

    return tokens.accessToken;
  }
}