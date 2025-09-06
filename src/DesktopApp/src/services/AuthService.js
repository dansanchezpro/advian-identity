const axios = require('axios');
const keytar = require('keytar');
const crypto = require('crypto');
const { URLSearchParams } = require('url');

class AuthService {
  constructor() {
    this.serviceName = 'IdentityServerDesktopApp';
    this.config = {
      authority: 'http://localhost:5001',
      clientId: 'desktopapp',
      scopes: ['openid', 'profile', 'email', 'offline_access'],
      redirectUri: 'http://localhost:8080/callback'
    };
    this.discovery = null;
    
    // Disable SSL verification for localhost development
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }

  async initialize() {
    console.log('[AuthService] Initializing...');
    
    try {
      const response = await axios.get(`${this.config.authority}/.well-known/openid_configuration`);
      this.discovery = response.data;
      console.log('[AuthService] Discovery loaded:', this.discovery.authorization_endpoint);
    } catch (error) {
      console.error('[AuthService] Failed to load discovery:', error.message);
      throw new Error('Failed to initialize auth service');
    }
  }

  generateCodeChallenge() {
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    
    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256'
    };
  }

  buildAuthorizationUrl(pkce) {
    if (!this.discovery) {
      throw new Error('Auth service not initialized');
    }

    const state = crypto.randomBytes(16).toString('hex');
    
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scopes.join(' '),
      state: state,
      code_challenge: pkce.codeChallenge,
      code_challenge_method: pkce.codeChallengeMethod
    });

    const authUrl = `${this.discovery.authorization_endpoint}?${params.toString()}`;
    
    return {
      authUrl,
      state,
      codeVerifier: pkce.codeVerifier
    };
  }

  async exchangeCodeForTokens(code, codeVerifier) {
    if (!this.discovery?.token_endpoint) {
      throw new Error('Token endpoint not found');
    }

    console.log('[AuthService] Exchanging code for tokens...');

    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      code_verifier: codeVerifier,
    });

    try {
      const response = await axios.post(this.discovery.token_endpoint, params.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });

      const tokenData = response.data;
      const expiresAt = Date.now() + (tokenData.expires_in * 1000);
      
      const tokens = {
        accessToken: tokenData.access_token,
        idToken: tokenData.id_token,
        refreshToken: tokenData.refresh_token,
        expiresAt: expiresAt
      };

      // Store tokens securely
      await this.storeTokens(tokens);
      
      // Fetch and store user info
      const userInfo = await this.fetchUserInfo(tokens.accessToken);
      await this.storeUserInfo(userInfo);

      console.log('[AuthService] Tokens stored successfully');
      return { tokens, userInfo };
    } catch (error) {
      console.error('[AuthService] Token exchange failed:', error.response?.data || error.message);
      throw new Error('Failed to exchange code for tokens');
    }
  }

  async refreshTokens() {
    console.log('[AuthService] Refreshing tokens...');
    
    const storedRefreshToken = await keytar.getPassword(this.serviceName, 'refresh_token');
    if (!storedRefreshToken) {
      throw new Error('No refresh token available');
    }

    if (!this.discovery?.token_endpoint) {
      throw new Error('Token endpoint not found');
    }

    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: storedRefreshToken,
      client_id: this.config.clientId,
    });

    try {
      const response = await axios.post(this.discovery.token_endpoint, params.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      });

      const tokenData = response.data;
      const expiresAt = Date.now() + (tokenData.expires_in * 1000);
      
      const newTokens = {
        accessToken: tokenData.access_token,
        idToken: tokenData.id_token,
        refreshToken: tokenData.refresh_token || storedRefreshToken,
        expiresAt: expiresAt
      };

      await this.storeTokens(newTokens);
      console.log('[AuthService] Tokens refreshed successfully');
      
      return newTokens;
    } catch (error) {
      console.error('[AuthService] Token refresh failed:', error.response?.data || error.message);
      throw new Error('Failed to refresh tokens');
    }
  }

  async fetchUserInfo(accessToken) {
    if (!this.discovery?.userinfo_endpoint) {
      throw new Error('UserInfo endpoint not found');
    }

    console.log('[AuthService] Fetching user info...');

    try {
      const response = await axios.get(this.discovery.userinfo_endpoint, {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      return response.data;
    } catch (error) {
      console.error('[AuthService] Failed to fetch user info:', error.message);
      throw new Error('Failed to fetch user info');
    }
  }

  async storeTokens(tokens) {
    await keytar.setPassword(this.serviceName, 'access_token', tokens.accessToken);
    await keytar.setPassword(this.serviceName, 'id_token', tokens.idToken);
    await keytar.setPassword(this.serviceName, 'expires_at', tokens.expiresAt.toString());
    
    if (tokens.refreshToken) {
      await keytar.setPassword(this.serviceName, 'refresh_token', tokens.refreshToken);
    }
  }

  async storeUserInfo(userInfo) {
    await keytar.setPassword(this.serviceName, 'user_info', JSON.stringify(userInfo));
  }

  async getStoredTokens() {
    try {
      const accessToken = await keytar.getPassword(this.serviceName, 'access_token');
      const idToken = await keytar.getPassword(this.serviceName, 'id_token');
      const refreshToken = await keytar.getPassword(this.serviceName, 'refresh_token');
      const expiresAtStr = await keytar.getPassword(this.serviceName, 'expires_at');

      if (!accessToken || !idToken || !expiresAtStr) {
        return null;
      }

      return {
        accessToken,
        idToken,
        refreshToken,
        expiresAt: parseInt(expiresAtStr)
      };
    } catch (error) {
      console.error('[AuthService] Failed to get stored tokens:', error);
      return null;
    }
  }

  async getStoredUserInfo() {
    try {
      const userInfoStr = await keytar.getPassword(this.serviceName, 'user_info');
      return userInfoStr ? JSON.parse(userInfoStr) : null;
    } catch (error) {
      console.error('[AuthService] Failed to get stored user info:', error);
      return null;
    }
  }

  async logout() {
    console.log('[AuthService] Logging out...');
    
    // Clear stored tokens and user info
    await keytar.deletePassword(this.serviceName, 'access_token');
    await keytar.deletePassword(this.serviceName, 'id_token');
    await keytar.deletePassword(this.serviceName, 'refresh_token');
    await keytar.deletePassword(this.serviceName, 'expires_at');
    await keytar.deletePassword(this.serviceName, 'user_info');
  }

  isTokenExpired(tokens) {
    // Add 60 second buffer for network delay
    return Date.now() >= (tokens.expiresAt - 60000);
  }

  async getValidAccessToken() {
    const tokens = await this.getStoredTokens();
    
    if (!tokens) {
      return null;
    }

    if (this.isTokenExpired(tokens) && tokens.refreshToken) {
      try {
        const newTokens = await this.refreshTokens();
        return newTokens.accessToken;
      } catch (error) {
        console.error('[AuthService] Failed to refresh token:', error);
        await this.logout(); // Clear invalid tokens
        return null;
      }
    }

    return tokens.accessToken;
  }

  async callProtectedApi(endpoint, method = 'GET', body = null) {
    const accessToken = await this.getValidAccessToken();
    if (!accessToken) {
      throw new Error('No valid access token available');
    }

    const config = {
      method,
      url: `https://localhost:6001/api/${endpoint}`,
      headers: {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    };

    if (body && method !== 'GET') {
      config.data = body;
    }

    try {
      const response = await axios(config);
      return response.data;
    } catch (error) {
      console.error(`[AuthService] API call to ${endpoint} failed:`, error.response?.data || error.message);
      throw error;
    }
  }
}

module.exports = AuthService;