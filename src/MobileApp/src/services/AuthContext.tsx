import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { AuthState, AuthTokens, UserInfo } from '../types/auth';
import { AuthService } from './AuthService';

interface AuthContextType extends AuthState {
  login: () => Promise<void>;
  logout: () => Promise<void>;
  getValidAccessToken: () => Promise<string | null>;
}

const AuthContext = createContext<AuthContextType | null>(null);

type AuthAction =
  | { type: 'LOADING' }
  | { type: 'LOGIN_SUCCESS'; tokens: AuthTokens; user: UserInfo }
  | { type: 'LOGOUT' }
  | { type: 'ERROR'; error: string }
  | { type: 'CLEAR_ERROR' };

const initialState: AuthState = {
  isAuthenticated: false,
  isLoading: true,
  error: undefined,
};

function authReducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case 'LOADING':
      return { ...state, isLoading: true, error: undefined };
    
    case 'LOGIN_SUCCESS':
      return {
        isAuthenticated: true,
        tokens: action.tokens,
        user: action.user,
        isLoading: false,
        error: undefined,
      };
    
    case 'LOGOUT':
      return {
        isAuthenticated: false,
        tokens: undefined,
        user: undefined,
        isLoading: false,
        error: undefined,
      };
    
    case 'ERROR':
      return {
        ...state,
        isLoading: false,
        error: action.error,
      };
    
    case 'CLEAR_ERROR':
      return {
        ...state,
        error: undefined,
      };
    
    default:
      return state;
  }
}

interface AuthProviderProps {
  children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [state, dispatch] = useReducer(authReducer, initialState);
  const authService = new AuthService();

  useEffect(() => {
    initializeAuth();
  }, []);

  const initializeAuth = async () => {
    try {
      console.log('[AuthContext] Initializing auth...');
      
      await authService.initialize();
      
      // Check for existing tokens
      const tokens = await authService.getStoredTokens();
      const userInfo = await authService.getStoredUserInfo();
      
      if (tokens && userInfo && !authService.isTokenExpired(tokens)) {
        console.log('[AuthContext] Found valid stored tokens');
        dispatch({ type: 'LOGIN_SUCCESS', tokens, user: userInfo });
      } else if (tokens && tokens.refreshToken) {
        console.log('[AuthContext] Attempting to refresh expired token');
        try {
          const newTokens = await authService.refreshTokens(tokens.refreshToken);
          if (userInfo) {
            dispatch({ type: 'LOGIN_SUCCESS', tokens: newTokens, user: userInfo });
          } else {
            dispatch({ type: 'LOGOUT' });
          }
        } catch (error) {
          console.log('[AuthContext] Token refresh failed, logging out');
          await authService.logout();
          dispatch({ type: 'LOGOUT' });
        }
      } else {
        console.log('[AuthContext] No valid tokens found');
        dispatch({ type: 'LOGOUT' });
      }
    } catch (error) {
      console.error('[AuthContext] Initialization failed:', error);
      dispatch({ type: 'ERROR', error: 'Failed to initialize authentication' });
    }
  };

  const login = async () => {
    try {
      dispatch({ type: 'LOADING' });
      console.log('[AuthContext] Starting login...');
      
      const tokens = await authService.login();
      const userInfo = await authService.getStoredUserInfo();
      
      if (userInfo) {
        dispatch({ type: 'LOGIN_SUCCESS', tokens, user: userInfo });
      } else {
        throw new Error('Failed to get user info after login');
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Login failed';
      console.error('[AuthContext] Login failed:', message);
      dispatch({ type: 'ERROR', error: message });
    }
  };

  const logout = async () => {
    try {
      console.log('[AuthContext] Logging out...');
      await authService.logout();
      dispatch({ type: 'LOGOUT' });
    } catch (error) {
      console.error('[AuthContext] Logout failed:', error);
      // Still dispatch logout to clear local state
      dispatch({ type: 'LOGOUT' });
    }
  };

  const getValidAccessToken = async (): Promise<string | null> => {
    return await authService.getValidAccessToken();
  };

  const contextValue: AuthContextType = {
    ...state,
    login,
    logout,
    getValidAccessToken,
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}