const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const AuthService = require('./src/services/AuthService');

let mainWindow = null;
let loginWindow = null;
let authService = null;

function createLoginWindow() {
  loginWindow = new BrowserWindow({
    width: 400,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    resizable: false,
    maximizable: false,
    show: false
  });

  loginWindow.loadFile(path.join(__dirname, 'public', 'login.html'));

  loginWindow.once('ready-to-show', () => {
    loginWindow.show();
  });

  loginWindow.on('closed', () => {
    loginWindow = null;
  });
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1000,
    height: 700,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    show: false
  });

  mainWindow.loadFile(path.join(__dirname, 'public', 'main.html'));

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (loginWindow) {
      loginWindow.close();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

async function checkExistingAuth() {
  try {
    const tokens = await authService.getStoredTokens();
    const userInfo = await authService.getStoredUserInfo();
    
    if (tokens && userInfo && !authService.isTokenExpired(tokens)) {
      console.log('[Main] Found valid stored authentication');
      createMainWindow();
      return true;
    } else if (tokens && tokens.refreshToken) {
      console.log('[Main] Attempting to refresh expired tokens');
      try {
        await authService.refreshTokens();
        createMainWindow();
        return true;
      } catch (error) {
        console.log('[Main] Refresh failed, showing login');
        await authService.logout();
        return false;
      }
    }
  } catch (error) {
    console.error('[Main] Error checking existing auth:', error);
  }
  return false;
}

app.whenReady().then(async () => {
  try {
    authService = new AuthService();
    await authService.initialize();
    console.log('[Main] AuthService initialized');

    const hasValidAuth = await checkExistingAuth();
    if (!hasValidAuth) {
      createLoginWindow();
    }
  } catch (error) {
    console.error('[Main] Failed to initialize AuthService:', error);
    createLoginWindow();
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      if (mainWindow) {
        createMainWindow();
      } else {
        createLoginWindow();
      }
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC handlers for authentication
ipcMain.handle('auth:login', async () => {
  try {
    console.log('[Main] Starting login process');
    
    const pkce = authService.generateCodeChallenge();
    const { authUrl, state, codeVerifier } = authService.buildAuthorizationUrl(pkce);
    
    // Store the code verifier and state for later use
    global.pendingAuth = { codeVerifier, state };
    
    // Open authorization URL in external browser
    await shell.openExternal(authUrl);
    
    return { success: true, message: 'Authorization URL opened in browser' };
  } catch (error) {
    console.error('[Main] Login error:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('auth:logout', async () => {
  try {
    console.log('[Main] Logging out');
    await authService.logout();
    
    if (mainWindow) {
      mainWindow.close();
      mainWindow = null;
    }
    
    createLoginWindow();
    return { success: true };
  } catch (error) {
    console.error('[Main] Logout error:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('auth:get-user-info', async () => {
  try {
    const userInfo = await authService.getStoredUserInfo();
    return { success: true, data: userInfo };
  } catch (error) {
    console.error('[Main] Get user info error:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('auth:get-tokens', async () => {
  try {
    const tokens = await authService.getStoredTokens();
    if (!tokens) {
      return { success: false, error: 'No tokens found' };
    }
    
    return { 
      success: true, 
      data: {
        expiresAt: tokens.expiresAt,
        isExpired: authService.isTokenExpired(tokens),
        timeRemaining: Math.max(0, tokens.expiresAt - Date.now())
      }
    };
  } catch (error) {
    console.error('[Main] Get tokens error:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('auth:call-api', async (event, endpoint, method = 'GET', body = null) => {
  try {
    const result = await authService.callProtectedApi(endpoint, method, body);
    return { success: true, data: result };
  } catch (error) {
    console.error('[Main] API call error:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('auth:refresh-tokens', async () => {
  try {
    const newTokens = await authService.refreshTokens();
    return { success: true, data: newTokens };
  } catch (error) {
    console.error('[Main] Refresh tokens error:', error);
    return { success: false, error: error.message };
  }
});

// Handle custom protocol for OAuth callback
app.setAsDefaultProtocolClient('desktopapp');

app.on('second-instance', (event, commandLine, workingDirectory) => {
  // Handle the callback URL from the second instance
  handleAuthCallback(commandLine);
});

app.on('open-url', (event, url) => {
  // Handle the callback URL on macOS
  handleAuthCallback([url]);
});

function handleAuthCallback(commandLine) {
  const callbackUrl = commandLine.find(arg => arg.startsWith('desktopapp://'));
  if (callbackUrl && global.pendingAuth) {
    console.log('[Main] Received auth callback:', callbackUrl);
    
    const url = new URL(callbackUrl);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const error = url.searchParams.get('error');
    
    if (error) {
      console.error('[Main] Auth callback error:', error);
      if (loginWindow) {
        loginWindow.webContents.send('auth:callback-error', error);
      }
      return;
    }
    
    if (code && state === global.pendingAuth.state) {
      handleAuthCode(code, global.pendingAuth.codeVerifier);
    } else {
      console.error('[Main] Invalid auth callback - missing code or state mismatch');
    }
    
    global.pendingAuth = null;
  }
}

async function handleAuthCode(code, codeVerifier) {
  try {
    console.log('[Main] Processing authorization code');
    
    const { tokens, userInfo } = await authService.exchangeCodeForTokens(code, codeVerifier);
    
    console.log('[Main] Authentication successful');
    createMainWindow();
    
  } catch (error) {
    console.error('[Main] Auth code processing error:', error);
    if (loginWindow) {
      loginWindow.webContents.send('auth:callback-error', error.message);
    }
  }
}