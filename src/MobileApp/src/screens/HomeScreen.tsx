import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  Alert,
  RefreshControl,
  ActivityIndicator,
} from 'react-native';
import { useAuth } from '../services/AuthContext';

interface ApiResponse {
  message: string;
  timestamp: string;
  server?: string;
  user?: {
    id: string;
    email: string;
    name: string;
  };
  token?: {
    time_remaining?: string;
    seconds_remaining?: number;
    is_expired?: boolean;
  };
}

export function HomeScreen() {
  const { user, logout, getValidAccessToken } = useAuth();
  const [apiResponse, setApiResponse] = useState<ApiResponse | null>(null);
  const [isLoadingApi, setIsLoadingApi] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    // Load initial data
    callTokenInfo();
  }, []);

  const callApi = async (endpoint: string, method: 'GET' | 'POST' = 'GET', body?: any) => {
    setIsLoadingApi(true);
    try {
      const accessToken = await getValidAccessToken();
      if (!accessToken) {
        Alert.alert('Error', 'No valid access token available');
        return;
      }

      const response = await fetch(`https://localhost:6001/api/api/${endpoint}`, {
        method,
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: body ? JSON.stringify(body) : undefined,
      });

      const data = await response.json();
      setApiResponse(data);

      if (!response.ok) {
        Alert.alert('API Error', data.message || `HTTP ${response.status}`);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'API call failed';
      Alert.alert('Network Error', message);
      console.error('[HomeScreen] API call failed:', error);
    } finally {
      setIsLoadingApi(false);
    }
  };

  const callPublicEndpoint = () => callApi('public');
  const callProtectedEndpoint = () => callApi('protected');
  const callUserInfo = () => callApi('user-info');
  const callWeather = () => callApi('weather');
  const callTokenInfo = () => callApi('token-info');
  const testRefreshToken = () => callApi('test-refresh', 'POST', {
    testData: 'Mobile app refresh test',
    requestTime: new Date().toISOString()
  });

  const handleLogout = async () => {
    Alert.alert(
      'Logout',
      'Are you sure you want to sign out?',
      [
        { text: 'Cancel', style: 'cancel' },
        { 
          text: 'Logout', 
          style: 'destructive',
          onPress: async () => {
            try {
              await logout();
            } catch (error) {
              console.error('Logout error:', error);
            }
          }
        },
      ]
    );
  };

  const onRefresh = async () => {
    setRefreshing(true);
    await callTokenInfo();
    setRefreshing(false);
  };

  return (
    <ScrollView 
      style={styles.container}
      refreshControl={
        <RefreshControl refreshing={refreshing} onRefresh={onRefresh} />
      }
    >
      <View style={styles.header}>
        <View style={styles.welcomeContainer}>
          <Text style={styles.welcomeText}>Welcome back!</Text>
          <Text style={styles.userEmail}>{user?.email}</Text>
          <Text style={styles.userName}>{user?.name}</Text>
        </View>
        
        <TouchableOpacity style={styles.logoutButton} onPress={handleLogout}>
          <Text style={styles.logoutButtonText}>Logout</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>🛡️ Protected API Testing</Text>
        <Text style={styles.sectionSubtitle}>
          Test endpoints from SampleBack1 API (localhost:6001)
        </Text>
      </View>

      <View style={styles.buttonContainer}>
        <TouchableOpacity 
          style={[styles.apiButton, styles.successButton]} 
          onPress={callPublicEndpoint}
          disabled={isLoadingApi}
        >
          <Text style={styles.buttonText}>📭 Call Public Endpoint</Text>
        </TouchableOpacity>

        <TouchableOpacity 
          style={[styles.apiButton, styles.primaryButton]} 
          onPress={callProtectedEndpoint}
          disabled={isLoadingApi}
        >
          <Text style={styles.buttonText}>🔒 Call Protected Endpoint</Text>
        </TouchableOpacity>

        <TouchableOpacity 
          style={[styles.apiButton, styles.infoButton]} 
          onPress={callUserInfo}
          disabled={isLoadingApi}
        >
          <Text style={styles.buttonText}>👤 Get User Info</Text>
        </TouchableOpacity>

        <TouchableOpacity 
          style={[styles.apiButton, styles.warningButton]} 
          onPress={callWeather}
          disabled={isLoadingApi}
        >
          <Text style={styles.buttonText}>🌤️ Get Weather Data</Text>
        </TouchableOpacity>

        <TouchableOpacity 
          style={[styles.apiButton, styles.secondaryButton]} 
          onPress={testRefreshToken}
          disabled={isLoadingApi}
        >
          <Text style={styles.buttonText}>🔄 Test Refresh Token</Text>
        </TouchableOpacity>

        <TouchableOpacity 
          style={[styles.apiButton, styles.outlineButton]} 
          onPress={callTokenInfo}
          disabled={isLoadingApi}
        >
          <Text style={[styles.buttonText, styles.outlineButtonText]}>⏰ Check Token Expiry</Text>
        </TouchableOpacity>
      </View>

      {isLoadingApi && (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color="#007BFF" />
          <Text style={styles.loadingText}>Calling API...</Text>
        </View>
      )}

      {apiResponse && (
        <View style={styles.responseContainer}>
          <Text style={styles.responseTitle}>API Response:</Text>
          <ScrollView style={styles.responseScrollView} nestedScrollEnabled>
            <Text style={styles.responseText}>
              {JSON.stringify(apiResponse, null, 2)}
            </Text>
          </ScrollView>
        </View>
      )}

      <View style={styles.infoSection}>
        <Text style={styles.infoTitle}>ℹ️ How to Test Refresh Tokens</Text>
        <Text style={styles.infoText}>
          1. Access tokens expire in 5 minutes{'\n'}
          2. Use "Check Token Expiry" to monitor countdown{'\n'}
          3. Wait for token to expire{'\n'}
          4. Call any protected endpoint{'\n'}
          5. App will automatically refresh token and retry{'\n'}
          6. Check token expiry again to see new 5-minute timer
        </Text>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#F8F9FA',
  },
  header: {
    backgroundColor: '#007BFF',
    padding: 20,
    paddingTop: 60,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
  },
  welcomeContainer: {
    flex: 1,
  },
  welcomeText: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#FFFFFF',
    marginBottom: 5,
  },
  userEmail: {
    fontSize: 16,
    color: '#E3F2FD',
    marginBottom: 2,
  },
  userName: {
    fontSize: 14,
    color: '#BBDEFB',
  },
  logoutButton: {
    backgroundColor: 'rgba(255, 255, 255, 0.2)',
    paddingVertical: 8,
    paddingHorizontal: 16,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: 'rgba(255, 255, 255, 0.3)',
  },
  logoutButtonText: {
    color: '#FFFFFF',
    fontSize: 14,
    fontWeight: '600',
  },
  section: {
    padding: 20,
    paddingBottom: 10,
  },
  sectionTitle: {
    fontSize: 20,
    fontWeight: 'bold',
    color: '#212529',
    marginBottom: 5,
  },
  sectionSubtitle: {
    fontSize: 14,
    color: '#6C757D',
  },
  buttonContainer: {
    padding: 20,
    paddingTop: 10,
  },
  apiButton: {
    paddingVertical: 15,
    paddingHorizontal: 20,
    borderRadius: 8,
    marginBottom: 10,
    alignItems: 'center',
  },
  primaryButton: {
    backgroundColor: '#007BFF',
  },
  successButton: {
    backgroundColor: '#28A745',
  },
  infoButton: {
    backgroundColor: '#17A2B8',
  },
  warningButton: {
    backgroundColor: '#FFC107',
  },
  secondaryButton: {
    backgroundColor: '#6C757D',
  },
  outlineButton: {
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: '#007BFF',
  },
  buttonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: '600',
  },
  outlineButtonText: {
    color: '#007BFF',
  },
  loadingContainer: {
    alignItems: 'center',
    padding: 20,
  },
  loadingText: {
    marginTop: 10,
    fontSize: 16,
    color: '#6C757D',
  },
  responseContainer: {
    margin: 20,
    backgroundColor: '#FFFFFF',
    borderRadius: 8,
    elevation: 2,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
  },
  responseTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#212529',
    padding: 15,
    paddingBottom: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#E9ECEF',
  },
  responseScrollView: {
    maxHeight: 300,
  },
  responseText: {
    fontFamily: 'monospace',
    fontSize: 12,
    color: '#495057',
    padding: 15,
    lineHeight: 18,
  },
  infoSection: {
    margin: 20,
    padding: 15,
    backgroundColor: '#D1ECF1',
    borderRadius: 8,
    borderLeftWidth: 4,
    borderLeftColor: '#17A2B8',
  },
  infoTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#0C5460',
    marginBottom: 10,
  },
  infoText: {
    fontSize: 14,
    color: '#0C5460',
    lineHeight: 20,
  },
});