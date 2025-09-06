import React from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Alert,
  ActivityIndicator,
  Image,
} from 'react-native';
import { useAuth } from '../services/AuthContext';

export function LoginScreen() {
  const { login, isLoading, error } = useAuth();

  const handleLogin = async () => {
    try {
      await login();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Login failed';
      Alert.alert('Login Error', message);
    }
  };

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <View style={styles.logoContainer}>
          <Text style={styles.logoText}>🔐</Text>
        </View>
        <Text style={styles.title}>Identity Server</Text>
        <Text style={styles.subtitle}>Mobile App</Text>
      </View>

      <View style={styles.content}>
        <View style={styles.description}>
          <Text style={styles.descriptionText}>
            Secure authentication powered by your custom Identity Server
          </Text>
          <Text style={styles.featuresText}>
            • Single Sign-On (SSO){'\n'}
            • Refresh Token Support{'\n'}
            • OAuth2 / OIDC Standards{'\n'}
            • Secure Token Storage
          </Text>
        </View>

        {error && (
          <View style={styles.errorContainer}>
            <Text style={styles.errorText}>❌ {error}</Text>
          </View>
        )}

        <TouchableOpacity
          style={[styles.loginButton, isLoading && styles.loginButtonDisabled]}
          onPress={handleLogin}
          disabled={isLoading}
        >
          {isLoading ? (
            <View style={styles.loadingContainer}>
              <ActivityIndicator size="small" color="#FFFFFF" />
              <Text style={styles.loginButtonText}>Connecting...</Text>
            </View>
          ) : (
            <Text style={styles.loginButtonText}>Sign In with Identity Server</Text>
          )}
        </TouchableOpacity>

        <View style={styles.infoContainer}>
          <Text style={styles.infoText}>
            This will redirect you to the Identity Server login page.
            Use your demo credentials:
          </Text>
          <Text style={styles.credentialsText}>
            📧 admin@example.com{'\n'}
            🔒 Admin123!
          </Text>
        </View>
      </View>

      <View style={styles.footer}>
        <Text style={styles.footerText}>
          Identity Server: localhost:5000{'\n'}
          Client ID: mobileapp
        </Text>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#F8F9FA',
    padding: 20,
  },
  header: {
    alignItems: 'center',
    marginTop: 60,
    marginBottom: 40,
  },
  logoContainer: {
    width: 80,
    height: 80,
    backgroundColor: '#007BFF',
    borderRadius: 40,
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 20,
  },
  logoText: {
    fontSize: 40,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#212529',
    marginBottom: 5,
  },
  subtitle: {
    fontSize: 16,
    color: '#6C757D',
  },
  content: {
    flex: 1,
    justifyContent: 'space-between',
  },
  description: {
    marginBottom: 30,
  },
  descriptionText: {
    fontSize: 16,
    color: '#495057',
    textAlign: 'center',
    marginBottom: 20,
    lineHeight: 22,
  },
  featuresText: {
    fontSize: 14,
    color: '#6C757D',
    textAlign: 'left',
    backgroundColor: '#E9ECEF',
    padding: 15,
    borderRadius: 8,
    lineHeight: 20,
  },
  errorContainer: {
    backgroundColor: '#F8D7DA',
    borderColor: '#F5C6CB',
    borderWidth: 1,
    borderRadius: 8,
    padding: 15,
    marginBottom: 20,
  },
  errorText: {
    color: '#721C24',
    textAlign: 'center',
    fontSize: 14,
  },
  loginButton: {
    backgroundColor: '#007BFF',
    paddingVertical: 15,
    paddingHorizontal: 30,
    borderRadius: 8,
    alignItems: 'center',
    elevation: 2,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
  },
  loginButtonDisabled: {
    backgroundColor: '#ADB5BD',
  },
  loadingContainer: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  loginButtonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: '600',
    marginLeft: 10,
  },
  infoContainer: {
    marginTop: 30,
    padding: 20,
    backgroundColor: '#D1ECF1',
    borderRadius: 8,
    borderLeftWidth: 4,
    borderLeftColor: '#BEE5EB',
  },
  infoText: {
    fontSize: 14,
    color: '#0C5460',
    marginBottom: 10,
    lineHeight: 18,
  },
  credentialsText: {
    fontSize: 14,
    fontWeight: '600',
    color: '#0C5460',
    fontFamily: 'monospace',
  },
  footer: {
    alignItems: 'center',
    paddingVertical: 20,
  },
  footerText: {
    fontSize: 12,
    color: '#ADB5BD',
    textAlign: 'center',
    lineHeight: 16,
  },
});