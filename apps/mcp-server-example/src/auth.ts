/**
 * Authentication Module for MCP Server
 *
 * Manages:
 * - User token acquisition (authorization code flow with PKCE)
 * - Token validation for incoming requests
 *
 * @packageDocumentation
 */

import {
  createTokenManager,
  createTokenValidator,
  createMemoryStorage,
  type TokenManager,
  type TokenValidator,
  type TokenSet,
  type TokenAcquisitionResult,
  type AuthorizationUrlResult,
} from '@pingidentity/aic-mcp-sdk';
import type { McpServerConfig } from './config.js';
import { toTokenManagerConfig } from './config.js';

/**
 * Authentication state for the MCP server.
 */
export interface AuthState {
  /** User's token set (from authorization code flow) */
  readonly userTokens?: TokenSet | undefined;
  /** Whether the user is authenticated */
  readonly isUserAuthenticated: boolean;
}

/**
 * Authentication manager for the MCP server.
 */
export interface AuthManager {
  /**
   * Starts the user authentication flow.
   * Returns an authorization URL that the user should be redirected to.
   */
  readonly startUserAuth: (options?: {
    readonly scopes?: readonly string[];
  }) => Promise<TokenAcquisitionResult | AuthorizationUrlResult>;

  /**
   * Handles the OAuth callback after user authentication.
   */
  readonly handleCallback: (code: string, state: string) => Promise<TokenAcquisitionResult>;

  /**
   * Gets the token validator for validating incoming tokens.
   */
  readonly getValidator: () => TokenValidator;

  /**
   * Gets the current auth state.
   */
  readonly getAuthState: () => Promise<AuthState>;

  /**
   * Clears all stored tokens.
   */
  readonly logout: () => Promise<void>;
}

/**
 * Checks if a result is an AuthorizationUrlResult.
 */
export function isAuthorizationUrlResult(
  result: TokenAcquisitionResult | AuthorizationUrlResult
): result is AuthorizationUrlResult {
  return 'url' in result && 'state' in result;
}

/**
 * Creates an authentication manager for the MCP server.
 */
export function createAuthManager(config: McpServerConfig): AuthManager {
  const storage = createMemoryStorage();

  const tokenManager: TokenManager = createTokenManager(toTokenManagerConfig(config), storage);

  const validator: TokenValidator = createTokenValidator({
    amUrl: config.amUrl,
    clientId: config.client.clientId,
    clientSecret: config.client.clientSecret,
    realmPath: config.realmPath,
  });

  const startUserAuth: AuthManager['startUserAuth'] = async (options) => {
    return tokenManager.startAuthorization({
      scopes: options?.scopes ?? [...config.client.scopes],
    });
  };

  const handleCallback: AuthManager['handleCallback'] = async (code, state) => {
    return tokenManager.handleCallback(code, state);
  };

  const getValidator: AuthManager['getValidator'] = () => validator;

  const getAuthState: AuthManager['getAuthState'] = async () => {
    const userTokens = await tokenManager.getTokenSet();
    const now = Date.now();

    return {
      userTokens,
      isUserAuthenticated: userTokens !== undefined && userTokens.expiresAt > now,
    };
  };

  const logout: AuthManager['logout'] = async () => {
    await tokenManager.clearTokens();
  };

  return {
    startUserAuth,
    handleCallback,
    getValidator,
    getAuthState,
    logout,
  };
}
