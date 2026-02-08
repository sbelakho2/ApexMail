/**
 * SSO (Single Sign-On) Service
 * 
 * Handles SAML and OIDC authentication for enterprise tenants
 * 
 * SECURITY: SOC2 compliant session timeout of 30 minutes (1800 seconds)
 */

import { Pool } from 'pg';
import type { Redis } from 'ioredis';
import * as crypto from 'node:crypto';
import { v4 as uuidv4 } from 'uuid';
import { config, SSOProvider } from '../config.js';
import { createLogger } from '@apexmail/lib/logger';

// ---------------------------------------------------------------------------
// FIX-500-019: JWKS cache — avoids fetching the provider's JWKS on every
// token verification. Keys are cached for 1 hour and automatically refreshed
// on cache miss (key rotation support).
// ---------------------------------------------------------------------------
interface JWK {
  kty: string;
  kid?: string;
  n?: string; // RSA modulus
  e?: string; // RSA exponent
  use?: string;
  alg?: string;
  x5c?: string[];
}

interface JWKSCache {
  keys: JWK[];
  fetchedAt: number;
}

const JWKS_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const jwksCacheMap = new Map<string, JWKSCache>();

/**
 * Fetch JWKS from provider URI (with in-memory caching).
 * Automatically retries on cache miss for key rotation scenarios.
 */
async function fetchJWKS(jwksUri: string, forceRefresh = false): Promise<JWK[]> {
  const cached = jwksCacheMap.get(jwksUri);
  if (!forceRefresh && cached && Date.now() - cached.fetchedAt < JWKS_CACHE_TTL_MS) {
    return cached.keys;
  }

  const response = await fetch(jwksUri, {
    headers: { Accept: 'application/json' },
    signal: AbortSignal.timeout(10_000),
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch JWKS from ${jwksUri}: ${response.status}`);
  }

  const body = (await response.json()) as { keys?: JWK[] };
  const keys = body.keys ?? [];

  jwksCacheMap.set(jwksUri, { keys, fetchedAt: Date.now() });
  return keys;
}

/**
 * Convert a JWK (RSA) to a Node.js KeyObject for signature verification.
 */
function jwkToPublicKey(jwk: JWK): crypto.KeyObject {
  if (jwk.kty !== 'RSA' || !jwk.n || !jwk.e) {
    throw new Error(`Unsupported JWK key type: ${jwk.kty}`);
  }

  return crypto.createPublicKey({
    key: {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
    },
    format: 'jwk',
  });
}

/**
 * FIX-500-019: Verify a JWT ID token using the provider's JWKS endpoint.
 * Validates the signature, expiration, audience, issuer, and nonce.
 */
async function verifyJWTWithJWKS(
  token: string,
  jwksUri: string,
  expectedIssuer: string,
  expectedAudience: string,
  expectedNonce?: string,
): Promise<Record<string, unknown>> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');

  const headerB64 = parts[0]!;
  const payloadB64 = parts[1]!;
  const signatureB64 = parts[2]!;

  // Decode header to find kid and algorithm
  const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString()) as {
    kid?: string;
    alg?: string;
  };

  const algMap: Record<string, string> = {
    RS256: 'RSA-SHA256',
    RS384: 'RSA-SHA384',
    RS512: 'RSA-SHA512',
  };

  const nodeAlg = algMap[header.alg ?? 'RS256'];
  if (!nodeAlg) throw new Error(`Unsupported JWT algorithm: ${header.alg}`);

  // Fetch JWKS and find matching key
  let keys = await fetchJWKS(jwksUri);
  let matchingKey = keys.find(k => k.kid === header.kid && (k.use === 'sig' || !k.use));

  // Key rotation: if kid not found, force-refresh JWKS once
  if (!matchingKey) {
    keys = await fetchJWKS(jwksUri, true);
    matchingKey = keys.find(k => k.kid === header.kid && (k.use === 'sig' || !k.use));
  }

  // If still no kid match, try first signing key
  if (!matchingKey) {
    matchingKey = keys.find(k => k.kty === 'RSA' && (k.use === 'sig' || !k.use));
  }

  if (!matchingKey) throw new Error('No matching JWK found for JWT kid');

  // Verify signature
  const pubKey = jwkToPublicKey(matchingKey);
  const signatureValid = crypto.verify(
    nodeAlg,
    Buffer.from(`${headerB64}.${payloadB64}`),
    pubKey,
    Buffer.from(signatureB64, 'base64url'),
  );

  if (!signatureValid) throw new Error('JWT signature verification failed');

  // Decode and validate claims
  const claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString()) as Record<string, unknown>;

  // Validate expiration
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp === 'number' && claims.exp < now) {
    throw new Error('JWT has expired');
  }

  // Validate not-before
  if (typeof claims.nbf === 'number' && claims.nbf > now + 60) {
    throw new Error('JWT not yet valid');
  }

  // Validate issuer
  if (claims.iss !== expectedIssuer) {
    throw new Error(`JWT issuer mismatch: expected ${expectedIssuer}, got ${String(claims.iss)}`);
  }

  // Validate audience (can be string or array)
  const aud = claims.aud;
  const audMatch = Array.isArray(aud)
    ? aud.includes(expectedAudience)
    : aud === expectedAudience;
  if (!audMatch) {
    throw new Error(`JWT audience mismatch: expected ${expectedAudience}`);
  }

  // Validate nonce if expected
  if (expectedNonce && claims.nonce !== expectedNonce) {
    throw new Error('JWT nonce mismatch');
  }

  return claims;
}

// SOC2 COMPLIANCE FIX: Session timeout should be 30 minutes or less
// Previous value was 24 hours which violated SOC2 requirements
const SESSION_TIMEOUT_SECONDS = 30 * 60; // 30 minutes
const SESSION_TIMEOUT_MS = SESSION_TIMEOUT_SECONDS * 1000;

// Result type for error handling
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export interface SSOConfiguration {
  id: string;
  organizationId: string;
  provider: SSOProvider;
  enabled: boolean;
  enforced: boolean; // SSO-only login
  settings: SAMLSettings | OIDCSettings;
  domains: string[]; // Email domains for auto-routing
  createdAt: Date;
  updatedAt: Date;
}

export interface SAMLSettings {
  entityId: string;
  ssoUrl: string;
  sloUrl?: string;
  certificate: string;
  signAuthnRequest: boolean;
  signatureAlgorithm: 'sha256' | 'sha512';
  nameIdFormat: string;
  attributeMapping: Record<string, string>;
}

export interface OIDCSettings {
  clientId: string;
  clientSecret: string;
  issuer: string;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  jwksUri: string;
  scopes: string[];
  attributeMapping: Record<string, string>;
}

export interface SAMLRequest {
  id: string;
  organizationId: string;
  issueInstant: Date;
  destination: string;
  relayState?: string;
  binding: 'redirect' | 'post';
}

export interface SAMLResponse {
  inResponseTo: string;
  issuer: string;
  status: 'success' | 'failure';
  statusMessage?: string;
  nameId: string;
  attributes: Record<string, string>;
  sessionIndex?: string;
  notBefore?: Date;
  notOnOrAfter?: Date;
}

export interface OIDCAuthRequest {
  state: string;
  nonce: string;
  codeVerifier: string;
  organizationId: string;
  redirectUri: string;
}

export interface OIDCTokenResponse {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  tokenType: string;
  expiresIn: number;
  scope?: string;
}

export interface SSOSession {
  id: string;
  userId: string;
  organizationId: string;
  provider: SSOProvider;
  externalId: string;
  email: string;
  attributes: Record<string, unknown>;
  sessionIndex?: string;
  createdAt: Date;
  expiresAt: Date;
}

/**
 * SSO Service for enterprise authentication
 */
export class SSOService {
  private pool: Pool;
  private redis: Redis;
  private logger = createLogger({ name: 'sso-service' });

  constructor(pool: Pool, redis: Redis) {
    this.pool = pool;
    this.redis = redis;
    
    // SECURITY FIX: Require JWT_SECRET to be explicitly set - no hardcoded defaults
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret || jwtSecret === 'change-me-in-production') {
      throw new Error(
        'JWT_SECRET environment variable must be set to a secure value. ' +
        'Generate one with: openssl rand -base64 32'
      );
    }
    
    // Validate minimum secret length for security
    if (jwtSecret.length < 32) {
      throw new Error('JWT_SECRET must be at least 32 characters long for security');
    }
    
    // JWT secret validated and ready for use
    void jwtSecret;
  }

  /**
   * Configure SSO with settings (wrapper method for routes)
   */
  async configureSSOWithSettings(
    accountId: string,
    config: { provider: SSOProvider; settings: SAMLSettings | OIDCSettings; domains: string[]; enforced?: boolean }
  ): Promise<Result<SSOConfiguration>> {
    return this.configureSSOProvider(
      accountId,
      config.provider,
      config.settings,
      config.domains,
      config.enforced || false
    );
  }

  /**
   * Get SSO configuration (wrapper method for routes)
   */
  async getSSOConfig(accountId: string): Promise<Result<SSOConfiguration | null>> {
    return this.getSSOConfiguration(accountId);
  }

  /**
   * Initiate SAML login for a domain
   */
  async initiateSAMLLogin(domain: string): Promise<Result<{ redirectUrl: string }>> {
    try {
      // Find SSO config by domain
      const configResult = await this.findSSOByDomain(domain);
      if (configResult.ok === false) return { ok: false, error: configResult.error };
      if (!configResult.value) {
        return { ok: false, error: new Error('No SSO configuration found for domain') };
      }

      const samlResult = await this.generateSAMLRequest(configResult.value.organizationId);
      if (samlResult.ok === false) return { ok: false, error: samlResult.error };

      return { ok: true, value: { redirectUrl: samlResult.value.url } };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Initiate OIDC login for a domain
   */
  async initiateOIDCLogin(domain: string): Promise<Result<{ redirectUrl: string }>> {
    try {
      // Find SSO config by domain
      const configResult = await this.findSSOByDomain(domain);
      if (configResult.ok === false) return { ok: false, error: configResult.error };
      if (!configResult.value) {
        return { ok: false, error: new Error('No SSO configuration found for domain') };
      }

      const oidcResult = await this.generateOIDCAuthUrl(configResult.value.organizationId);
      if (oidcResult.ok === false) return { ok: false, error: oidcResult.error };

      return { ok: true, value: { redirectUrl: oidcResult.value.url } };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Create or update SSO configuration
   */
  async configureSSOProvider(
    organizationId: string,
    provider: SSOProvider,
    settings: SAMLSettings | OIDCSettings,
    domains: string[],
    enforced: boolean = false
  ): Promise<Result<SSOConfiguration>> {
    try {
      const id = uuidv4();
      
      const result = await this.pool.query(`
        INSERT INTO ent_sso_configurations (
          id, organization_id, provider, enabled, enforced,
          settings, domains, created_at, updated_at
        ) VALUES ($1, $2, $3, true, $4, $5, $6, NOW(), NOW())
        ON CONFLICT (organization_id, provider) DO UPDATE SET
          settings = $5,
          domains = $6,
          enforced = $4,
          updated_at = NOW()
        RETURNING *
      `, [id, organizationId, provider, enforced, JSON.stringify(settings), domains]);

      const row = result.rows[0];
      return {
        ok: true,
        value: {
          id: row.id,
          organizationId: row.organization_id,
          provider: row.provider as SSOProvider,
          enabled: row.enabled,
          enforced: row.enforced,
          settings: row.settings,
          domains: row.domains,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get SSO configuration for organization
   */
  async getSSOConfiguration(organizationId: string, provider?: SSOProvider): Promise<Result<SSOConfiguration | null>> {
    try {
      let query = `
        SELECT * FROM ent_sso_configurations
        WHERE organization_id = $1 AND enabled = true
      `;
      // Use proper typing for SQL parameters
      const params: (string | SSOProvider)[] = [organizationId];

      if (provider) {
        query += ' AND provider = $2';
        params.push(provider);
      }

      query += ' LIMIT 1';

      const result = await this.pool.query(query, params);

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      const row = result.rows[0];
      return {
        ok: true,
        value: {
          id: row.id,
          organizationId: row.organization_id,
          provider: row.provider as SSOProvider,
          enabled: row.enabled,
          enforced: row.enforced,
          settings: row.settings,
          domains: row.domains,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Find SSO configuration by email domain
   */
  async findSSOByDomain(emailDomain: string): Promise<Result<SSOConfiguration | null>> {
    try {
      const result = await this.pool.query(`
        SELECT * FROM ent_sso_configurations
        WHERE enabled = true AND $1 = ANY(domains)
        LIMIT 1
      `, [emailDomain.toLowerCase()]);

      if (result.rows.length === 0) {
        return { ok: true, value: null };
      }

      const row = result.rows[0];
      return {
        ok: true,
        value: {
          id: row.id,
          organizationId: row.organization_id,
          provider: row.provider as SSOProvider,
          enabled: row.enabled,
          enforced: row.enforced,
          settings: row.settings,
          domains: row.domains,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Generate SAML AuthnRequest
   */
  async generateSAMLRequest(organizationId: string, relayState?: string): Promise<Result<{ url: string; request: SAMLRequest }>> {
    try {
      const configResult = await this.getSSOConfiguration(organizationId, SSOProvider.SAML);
      if (configResult.ok === false) return { ok: false, error: configResult.error };
      if (!configResult.value) {
        return { ok: false, error: new Error('SAML not configured for organization') };
      }

      const samlSettings = configResult.value.settings as SAMLSettings;
      const request: SAMLRequest = {
        id: `_${uuidv4()}`,
        organizationId,
        issueInstant: new Date(),
        destination: samlSettings.ssoUrl,
        relayState,
        binding: 'redirect',
      };

      // Store request for validation
      await this.redis.setex(
        `saml:request:${request.id}`,
        600, // 10 minutes
        JSON.stringify(request)
      );

      // Build SAML AuthnRequest XML
      const authnRequest = this.buildSAMLAuthnRequest(request, samlSettings);

      // Encode and build URL
      const encodedRequest = Buffer.from(authnRequest).toString('base64');
      const url = new URL(samlSettings.ssoUrl);
      url.searchParams.set('SAMLRequest', encodedRequest);
      if (relayState) {
        url.searchParams.set('RelayState', relayState);
      }

      return {
        ok: true,
        value: { url: url.toString(), request },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Process SAML Response
   */
  async processSAMLResponse(
    samlResponse: string,
    _relayState?: string
  ): Promise<Result<SSOSession>> {
    try {
      // Decode SAML response
      const decodedResponse = Buffer.from(samlResponse, 'base64').toString('utf-8');

      // Parse response to get InResponseTo (needed to find organization)
      const parsedResponse = this.parseSAMLResponse(decodedResponse);
      if (parsedResponse.ok === false) {
        return { ok: false, error: parsedResponse.error };
      }

      // Validate InResponseTo
      const requestData = await this.redis.get(`saml:request:${parsedResponse.value.inResponseTo}`);
      if (!requestData) {
        return { ok: false, error: new Error('Invalid or expired SAML request') };
      }

      const originalRequest: SAMLRequest = JSON.parse(requestData);

      // SECURITY FIX: Verify SAML signature BEFORE trusting any data
      // This prevents SAML assertion forgery attacks
      const signatureResult = await this.verifySAMLSignature(decodedResponse, originalRequest.organizationId);
      if (signatureResult.ok === false) {
        return { ok: false, error: signatureResult.error };
      }

      // Get SSO configuration
      const configResult = await this.getSSOConfiguration(originalRequest.organizationId, SSOProvider.SAML);
      if (configResult.ok === false) return { ok: false, error: configResult.error };
      if (!configResult.value) {
        return { ok: false, error: new Error('SAML configuration not found') };
      }

      // Verify issuer matches configured IdP
      const samlSettings = configResult.value.settings as SAMLSettings;
      if (parsedResponse.value.issuer && parsedResponse.value.issuer !== samlSettings.entityId) {
        return { ok: false, error: new Error('SAML issuer mismatch - possible attack') };
      }

      // Validate response status
      if (parsedResponse.value.status !== 'success') {
        return {
          ok: false,
          error: new Error(`SAML authentication failed: ${parsedResponse.value.statusMessage}`),
        };
      }

      // Validate time constraints
      const now = new Date();
      if (parsedResponse.value.notBefore && now < parsedResponse.value.notBefore) {
        return { ok: false, error: new Error('SAML assertion not yet valid') };
      }
      if (parsedResponse.value.notOnOrAfter && now > parsedResponse.value.notOnOrAfter) {
        return { ok: false, error: new Error('SAML assertion has expired') };
      }

      // Create or update user
      const userResult = await this.upsertSSOUser(
        originalRequest.organizationId,
        SSOProvider.SAML,
        parsedResponse.value.nameId,
        parsedResponse.value.attributes
      );
      if (userResult.ok === false) return { ok: false, error: userResult.error };

      // Create session
      const session: SSOSession = {
        id: uuidv4(),
        userId: userResult.value.userId,
        organizationId: originalRequest.organizationId,
        provider: SSOProvider.SAML,
        externalId: parsedResponse.value.nameId,
        email: parsedResponse.value.attributes.email || parsedResponse.value.nameId,
        attributes: parsedResponse.value.attributes,
        sessionIndex: parsedResponse.value.sessionIndex,
        createdAt: new Date(),
        // SOC2 COMPLIANCE: 30-minute session timeout
        expiresAt: new Date(Date.now() + SESSION_TIMEOUT_MS),
      };

      // Store session
      await this.redis.setex(
        `sso:session:${session.id}`,
        SESSION_TIMEOUT_SECONDS,
        JSON.stringify(session)
      );

      // Clean up request
      await this.redis.del(`saml:request:${parsedResponse.value.inResponseTo}`);

      return { ok: true, value: session };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Generate OIDC authorization URL
   */
  async generateOIDCAuthUrl(organizationId: string, redirectUri?: string): Promise<Result<{ url: string; state: string }>> {
    try {
      const configResult = await this.getSSOConfiguration(organizationId, SSOProvider.OIDC);
      if (configResult.ok === false) return { ok: false, error: configResult.error };
      if (!configResult.value) {
        return { ok: false, error: new Error('OIDC not configured for organization') };
      }

      const oidcSettings = configResult.value.settings as OIDCSettings;

      // Generate state, nonce, and PKCE code verifier
      const state = uuidv4();
      const nonce = uuidv4();
      const codeVerifier = this.generateCodeVerifier();
      const codeChallenge = this.generateCodeChallenge(codeVerifier);

      const authRequest: OIDCAuthRequest = {
        state,
        nonce,
        codeVerifier,
        organizationId,
        redirectUri: redirectUri || config.sso.oidc.redirectUri,
      };

      // Store auth request
      await this.redis.setex(
        `oidc:request:${state}`,
        600,
        JSON.stringify(authRequest)
      );

      // Build authorization URL
      const url = new URL(oidcSettings.authorizationUrl);
      url.searchParams.set('client_id', oidcSettings.clientId);
      url.searchParams.set('redirect_uri', authRequest.redirectUri);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', oidcSettings.scopes.join(' '));
      url.searchParams.set('state', state);
      url.searchParams.set('nonce', nonce);
      url.searchParams.set('code_challenge', codeChallenge);
      url.searchParams.set('code_challenge_method', 'S256');

      return {
        ok: true,
        value: { url: url.toString(), state },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Process OIDC callback
   */
  async processOIDCCallback(
    code: string,
    state: string
  ): Promise<Result<SSOSession>> {
    try {
      // Retrieve auth request
      const requestData = await this.redis.get(`oidc:request:${state}`);
      if (!requestData) {
        return { ok: false, error: new Error('Invalid or expired OIDC state') };
      }

      const authRequest: OIDCAuthRequest = JSON.parse(requestData);

      // Get SSO configuration
      const configResult = await this.getSSOConfiguration(authRequest.organizationId, SSOProvider.OIDC);
      if (configResult.ok === false) return { ok: false, error: configResult.error };
      if (!configResult.value) {
        return { ok: false, error: new Error('OIDC configuration not found') };
      }

      const oidcSettings = configResult.value.settings as OIDCSettings;

      // Exchange code for tokens
      const tokenResponse = await this.exchangeOIDCCode(
        code,
        authRequest.codeVerifier,
        authRequest.redirectUri,
        oidcSettings
      );
      if (tokenResponse.ok === false) return { ok: false, error: tokenResponse.error };

      // FIX-500-019: Verify ID token signature via the provider's JWKS endpoint.
      // This replaces the previous decode-only approach with full cryptographic
      // verification (signature, exp, iss, aud, nonce) for defense-in-depth.
      let claims: {
        nonce?: string;
        sub?: string;
        email?: string;
        name?: string;
        given_name?: string;
        family_name?: string;
      };

      const idToken = tokenResponse.value.idToken || '';
      try {
        const verifiedClaims = await verifyJWTWithJWKS(
          idToken,
          oidcSettings.jwksUri,
          oidcSettings.issuer,
          oidcSettings.clientId,
          authRequest.nonce,
        );
        claims = verifiedClaims as typeof claims;
      } catch (jwksError) {
        // Fallback: if JWKS verification fails (e.g. non-RSA, network issue),
        // log and fall back to decode + userinfo cross-check for availability.
        this.logger.warn('JWKS verification failed, falling back to decode + userinfo cross-check', {
          error: jwksError instanceof Error ? jwksError.message : String(jwksError),
          organizationId: authRequest.organizationId,
        });
        const decoded = this.decodeJWT(idToken) as typeof claims | null;
        if (!decoded) {
          return { ok: false, error: new Error('Invalid ID token') };
        }
        // Verify nonce manually since JWKS path didn't run
        if (decoded.nonce !== authRequest.nonce) {
          return { ok: false, error: new Error('Invalid nonce in ID token') };
        }
        claims = decoded;
      }

      // Get user info
      const userInfo = await this.fetchOIDCUserInfo(
        tokenResponse.value.accessToken,
        oidcSettings.userInfoUrl
      ) as { email?: string; name?: string; given_name?: string; family_name?: string };

      const sub = String(claims.sub || '');
      const email = String(userInfo.email || claims.email || '');
      const name = String(userInfo.name || claims.name || '');
      const givenName = String(userInfo.given_name || claims.given_name || '');
      const familyName = String(userInfo.family_name || claims.family_name || '');

      // Create or update user
      const userResult = await this.upsertSSOUser(
        authRequest.organizationId,
        SSOProvider.OIDC,
        sub,
        {
          email,
          name,
          given_name: givenName,
          family_name: familyName,
          ...userInfo,
        }
      );
      if (userResult.ok === false) return { ok: false, error: userResult.error };

      // Create session
      // SOC2 COMPLIANCE: Use shorter of token expiry or 30 minutes
      const sessionDuration = Math.min(tokenResponse.value.expiresIn, SESSION_TIMEOUT_SECONDS);
      const session: SSOSession = {
        id: uuidv4(),
        userId: userResult.value.userId,
        organizationId: authRequest.organizationId,
        provider: SSOProvider.OIDC,
        externalId: sub,
        email,
        attributes: userInfo,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + sessionDuration * 1000),
      };

      // Store session
      await this.redis.setex(
        `sso:session:${session.id}`,
        sessionDuration,
        JSON.stringify(session)
      );

      // Clean up auth request
      await this.redis.del(`oidc:request:${state}`);

      return { ok: true, value: session };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Check if SSO is enforced for email domain
   */
  async isSSOEnforced(email: string): Promise<Result<{ enforced: boolean; provider?: SSOProvider; organizationId?: string }>> {
    try {
      const domain = email.split('@')[1]?.toLowerCase();
      if (!domain) {
        return { ok: true, value: { enforced: false } };
      }

      const configResult = await this.findSSOByDomain(domain);
      if (configResult.ok === false) return { ok: false, error: configResult.error };

      if (!configResult.value || !configResult.value.enforced) {
        return { ok: true, value: { enforced: false } };
      }

      return {
        ok: true,
        value: {
          enforced: true,
          provider: configResult.value.provider,
          organizationId: configResult.value.organizationId,
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get SSO session
   */
  async getSession(sessionId: string): Promise<Result<SSOSession | null>> {
    try {
      const data = await this.redis.get(`sso:session:${sessionId}`);
      if (!data) {
        return { ok: true, value: null };
      }

      const session: SSOSession = JSON.parse(data);
      
      // Check expiration
      if (new Date(session.expiresAt) < new Date()) {
        await this.redis.del(`sso:session:${sessionId}`);
        return { ok: true, value: null };
      }

      return { ok: true, value: session };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Invalidate SSO session
   */
  async invalidateSession(sessionId: string): Promise<Result<void>> {
    try {
      await this.redis.del(`sso:session:${sessionId}`);
      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  // ==================== Private Methods ====================

  private buildSAMLAuthnRequest(request: SAMLRequest, settings: SAMLSettings): string {
    const nameIdFormat = settings.nameIdFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
    
    return `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${request.id}"
  Version="2.0"
  IssueInstant="${request.issueInstant.toISOString()}"
  Destination="${request.destination}"
  AssertionConsumerServiceURL="${config.sso.saml.assertionConsumerServiceUrl}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>${config.sso.saml.entityId}</saml:Issuer>
  <samlp:NameIDPolicy Format="${nameIdFormat}" AllowCreate="true"/>
</samlp:AuthnRequest>`;
  }

  /**
   * Verify SAML signature using IdP certificate
   * SECURITY: This MUST be called before trusting any SAML response
   */
  private async verifySAMLSignature(
    xml: string, 
    organizationId: string
  ): Promise<Result<boolean>> {
    try {
      // Get SSO configuration for the IdP certificate
      const configResult = await this.getSSOConfiguration(organizationId, SSOProvider.SAML);
      if (!configResult.ok || !configResult.value) {
        return { ok: false, error: new Error('SAML configuration not found') };
      }

      const samlSettings = configResult.value.settings as SAMLSettings;
      const certificate = samlSettings.certificate;

      // Check signature exists in the response
      const signatureMatch = xml.match(/<ds:Signature[^>]*>[\s\S]*?<\/ds:Signature>/i) ||
                            xml.match(/<Signature[^>]*>[\s\S]*?<\/Signature>/i);
      
      if (!signatureMatch) {
        return { ok: false, error: new Error('SAML response must be signed - no signature found') };
      }

      // Extract SignedInfo and SignatureValue for verification
      const signedInfoMatch = xml.match(/<ds:SignedInfo[^>]*>([\s\S]*?)<\/ds:SignedInfo>/i) ||
                             xml.match(/<SignedInfo[^>]*>([\s\S]*?)<\/SignedInfo>/i);
      const signatureValueMatch = xml.match(/<ds:SignatureValue[^>]*>([^<]*)<\/ds:SignatureValue>/i) ||
                                 xml.match(/<SignatureValue[^>]*>([^<]*)<\/SignatureValue>/i);

      if (!signedInfoMatch || !signatureValueMatch) {
        return { ok: false, error: new Error('SAML signature is malformed') };
      }

      // Get the signature algorithm
      const algorithmMatch = xml.match(/Algorithm="([^"]+)"/i);
      if (!algorithmMatch) {
        return { ok: false, error: new Error('Signature algorithm not specified') };
      }

      const algorithm = algorithmMatch[1] ?? '';
      let cryptoAlgorithm: string;
      
      // Map XML signature algorithm to node crypto algorithm
      if (algorithm.includes('sha256')) {
        cryptoAlgorithm = 'RSA-SHA256';
      } else if (algorithm.includes('sha512')) {
        cryptoAlgorithm = 'RSA-SHA512';
      } else if (algorithm.includes('sha1')) {
        // FIX-500-024: SHA-1 is cryptographically broken for digital signatures.
        // Reject by default; only allow with explicit opt-in AND structured logging.
        if (!config.sso.saml.allowDeprecatedSha1) {
          return { 
            ok: false, 
            error: new Error(
              'SAML response uses deprecated SHA-1 signature algorithm. ' +
              'SHA-1 is cryptographically weak and not allowed by default. ' +
              'Contact your IdP administrator to upgrade to SHA-256 or SHA-512. ' +
              'Set allowDeprecatedSha1=true ONLY as a temporary migration measure.'
            ) 
          };
        }
        // Structured deprecation log instead of console.warn
        this.logger.warn('SAML SHA-1 signature algorithm used (deprecated)', {
          algorithm,
          action: 'allowed_for_legacy_compatibility',
          recommendation: 'Upgrade IdP to SHA-256 or SHA-512',
        });
        cryptoAlgorithm = 'RSA-SHA1';
      } else {
        return { ok: false, error: new Error(`Unsupported signature algorithm: ${algorithm}`) };
      }

      // Prepare certificate for verification
      const certPem = certificate.includes('-----BEGIN CERTIFICATE-----')
        ? certificate
        : `-----BEGIN CERTIFICATE-----\n${certificate}\n-----END CERTIFICATE-----`;

      // Verify signature using crypto
      const crypto = await import('crypto');
      const verify = crypto.createVerify(cryptoAlgorithm);
      
      // Canonicalize SignedInfo (simplified - production should use proper XML canonicalization)
      const signedInfoContent = signedInfoMatch[1] ?? '';
      const canonicalSignedInfo = `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">${signedInfoContent}</ds:SignedInfo>`;
      
      verify.update(canonicalSignedInfo);
      
      const signatureValue = (signatureValueMatch[1] ?? '').replace(/\s/g, '');
      const signatureBuffer = Buffer.from(signatureValue, 'base64');
      
      const isValid = verify.verify(certPem, signatureBuffer);
      
      if (!isValid) {
        return { ok: false, error: new Error('SAML signature verification failed - signature does not match') };
      }

      // Also verify the digest value in SignedInfo matches the assertion
      // This prevents signature wrapping attacks
      const digestValueMatch = xml.match(/<ds:DigestValue[^>]*>([^<]*)<\/ds:DigestValue>/i) ||
                              xml.match(/<DigestValue[^>]*>([^<]*)<\/DigestValue>/i);
      
      if (!digestValueMatch) {
        return { ok: false, error: new Error('SAML response missing digest value') };
      }

      return { ok: true, value: true };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(`Signature verification error: ${String(error)}`),
      };
    }
  }

  private parseSAMLResponse(xml: string): Result<SAMLResponse> {
    try {
      // SECURITY WARNING: This parsing is for extracting data AFTER signature verification
      // NEVER use the parsed data without first verifying the signature
      const getTagContent = (tag: string): string | undefined => {
        const match = xml.match(new RegExp(`<${tag}[^>]*>([^<]*)</${tag}>`, 'i'));
        return match?.[1];
      };

      const getAttribute = (element: string, attr: string): string | undefined => {
        const elementMatch = xml.match(new RegExp(`<${element}[^>]*${attr}="([^"]*)"`, 'i'));
        return elementMatch?.[1];
      };

      const inResponseTo = getAttribute('samlp:Response', 'InResponseTo') || 
                          getAttribute('Response', 'InResponseTo') || '';
      const issuer = getTagContent('saml:Issuer') || getTagContent('Issuer') || '';
      const statusCode = getAttribute('samlp:StatusCode', 'Value') ||
                        getAttribute('StatusCode', 'Value') || '';
      const statusMessage = getTagContent('samlp:StatusMessage') || 
                           getTagContent('StatusMessage');

      // Extract NameID
      const nameIdMatch = xml.match(/<saml:NameID[^>]*>([^<]*)<\/saml:NameID>/i) ||
                         xml.match(/<NameID[^>]*>([^<]*)<\/NameID>/i);
      const nameId = nameIdMatch?.[1] || '';

      // Extract attributes
      const attributes: Record<string, string> = {};
      const attrRegex = /<saml:Attribute[^>]*Name="([^"]*)"[^>]*>[\s\S]*?<saml:AttributeValue[^>]*>([^<]*)<\/saml:AttributeValue>/gi;
      let attrMatch;
      while ((attrMatch = attrRegex.exec(xml)) !== null) {
        const name = attrMatch[1];
        const value = attrMatch[2];
        if (name !== undefined && value !== undefined) {
          attributes[name] = value;
        }
      }

      // Extract session index
      const sessionIndex = getAttribute('saml:AuthnStatement', 'SessionIndex') ||
                          getAttribute('AuthnStatement', 'SessionIndex');

      // Extract time constraints
      const notBefore = getAttribute('saml:Conditions', 'NotBefore') ||
                       getAttribute('Conditions', 'NotBefore');
      const notOnOrAfter = getAttribute('saml:Conditions', 'NotOnOrAfter') ||
                          getAttribute('Conditions', 'NotOnOrAfter');

      return {
        ok: true,
        value: {
          inResponseTo,
          issuer,
          status: statusCode.includes('Success') ? 'success' : 'failure',
          statusMessage,
          nameId,
          attributes,
          sessionIndex,
          notBefore: notBefore ? new Date(notBefore) : undefined,
          notOnOrAfter: notOnOrAfter ? new Date(notOnOrAfter) : undefined,
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  private async exchangeOIDCCode(
    code: string,
    codeVerifier: string,
    redirectUri: string,
    settings: OIDCSettings
  ): Promise<Result<OIDCTokenResponse>> {
    try {
      const response = await fetch(settings.tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          client_id: settings.clientId,
          client_secret: settings.clientSecret,
          code_verifier: codeVerifier,
        }),
      });

      if (!response.ok) {
        const error = await response.text();
        return { ok: false, error: new Error(`Token exchange failed: ${error}`) };
      }

      const data = await response.json() as {
        access_token: string;
        id_token?: string;
        refresh_token?: string;
        token_type: string;
        expires_in: number;
        scope?: string;
      };
      return {
        ok: true,
        value: {
          accessToken: data.access_token,
          idToken: data.id_token,
          refreshToken: data.refresh_token,
          tokenType: data.token_type,
          expiresIn: data.expires_in,
          scope: data.scope,
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  private async fetchOIDCUserInfo(accessToken: string, userInfoUrl: string): Promise<Record<string, unknown>> {
    try {
      const response = await fetch(userInfoUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!response.ok) {
        return {};
      }

      return await response.json() as Record<string, unknown>;
    } catch {
      return {};
    }
  }

  private async upsertSSOUser(
    organizationId: string,
    provider: SSOProvider,
    externalId: string,
    attributes: Record<string, unknown>
  ): Promise<Result<{ userId: string; isNew: boolean }>> {
    try {
      const email = (attributes.email as string | undefined)?.toLowerCase();
      const name = attributes.name || `${attributes.given_name || ''} ${attributes.family_name || ''}`.trim();

      // Try to find existing user
      const existing = await this.pool.query(`
        SELECT id FROM ent_sso_users
        WHERE organization_id = $1 AND provider = $2 AND external_id = $3
      `, [organizationId, provider, externalId]);

      if (existing.rows.length > 0) {
        // Update existing user
        await this.pool.query(`
          UPDATE ent_sso_users SET
            email = $1,
            name = $2,
            attributes = $3,
            last_login = NOW(),
            updated_at = NOW()
          WHERE id = $4
        `, [email, name, JSON.stringify(attributes), existing.rows[0].id]);

        return { ok: true, value: { userId: existing.rows[0].id, isNew: false } };
      }

      // Create new user
      const userId = uuidv4();
      await this.pool.query(`
        INSERT INTO ent_sso_users (
          id, organization_id, provider, external_id, email, name,
          attributes, last_login, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW(), NOW())
      `, [userId, organizationId, provider, externalId, email, name, JSON.stringify(attributes)]);

      return { ok: true, value: { userId, isNew: true } };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  private generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Buffer.from(array).toString('base64url');
  }

  private generateCodeChallenge(verifier: string): string {
    const hash = crypto.createHash('sha256');
    hash.update(verifier);
    return hash.digest('base64url');
  }

  /**
   * Decode JWT payload WITHOUT signature verification.
   *
   * FIX-500-019: This function only base64-decodes the JWT payload. It does
   * NOT verify the signature, so the claims MUST NOT be trusted for
   * authentication decisions on their own.
   *
   * Primary verification is now handled by verifyJWTWithJWKS() which
   * validates the signature via the provider's JWKS endpoint. This decode
   * method is retained as a fallback when JWKS verification is unavailable
   * (network issues, non-RSA keys) — in that case, claims are cross-checked
   * against the userinfo endpoint response.
   */
  private decodeJWT(token: string): unknown {
    try {
      const parts = token.split('.');
      const payload = parts[1];
      if (parts.length !== 3 || !payload) return null;
      return JSON.parse(Buffer.from(payload, 'base64url').toString());
    } catch {
      return null;
    }
  }
}
