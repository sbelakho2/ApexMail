/**
 * SSO (Single Sign-On) Service
 * 
 * Handles SAML and OIDC authentication for enterprise tenants
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { config, SSOProvider } from '../config.js';

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
  idToken: string;
  refreshToken?: string;
  tokenType: string;
  expiresIn: number;
  scope: string;
}

export interface SSOSession {
  id: string;
  userId: string;
  organizationId: string;
  provider: SSOProvider;
  externalId: string;
  email: string;
  attributes: Record<string, string>;
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
  private jwtSecret: string;

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
    
    this.jwtSecret = jwtSecret;
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
      const params: any[] = [organizationId];

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
      if (!configResult.ok) return { ok: false, error: configResult.error };
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
    relayState?: string
  ): Promise<Result<SSOSession>> {
    try {
      // Decode SAML response
      const decodedResponse = Buffer.from(samlResponse, 'base64').toString('utf-8');

      // Parse response
      const parsedResponse = this.parseSAMLResponse(decodedResponse);
      if (!parsedResponse.ok) {
        return { ok: false, error: parsedResponse.error };
      }

      // Validate InResponseTo
      const requestData = await this.redis.get(`saml:request:${parsedResponse.value.inResponseTo}`);
      if (!requestData) {
        return { ok: false, error: new Error('Invalid or expired SAML request') };
      }

      const originalRequest: SAMLRequest = JSON.parse(requestData);

      // Get SSO configuration
      const configResult = await this.getSSOConfiguration(originalRequest.organizationId, SSOProvider.SAML);
      if (!configResult.ok) return { ok: false, error: configResult.error };
      if (!configResult.value) {
        return { ok: false, error: new Error('SAML configuration not found') };
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
      if (!userResult.ok) return { ok: false, error: userResult.error };

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
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      };

      // Store session
      await this.redis.setex(
        `sso:session:${session.id}`,
        86400,
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
      if (!configResult.ok) return { ok: false, error: configResult.error };
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
      if (!configResult.ok) return { ok: false, error: configResult.error };
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
      if (!tokenResponse.ok) return { ok: false, error: tokenResponse.error };

      // Validate ID token
      const claims = this.decodeJWT(tokenResponse.value.idToken);
      if (!claims) {
        return { ok: false, error: new Error('Invalid ID token') };
      }

      // Verify nonce
      if (claims.nonce !== authRequest.nonce) {
        return { ok: false, error: new Error('Invalid nonce in ID token') };
      }

      // Get user info
      const userInfo = await this.fetchOIDCUserInfo(
        tokenResponse.value.accessToken,
        oidcSettings.userInfoUrl
      );

      // Create or update user
      const userResult = await this.upsertSSOUser(
        authRequest.organizationId,
        SSOProvider.OIDC,
        claims.sub,
        {
          email: userInfo.email || claims.email,
          name: userInfo.name || claims.name,
          given_name: userInfo.given_name || claims.given_name,
          family_name: userInfo.family_name || claims.family_name,
          ...userInfo,
        }
      );
      if (!userResult.ok) return { ok: false, error: userResult.error };

      // Create session
      const session: SSOSession = {
        id: uuidv4(),
        userId: userResult.value.userId,
        organizationId: authRequest.organizationId,
        provider: SSOProvider.OIDC,
        externalId: claims.sub,
        email: userInfo.email || claims.email,
        attributes: userInfo,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + tokenResponse.value.expiresIn * 1000),
      };

      // Store session
      await this.redis.setex(
        `sso:session:${session.id}`,
        tokenResponse.value.expiresIn,
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
      if (!configResult.ok) return { ok: false, error: configResult.error };

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

  private parseSAMLResponse(xml: string): Result<SAMLResponse> {
    try {
      // Basic XML parsing - production would use a proper SAML library
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
        attributes[attrMatch[1]] = attrMatch[2];
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

      const data = await response.json();
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

  private async fetchOIDCUserInfo(accessToken: string, userInfoUrl: string): Promise<Record<string, any>> {
    try {
      const response = await fetch(userInfoUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!response.ok) {
        return {};
      }

      return await response.json();
    } catch {
      return {};
    }
  }

  private async upsertSSOUser(
    organizationId: string,
    provider: SSOProvider,
    externalId: string,
    attributes: Record<string, any>
  ): Promise<Result<{ userId: string; isNew: boolean }>> {
    try {
      const email = attributes.email?.toLowerCase();
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
    const hash = require('crypto').createHash('sha256');
    hash.update(verifier);
    return hash.digest('base64url');
  }

  private decodeJWT(token: string): any {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    } catch {
      return null;
    }
  }
}
