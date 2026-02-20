/**
 * Log Streaming Service
 * 
 * Stream logs to customer-owned S3 buckets and other destinations
 */

import { Pool } from 'pg';
import type { Redis } from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import {
  decryptAES256CBC,
  decryptBufferAES256GCM as decryptAES256GCM,
  deriveKeySync,
  encryptBufferAES256GCM as encryptAES256GCM,
  hmacSign,
} from '@apexmail/lib/crypto';
import { createLogger } from '@apexmail/lib';
import { config } from '../config.js';

const logger = createLogger({ name: 'enterprise-log-streaming' });

// Result type for error handling
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export enum StreamDestinationType {
  S3 = 's3',
  GCS = 'gcs',
  AZURE_BLOB = 'azure_blob',
  WEBHOOK = 'webhook',
  SPLUNK = 'splunk',
  DATADOG = 'datadog',
  SUMOLOGIC = 'sumologic',
}

export enum StreamStatus {
  ACTIVE = 'active',
  PAUSED = 'paused',
  ERROR = 'error',
  PENDING_VERIFICATION = 'pending_verification',
}

export enum LogCategory {
  EMAIL_EVENTS = 'email_events',
  API_CALLS = 'api_calls',
  SECURITY = 'security',
  DELIVERABILITY = 'deliverability',
  WEBHOOK_EVENTS = 'webhook_events',
  BOUNCE_REPORTS = 'bounce_reports',
  SPAM_REPORTS = 'spam_reports',
  ALL = 'all',
}

export interface LogStream {
  id: string;
  accountId: string;
  name: string;
  destinationType: StreamDestinationType;
  destinationConfig: DestinationConfig;
  categories: LogCategory[];
  status: StreamStatus;
  filterRules?: FilterRule[];
  batchConfig: BatchConfig;
  lastStreamedAt?: Date;
  lastError?: string;
  errorCount: number;
  bytesStreamed: number;
  eventsStreamed: number;
  createdAt: Date;
  updatedAt: Date;
}

export type DestinationConfig = 
  | S3DestinationConfig 
  | GCSDestinationConfig 
  | AzureBlobConfig 
  | WebhookConfig 
  | SplunkConfig 
  | DatadogConfig
  | SumoLogicConfig;

export interface S3DestinationConfig {
  type: 's3';
  bucket: string;
  region: string;
  prefix?: string;
  roleArn?: string;
  accessKeyId?: string;
  secretAccessKey?: string;
  kmsKeyId?: string;
}

export interface GCSDestinationConfig {
  type: 'gcs';
  bucket: string;
  prefix?: string;
  serviceAccountKey: string;
}

export interface AzureBlobConfig {
  type: 'azure_blob';
  connectionString: string;
  container: string;
  prefix?: string;
}

export interface WebhookConfig {
  type: 'webhook';
  url: string;
  headers?: Record<string, string>;
  secret?: string;
  tlsSkipVerify?: boolean;
}

export interface SplunkConfig {
  type: 'splunk';
  hecUrl: string;
  hecToken: string;
  index?: string;
  source?: string;
  sourcetype?: string;
}

export interface DatadogConfig {
  type: 'datadog';
  apiKey: string;
  site?: string;
  service?: string;
  source?: string;
  tags?: string[];
}

export interface SumoLogicConfig {
  type: 'sumologic';
  httpSourceUrl: string;
  sourceCategory?: string;
  sourceName?: string;
  sourceHost?: string;
}

export interface FilterRule {
  field: string;
  operator: 'equals' | 'not_equals' | 'contains' | 'not_contains' | 'regex' | 'in' | 'not_in';
  value: string | string[];
}

export interface BatchConfig {
  maxRecords: number;
  maxBytes: number;
  flushIntervalSeconds: number;
  compressionType?: 'gzip' | 'none';
}

export interface LogEvent {
  id: string;
  timestamp: Date;
  category: LogCategory;
  eventType: string;
  accountId: string;
  messageId?: string;
  data: Record<string, any>;
}

export interface StreamBatch {
  streamId: string;
  batchId: string;
  events: LogEvent[];
  startTime: Date;
  endTime: Date;
  size: number;
}

/**
 * Log Streaming Service
 */
export class LogStreamingService {
  private pool: Pool;
  private streamBuffers: Map<string, LogEvent[]> = new Map();
  private flushTimers: Map<string, NodeJS.Timeout> = new Map();

  constructor(pool: Pool, _redis: Redis) {
    this.pool = pool;
    void _redis; // Reserved for future pub/sub streaming
  }

  /**
   * Create a new log stream
   */
  async createStream(
    accountId: string,
    data: Omit<LogStream, 'id' | 'accountId' | 'status' | 'lastStreamedAt' | 'lastError' | 'errorCount' | 'bytesStreamed' | 'eventsStreamed' | 'createdAt' | 'updatedAt'>
  ): Promise<Result<LogStream>> {
    try {
      if (data.destinationType === StreamDestinationType.AZURE_BLOB) {
        return {
          ok: false,
          error: new Error('Azure Blob destination is not supported by ApexMail'),
        };
      }

      const id = uuidv4();

      // Encrypt sensitive credentials
      const encryptedConfig = await this.encryptDestinationConfig(data.destinationConfig);

      await this.pool.query(`
        INSERT INTO ent_log_streams (
          id, account_id, name, destination_type, destination_config,
          categories, status, filter_rules, batch_config,
          error_count, bytes_streamed, events_streamed,
          created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, 0, 0, NOW(), NOW())
      `, [
        id,
        accountId,
        data.name,
        data.destinationType,
        JSON.stringify(encryptedConfig),
        data.categories,
        StreamStatus.PENDING_VERIFICATION,
        JSON.stringify(data.filterRules || []),
        JSON.stringify(data.batchConfig),
      ]);

      return this.getStream(id);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get stream by ID
   */
  async getStream(id: string): Promise<Result<LogStream>> {
    try {
      const result = await this.pool.query(`
        SELECT * FROM ent_log_streams WHERE id = $1
      `, [id]);

      if (result.rows.length === 0) {
        return { ok: false, error: new Error('Stream not found') };
      }

      return { ok: true, value: this.rowToStream(result.rows[0]) };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * List streams for account
   */
  async listStreams(accountId: string): Promise<Result<LogStream[]>> {
    try {
      const result = await this.pool.query(`
        SELECT * FROM ent_log_streams WHERE account_id = $1 ORDER BY created_at DESC
      `, [accountId]);

      return {
        ok: true,
        value: result.rows.map(row => this.rowToStream(row)),
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Update stream
   */
  async updateStream(
    id: string,
    updates: Partial<Pick<LogStream, 'name' | 'categories' | 'filterRules' | 'batchConfig'>>
  ): Promise<Result<LogStream>> {
    try {
      const setClause: string[] = ['updated_at = NOW()'];
      // Use union type for SQL parameter values
      const params: (string | string[] | Record<string, unknown>)[] = [id];
      let paramIndex = 2;

      if (updates.name) {
        setClause.push(`name = $${paramIndex++}`);
        params.push(updates.name);
      }
      if (updates.categories) {
        setClause.push(`categories = $${paramIndex++}`);
        params.push(updates.categories);
      }
      if (updates.filterRules) {
        setClause.push(`filter_rules = $${paramIndex++}`);
        params.push(JSON.stringify(updates.filterRules));
      }
      if (updates.batchConfig) {
        setClause.push(`batch_config = $${paramIndex++}`);
        params.push(JSON.stringify(updates.batchConfig));
      }

      await this.pool.query(`
        UPDATE ent_log_streams SET ${setClause.join(', ')} WHERE id = $1
      `, params);

      return this.getStream(id);
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Verify stream destination connectivity
   */
  async verifyDestination(id: string): Promise<Result<{ success: boolean; message: string }>> {
    try {
      const streamResult = await this.getStream(id);
      if (streamResult.ok === false) return { ok: false, error: streamResult.error };

      const stream = streamResult.value;
      const decryptedConfig = await this.decryptDestinationConfig(stream.destinationConfig);

      let success = false;
      let message = '';

      switch (stream.destinationType) {
        case StreamDestinationType.S3: {
          const s3Result = await this.verifyS3(decryptedConfig as S3DestinationConfig);
          success = s3Result.success;
          message = s3Result.message;
          break;
        }

        case StreamDestinationType.WEBHOOK: {
          const webhookResult = await this.verifyWebhook(decryptedConfig as WebhookConfig);
          success = webhookResult.success;
          message = webhookResult.message;
          break;
        }

        case StreamDestinationType.SPLUNK: {
          const splunkResult = await this.verifySplunk(decryptedConfig as SplunkConfig);
          success = splunkResult.success;
          message = splunkResult.message;
          break;
        }

        case StreamDestinationType.DATADOG: {
          const datadogResult = await this.verifyDatadog(decryptedConfig as DatadogConfig);
          success = datadogResult.success;
          message = datadogResult.message;
          break;
        }

        case StreamDestinationType.SUMOLOGIC: {
          const sumoResult = await this.verifySumoLogic(decryptedConfig as SumoLogicConfig);
          success = sumoResult.success;
          message = sumoResult.message;
          break;
        }

        case StreamDestinationType.GCS: {
          const gcsResult = this.verifyGcsConfig(decryptedConfig as GCSDestinationConfig);
          success = gcsResult.success;
          message = gcsResult.message;
          break;
        }

        case StreamDestinationType.AZURE_BLOB: {
          const azureResult = this.verifyAzureBlobConfig(decryptedConfig as AzureBlobConfig);
          success = azureResult.success;
          message = azureResult.message;
          break;
        }

        default:
          message = 'Destination adapter unavailable in this build';
      }

      // Update stream status
      if (success) {
        await this.pool.query(`
          UPDATE ent_log_streams SET
            status = $2,
            last_error = NULL,
            updated_at = NOW()
          WHERE id = $1
        `, [id, StreamStatus.ACTIVE]);
      } else {
        await this.pool.query(`
          UPDATE ent_log_streams SET
            status = $2,
            last_error = $3,
            error_count = error_count + 1,
            updated_at = NOW()
          WHERE id = $1
        `, [id, StreamStatus.ERROR, message]);
      }

      return { ok: true, value: { success, message } };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Pause stream
   */
  async pauseStream(id: string): Promise<Result<void>> {
    try {
      await this.pool.query(`
        UPDATE ent_log_streams SET
          status = $2,
          updated_at = NOW()
        WHERE id = $1
      `, [id, StreamStatus.PAUSED]);

      // Stop flush timer
      const timer = this.flushTimers.get(id);
      if (timer) {
        clearInterval(timer);
        this.flushTimers.delete(id);
      }

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Resume stream
   */
  async resumeStream(id: string): Promise<Result<void>> {
    try {
      await this.pool.query(`
        UPDATE ent_log_streams SET
          status = $2,
          updated_at = NOW()
        WHERE id = $1
      `, [id, StreamStatus.ACTIVE]);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Delete stream
   */
  async deleteStream(id: string): Promise<Result<void>> {
    try {
      // Stop flush timer
      const timer = this.flushTimers.get(id);
      if (timer) {
        clearInterval(timer);
        this.flushTimers.delete(id);
      }

      // Clear buffer
      this.streamBuffers.delete(id);

      await this.pool.query(`DELETE FROM ent_log_streams WHERE id = $1`, [id]);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Ingest log event
   */
  async ingestEvent(event: LogEvent): Promise<Result<void>> {
    try {
      // Get all active streams for this account and category
      const streams = await this.pool.query(`
        SELECT * FROM ent_log_streams
        WHERE account_id = $1
        AND status = 'active'
        AND ($2 = ANY(categories) OR 'all' = ANY(categories))
      `, [event.accountId, event.category]);

      for (const row of streams.rows) {
        const stream = this.rowToStream(row);

        // Apply filter rules
        if (stream.filterRules && !this.passesFilters(event, stream.filterRules)) {
          continue;
        }

        // Add to buffer
        if (!this.streamBuffers.has(stream.id)) {
          this.streamBuffers.set(stream.id, []);
          this.setupFlushTimer(stream);
        }

        const buffer = this.streamBuffers.get(stream.id)!;
        buffer.push(event);

        // Check if buffer needs flushing
        const bufferSize = JSON.stringify(buffer).length;
        if (buffer.length >= stream.batchConfig.maxRecords || bufferSize >= stream.batchConfig.maxBytes) {
          await this.flushBuffer(stream.id);
        }
      }

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Flush buffer to destination
   */
  async flushBuffer(streamId: string): Promise<Result<void>> {
    try {
      const buffer = this.streamBuffers.get(streamId);
      if (!buffer || buffer.length === 0) {
        return { ok: true, value: undefined };
      }

      const streamResult = await this.getStream(streamId);
      if (streamResult.ok === false) return { ok: false, error: streamResult.error };

      const stream = streamResult.value;
      const events = [...buffer];
      this.streamBuffers.set(streamId, []);

      const firstEvent = events[0];
      const lastEvent = events[events.length - 1];
      
      if (!firstEvent || !lastEvent) {
        return { ok: false, error: new Error('Empty batch') };
      }

      const batch: StreamBatch = {
        streamId,
        batchId: uuidv4(),
        events,
        startTime: firstEvent.timestamp,
        endTime: lastEvent.timestamp,
        size: JSON.stringify(events).length,
      };

      // Send to destination
      const decryptedConfig = await this.decryptDestinationConfig(stream.destinationConfig);
      let success = false;
      let errorMessage: string | undefined;

      switch (stream.destinationType) {
        case StreamDestinationType.S3: {
          const s3Result = await this.sendToS3(batch, decryptedConfig as S3DestinationConfig, stream.batchConfig);
          success = s3Result.success;
          errorMessage = s3Result.error;
          break;
        }

        case StreamDestinationType.WEBHOOK: {
          const webhookResult = await this.sendToWebhook(batch, decryptedConfig as WebhookConfig);
          success = webhookResult.success;
          errorMessage = webhookResult.error;
          break;
        }

        case StreamDestinationType.SPLUNK: {
          const splunkResult = await this.sendToSplunk(batch, decryptedConfig as SplunkConfig);
          success = splunkResult.success;
          errorMessage = splunkResult.error;
          break;
        }

        case StreamDestinationType.DATADOG: {
          const datadogResult = await this.sendToDatadog(batch, decryptedConfig as DatadogConfig);
          success = datadogResult.success;
          errorMessage = datadogResult.error;
          break;
        }

        case StreamDestinationType.SUMOLOGIC: {
          const sumoResult = await this.sendToSumoLogic(batch, decryptedConfig as SumoLogicConfig);
          success = sumoResult.success;
          errorMessage = sumoResult.error;
          break;
        }

        case StreamDestinationType.GCS: {
          success = false;
          errorMessage = 'GCS delivery adapter unavailable in this build';
          break;
        }

        case StreamDestinationType.AZURE_BLOB: {
          success = false;
          errorMessage = 'Azure Blob delivery adapter unavailable in this build';
          break;
        }

        default:
          errorMessage = 'Destination adapter unavailable in this build';
      }

      // Update stream stats
      if (success) {
        await this.pool.query(`
          UPDATE ent_log_streams SET
            last_streamed_at = NOW(),
            bytes_streamed = bytes_streamed + $2,
            events_streamed = events_streamed + $3,
            updated_at = NOW()
          WHERE id = $1
        `, [streamId, batch.size, batch.events.length]);
      } else {
        await this.pool.query(`
          UPDATE ent_log_streams SET
            last_error = $2,
            error_count = error_count + 1,
            updated_at = NOW()
          WHERE id = $1
        `, [streamId, errorMessage]);

        // Re-add events to buffer for retry
        const currentBuffer = this.streamBuffers.get(streamId) || [];
        this.streamBuffers.set(streamId, [...events, ...currentBuffer]);
      }

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  /**
   * Get stream statistics
   */
  async getStreamStats(streamId: string, startDate: Date, endDate: Date): Promise<Result<{
    eventsStreamed: number;
    bytesStreamed: number;
    errorCount: number;
    successRate: number;
    eventsByCategory: Record<string, number>;
    hourlyVolume: { hour: string; count: number }[];
  }>> {
    try {
      const stream = await this.getStream(streamId);
      if (stream.ok === false) return { ok: false, error: stream.error };

      const batchResult = await this.pool.query(`
        SELECT
          SUM(event_count) as total_events,
          SUM(batch_size) as total_bytes,
          COUNT(*) FILTER (WHERE success = false) as error_count,
          COUNT(*) as total_batches
        FROM ent_stream_batches
        WHERE stream_id = $1
        AND created_at BETWEEN $2 AND $3
      `, [streamId, startDate, endDate]);

      const categoryResult = await this.pool.query(`
        SELECT category, SUM(event_count) as count
        FROM ent_stream_batches
        WHERE stream_id = $1
        AND created_at BETWEEN $2 AND $3
        GROUP BY category
      `, [streamId, startDate, endDate]);

      const hourlyResult = await this.pool.query(`
        SELECT
          DATE_TRUNC('hour', created_at) as hour,
          SUM(event_count) as count
        FROM ent_stream_batches
        WHERE stream_id = $1
        AND created_at BETWEEN $2 AND $3
        GROUP BY DATE_TRUNC('hour', created_at)
        ORDER BY hour
      `, [streamId, startDate, endDate]);

      const stats = batchResult.rows[0];
      const totalBatches = parseInt(stats.total_batches, 10) || 0;
      const errorCount = parseInt(stats.error_count, 10) || 0;

      return {
        ok: true,
        value: {
          eventsStreamed: parseInt(stats.total_events, 10) || 0,
          bytesStreamed: parseInt(stats.total_bytes, 10) || 0,
          errorCount,
          successRate: totalBatches > 0 ? (totalBatches - errorCount) / totalBatches : 1,
          eventsByCategory: Object.fromEntries(
            categoryResult.rows.map(r => [r.category, parseInt(r.count, 10)])
          ),
          hourlyVolume: hourlyResult.rows.map(r => ({
            hour: r.hour.toISOString(),
            count: parseInt(r.count, 10),
          })),
        },
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }

  // Verification methods
  private async verifyS3(config: S3DestinationConfig): Promise<{ success: boolean; message: string }> {
    try {
      const { S3Client, PutObjectCommand, HeadBucketCommand } = await import('@aws-sdk/client-s3');

      const clientConfig: any = { region: config.region };
      if (config.accessKeyId && config.secretAccessKey) {
        clientConfig.credentials = {
          accessKeyId: config.accessKeyId,
          secretAccessKey: config.secretAccessKey,
        };
      }

      const client = new S3Client(clientConfig);

      // Try to check bucket access
      await client.send(new HeadBucketCommand({ Bucket: config.bucket }));

      // Try to write a test file
      const testKey = `${config.prefix || ''}apex-verification-${Date.now()}.txt`;
      await client.send(new PutObjectCommand({
        Bucket: config.bucket,
        Key: testKey,
        Body: 'ApexMail log streaming verification',
      }));

      return { success: true, message: 'S3 bucket access verified successfully' };
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : 'Failed to verify S3 access',
      };
    }
  }

  private async verifyWebhook(config: WebhookConfig): Promise<{ success: boolean; message: string }> {
    try {
      const response = await fetch(config.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...config.headers,
        },
        body: JSON.stringify({
          type: 'verification',
          timestamp: new Date().toISOString(),
        }),
      });

      if (response.ok) {
        return { success: true, message: 'Webhook endpoint verified successfully' };
      }
      return { success: false, message: `Webhook returned status ${response.status}` };
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : 'Failed to verify webhook',
      };
    }
  }

  private async verifySplunk(config: SplunkConfig): Promise<{ success: boolean; message: string }> {
    try {
      const response = await fetch(config.hecUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Splunk ${config.hecToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          event: { type: 'verification', source: 'apexmail' },
          index: config.index,
          source: config.source || 'apexmail',
          sourcetype: config.sourcetype || 'apexmail:log',
        }),
      });

      if (response.ok) {
        return { success: true, message: 'Splunk HEC verified successfully' };
      }
      return { success: false, message: `Splunk returned status ${response.status}` };
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : 'Failed to verify Splunk',
      };
    }
  }

  private async verifyDatadog(config: DatadogConfig): Promise<{ success: boolean; message: string }> {
    try {
      const site = config.site || 'datadoghq.com';
      const response = await fetch(`https://http-intake.logs.${site}/api/v2/logs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'DD-API-KEY': config.apiKey,
        },
        body: JSON.stringify([{
          ddsource: config.source || 'apexmail',
          ddtags: config.tags?.join(','),
          service: config.service || 'apexmail',
          message: 'ApexMail log streaming verification',
        }]),
      });

      if (response.ok) {
        return { success: true, message: 'Datadog verified successfully' };
      }
      return { success: false, message: `Datadog returned status ${response.status}` };
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : 'Failed to verify Datadog',
      };
    }
  }

  private async verifySumoLogic(config: SumoLogicConfig): Promise<{ success: boolean; message: string }> {
    try {
      const testPayload = {
        type: 'verification',
        source: 'apexmail',
        timestamp: new Date().toISOString(),
      };

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      if (config.sourceCategory) headers['X-Sumo-Category'] = config.sourceCategory;
      if (config.sourceName) headers['X-Sumo-Name'] = config.sourceName;
      if (config.sourceHost) headers['X-Sumo-Host'] = config.sourceHost;

      const response = await fetch(config.httpSourceUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(testPayload),
      });

      if (response.ok) {
        return { success: true, message: 'Sumo Logic HTTP source verified successfully' };
      }

      return { success: false, message: `Sumo Logic returned status ${response.status}` };
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : 'Failed to verify Sumo Logic HTTP source',
      };
    }
  }

  private verifyGcsConfig(config: GCSDestinationConfig): { success: boolean; message: string } {
    if (!config.bucket?.trim()) {
      return { success: false, message: 'GCS bucket is required' };
    }

    if (!config.serviceAccountKey?.trim()) {
      return { success: false, message: 'GCS service account key is required' };
    }

    try {
      const parsed = JSON.parse(config.serviceAccountKey) as Record<string, unknown>;
      if (typeof parsed.client_email !== 'string' || typeof parsed.private_key !== 'string') {
        return { success: false, message: 'GCS service account key must include client_email and private_key' };
      }

      return {
        success: false,
        message: 'GCS configuration parsed successfully, but delivery adapter is unavailable in this build',
      };
    } catch {
      return { success: false, message: 'Invalid GCS service account key JSON' };
    }
  }

  private verifyAzureBlobConfig(config: AzureBlobConfig): { success: boolean; message: string } {
    if (!config.container?.trim()) {
      return { success: false, message: 'Azure Blob container is required' };
    }

    const connection = config.connectionString?.trim();
    if (!connection) {
      return { success: false, message: 'Azure Blob connection string is required' };
    }

    if (!/AccountName=/.test(connection) || !/AccountKey=/.test(connection)) {
      return {
        success: false,
        message: 'Azure Blob connection string must include AccountName and AccountKey',
      };
    }

    return {
      success: false,
      message: 'Azure Blob configuration parsed successfully, but delivery adapter is unavailable in this build',
    };
  }

  // Sending methods
  private async sendToS3(batch: StreamBatch, config: S3DestinationConfig, batchConfig: BatchConfig): Promise<{ success: boolean; error?: string }> {
    try {
      const { S3Client, PutObjectCommand } = await import('@aws-sdk/client-s3');
      const zlib = await import('zlib');
      const { promisify } = await import('util');
      const gzip = promisify(zlib.gzip);

      const clientConfig: any = { region: config.region };
      if (config.accessKeyId && config.secretAccessKey) {
        clientConfig.credentials = {
          accessKeyId: config.accessKeyId,
          secretAccessKey: config.secretAccessKey,
        };
      }

      const client = new S3Client(clientConfig);

      // Format data as NDJSON
      let body: Buffer | string = batch.events.map(e => JSON.stringify(e)).join('\n');

      // Compress if configured
      let extension = '.ndjson';
      if (batchConfig.compressionType === 'gzip') {
        body = await gzip(body);
        extension = '.ndjson.gz';
      }

      const date = new Date();
      const key = [
        config.prefix,
        date.getFullYear(),
        String(date.getMonth() + 1).padStart(2, '0'),
        String(date.getDate()).padStart(2, '0'),
        `${batch.batchId}${extension}`,
      ].filter(Boolean).join('/');

      const putParams: any = {
        Bucket: config.bucket,
        Key: key,
        Body: body,
        ContentType: batchConfig.compressionType === 'gzip' ? 'application/gzip' : 'application/x-ndjson',
      };

      if (config.kmsKeyId) {
        putParams.ServerSideEncryption = 'aws:kms';
        putParams.SSEKMSKeyId = config.kmsKeyId;
      }

      await client.send(new PutObjectCommand(putParams));

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'S3 upload failed',
      };
    }
  }

  private async sendToWebhook(batch: StreamBatch, config: WebhookConfig): Promise<{ success: boolean; error?: string }> {
    try {
      const payload = JSON.stringify({
        batchId: batch.batchId,
        events: batch.events,
        timestamp: new Date().toISOString(),
      });

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...config.headers,
      };

      // Add signature if secret is configured
      if (config.secret) {
        const signature = hmacSign(config.secret, payload, 'sha256');
        headers['X-Apex-Signature'] = `sha256=${signature}`;
      }

      const response = await fetch(config.url, {
        method: 'POST',
        headers,
        body: payload,
      });

      if (response.ok) {
        return { success: true };
      }
      return { success: false, error: `Webhook returned ${response.status}` };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Webhook delivery failed',
      };
    }
  }

  private async sendToSplunk(batch: StreamBatch, config: SplunkConfig): Promise<{ success: boolean; error?: string }> {
    try {
      const events = batch.events.map(e => ({
        time: Math.floor(e.timestamp.getTime() / 1000),
        event: e,
        index: config.index,
        source: config.source || 'apexmail',
        sourcetype: config.sourcetype || 'apexmail:log',
      }));

      const response = await fetch(config.hecUrl, {
        method: 'POST',
        headers: {
          'Authorization': `Splunk ${config.hecToken}`,
          'Content-Type': 'application/json',
        },
        body: events.map(e => JSON.stringify(e)).join('\n'),
      });

      if (response.ok) {
        return { success: true };
      }
      return { success: false, error: `Splunk returned ${response.status}` };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Splunk delivery failed',
      };
    }
  }

  private async sendToDatadog(batch: StreamBatch, config: DatadogConfig): Promise<{ success: boolean; error?: string }> {
    try {
      const site = config.site || 'datadoghq.com';
      const logs = batch.events.map(e => ({
        ddsource: config.source || 'apexmail',
        ddtags: config.tags?.join(','),
        service: config.service || 'apexmail',
        message: JSON.stringify(e.data),
        ...e,
      }));

      const response = await fetch(`https://http-intake.logs.${site}/api/v2/logs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'DD-API-KEY': config.apiKey,
        },
        body: JSON.stringify(logs),
      });

      if (response.ok) {
        return { success: true };
      }
      return { success: false, error: `Datadog returned ${response.status}` };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Datadog delivery failed',
      };
    }
  }

  private async sendToSumoLogic(batch: StreamBatch, config: SumoLogicConfig): Promise<{ success: boolean; error?: string }> {
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      if (config.sourceCategory) headers['X-Sumo-Category'] = config.sourceCategory;
      if (config.sourceName) headers['X-Sumo-Name'] = config.sourceName;
      if (config.sourceHost) headers['X-Sumo-Host'] = config.sourceHost;

      const body = batch.events.map((event) => JSON.stringify(event)).join('\n');
      const response = await fetch(config.httpSourceUrl, {
        method: 'POST',
        headers,
        body,
      });

      if (response.ok) {
        return { success: true };
      }

      return { success: false, error: `Sumo Logic returned ${response.status}` };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Sumo Logic delivery failed',
      };
    }
  }

  private passesFilters(event: LogEvent, rules: FilterRule[]): boolean {
    for (const rule of rules) {
      const value = this.getNestedValue(event, rule.field);

      switch (rule.operator) {
        case 'equals':
          if (value !== rule.value) return false;
          break;
        case 'not_equals':
          if (value === rule.value) return false;
          break;
        case 'contains':
          if (!String(value).includes(String(rule.value))) return false;
          break;
        case 'not_contains':
          if (String(value).includes(String(rule.value))) return false;
          break;
        case 'regex':
          if (!new RegExp(String(rule.value)).test(String(value))) return false;
          break;
        case 'in':
          if (!Array.isArray(rule.value) || !rule.value.includes(value)) return false;
          break;
        case 'not_in':
          if (Array.isArray(rule.value) && rule.value.includes(value)) return false;
          break;
      }
    }
    return true;
  }

  private getNestedValue(obj: any, path: string): any {
    // FIX-500-345: Short-circuit on blocked keys instead of continuing traversal
    const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
    const parts = path.split('.');
    let current = obj;
    for (const k of parts) {
      if (BLOCKED_KEYS.has(k)) return undefined;
      current = (current || {})[k];
    }
    return current;
  }

  private setupFlushTimer(stream: LogStream): void {
    if (this.flushTimers.has(stream.id)) return;

    const timer = setInterval(
      () => this.flushBuffer(stream.id),
      stream.batchConfig.flushIntervalSeconds * 1000
    );
    this.flushTimers.set(stream.id, timer);
  }

  private async encryptDestinationConfig(config: DestinationConfig): Promise<DestinationConfig> {
    const sensitiveFields = ['secretAccessKey', 'serviceAccountKey', 'connectionString', 'hecToken', 'apiKey', 'secret'];
    const encrypted = { ...config } as Record<string, unknown>;

    for (const field of sensitiveFields) {
      const fieldValue = encrypted[field];
      if (fieldValue && typeof fieldValue === 'string') {
        encrypted[field] = this.encrypt(fieldValue);
      }
    }

    // Return with proper type assertion - we know the structure matches DestinationConfig
    return encrypted as unknown as DestinationConfig;
  }

  private async decryptDestinationConfig(config: DestinationConfig): Promise<DestinationConfig> {
    const sensitiveFields = ['secretAccessKey', 'serviceAccountKey', 'connectionString', 'hecToken', 'apiKey', 'secret'];
    const decrypted = { ...config } as Record<string, unknown>;

    for (const field of sensitiveFields) {
      const fieldValue = decrypted[field];
      if (fieldValue && typeof fieldValue === 'string') {
        decrypted[field] = this.decrypt(fieldValue);
      }
    }

    // Return with proper type assertion - we know the structure matches DestinationConfig
    return decrypted as unknown as DestinationConfig;
  }

  // FIX-500-034: Use AES-256-GCM (authenticated encryption) instead of AES-256-CBC
  // which is vulnerable to padding oracle attacks.
  private encrypt(text: string): string {
    const key = deriveKeySync(config.logStreaming.encryptionKey, 'log-streaming', 32);
    const payload = encryptAES256GCM(Buffer.from(text, 'utf8'), key).toString('base64');
    return `gcm:${payload}`;
  }

  private decrypt(text: string): string {
    // Try GCM first (new format: gcm:<base64(iv|tag|ciphertext)>)
    if (text.startsWith('gcm:')) {
      const key = deriveKeySync(config.logStreaming.encryptionKey, 'log-streaming', 32);
      const raw = Buffer.from(text.slice(4), 'base64');
      const gcmResult = decryptAES256GCM(raw, key);
      if (gcmResult.ok) {
        return gcmResult.value.toString('utf8');
      }
    }
    // Fallback to legacy CBC for existing encrypted data
    const cbcResult = decryptAES256CBC(text, config.logStreaming.encryptionKey, 'salt');
    if (!cbcResult.ok) {
      throw cbcResult.error;
    }
    // FIX-500-344: Log migration hint so callers can re-encrypt with GCM
    logger.info('Legacy CBC-encrypted credential decrypted; callers should re-encrypt with GCM');
    return cbcResult.value;
  }

  /**
   * Process batch for a stream (called by background job scheduler)
   */
  async processBatch(streamId: string): Promise<Result<void>> {
    return this.flushBuffer(streamId);
  }

  private rowToStream(row: any): LogStream {
    return {
      id: row.id,
      accountId: row.account_id,
      name: row.name,
      destinationType: row.destination_type as StreamDestinationType,
      destinationConfig: row.destination_config,
      categories: row.categories,
      status: row.status as StreamStatus,
      filterRules: row.filter_rules,
      batchConfig: row.batch_config,
      lastStreamedAt: row.last_streamed_at,
      lastError: row.last_error,
      errorCount: row.error_count,
      bytesStreamed: row.bytes_streamed,
      eventsStreamed: row.events_streamed,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
