/**
 * Queue Notifier - PostgreSQL LISTEN/NOTIFY wakeup for queue processors
 *
 * Replaces constant polling with event-driven wakeup. Each queue table has an
 * AFTER INSERT trigger that calls pg_notify('queue_<table>', id). This module
 * LISTENs on those channels and resolves pending wakeup promises so processors
 * wake immediately instead of sleeping for their full pollInterval.
 *
 * Fallback: if no notification arrives within `fallbackMs`, the processor wakes
 * anyway (defensive against missed notifications or reconnect gaps).
 */

import { Client, type ClientConfig } from 'pg';
import type { Logger } from '@apexmail/lib';
import { EventEmitter } from 'events';

const CHANNELS = [
  'queue_email_queue',
  'queue_webhook_queue',
  'queue_analytics_queue',
] as const;

export type QueueChannel = typeof CHANNELS[number];

export class QueueNotifier extends EventEmitter {
  private client: Client | null = null;
  private readonly clientConfig: ClientConfig;
  private readonly logger: Logger;
  private isRunning = false;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private readonly reconnectDelay = 3000;

  constructor(clientConfig: ClientConfig, logger: Logger) {
    super();
    this.clientConfig = clientConfig;
    this.logger = logger;
  }

  async start(): Promise<void> {
    this.isRunning = true;
    await this.connect();
  }

  async stop(): Promise<void> {
    this.isRunning = false;

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.client) {
      try {
        for (const ch of CHANNELS) {
          await this.client.query(`UNLISTEN ${ch}`);
        }
      } catch {
        // Ignore errors during shutdown
      }
      await this.client.end().catch(() => {});
      this.client = null;
    }

    this.logger.info('Queue notifier stopped');
  }

  /**
   * Returns a Promise that resolves when a notification arrives on `channel`
   * or after `fallbackMs` (whichever comes first). This replaces the static
   * `setTimeout(pollInterval)` sleep in each processor's poll loop.
   */
  waitForNotification(channel: QueueChannel, fallbackMs: number): Promise<void> {
    return new Promise<void>((resolve) => {
      let resolved = false;
      const timer = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          this.removeListener(channel, onNotify);
          resolve();
        }
      }, fallbackMs);

      const onNotify = () => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          resolve();
        }
      };

      this.once(channel, onNotify);
    });
  }

  private async connect(): Promise<void> {
    try {
      this.client = new Client(this.clientConfig);

      this.client.on('error', (err) => {
        this.logger.error('Queue notifier connection error', { error: err.message });
        this.scheduleReconnect();
      });

      this.client.on('end', () => {
        if (this.isRunning) {
          this.logger.warn('Queue notifier connection closed unexpectedly');
          this.scheduleReconnect();
        }
      });

      this.client.on('notification', (msg) => {
        if (msg.channel) {
          this.emit(msg.channel);
        }
      });

      await this.client.connect();

      for (const ch of CHANNELS) {
        await this.client.query(`LISTEN ${ch}`);
      }

      this.logger.info('Queue notifier listening', { channels: [...CHANNELS] });
    } catch (err) {
      this.logger.error('Queue notifier failed to connect', { error: err });
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (!this.isRunning) return;
    if (this.reconnectTimer) return; // Already scheduled

    // Clean up old client
    if (this.client) {
      this.client.removeAllListeners();
      this.client.end().catch(() => {});
      this.client = null;
    }

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      if (this.isRunning) {
        this.logger.info('Queue notifier reconnecting...');
        await this.connect();
      }
    }, this.reconnectDelay);
  }
}
