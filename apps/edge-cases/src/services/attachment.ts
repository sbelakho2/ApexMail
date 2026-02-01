/**
 * Attachment Handling Service
 * 
 * Virus scanning, size limits, type restrictions, and MIME handling
 */

import { Pool } from 'pg';
import Redis from 'ioredis';
import * as mimeTypes from 'mime-types';
import { config, BASE64_OVERHEAD } from '../config.js';
import net from 'net';

// Result type for error handling
type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export interface Attachment {
  filename: string;
  contentType: string;
  content: Buffer;
  size: number;
  disposition: 'attachment' | 'inline';
  contentId?: string;
}

export interface AttachmentValidation {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  virusScanned: boolean;
  virusDetected: boolean;
  virusName?: string;
}

export interface MessageSizeValidation {
  isValid: boolean;
  estimatedSize: number;
  maxSize: number;
  error?: string;
}

export interface VirusScanResult {
  isClean: boolean;
  virusName?: string;
  scanTime: number;
  error?: string;
}

export interface AttachmentStats {
  count: number;
  totalSize: number;
  mimeTypes: string[];
  hasInline: boolean;
  hasAttachment: boolean;
}

/**
 * Attachment Service for handling email attachments
 */
export class AttachmentService {
  private pool: Pool;
  private redis: Redis;
  private clamavSocket?: net.Socket;

  constructor(pool: Pool, redis: Redis) {
    this.pool = pool;
    this.redis = redis;
  }

  /**
   * Validate a single attachment
   */
  async validateAttachment(attachment: Attachment): Promise<Result<AttachmentValidation>> {
    const errors: string[] = [];
    const warnings: string[] = [];
    let virusScanned = false;
    let virusDetected = false;
    let virusName: string | undefined;

    try {
      // Check file size
      if (attachment.size > config.attachments.maxSingleAttachmentSize) {
        errors.push(
          `Attachment "${attachment.filename}" exceeds size limit: ${this.formatSize(attachment.size)} > ${this.formatSize(config.attachments.maxSingleAttachmentSize)}`
        );
      }

      // Check file extension
      const extension = this.getFileExtension(attachment.filename);
      if (config.attachments.blockedExtensions.includes(extension.toLowerCase())) {
        errors.push(`File extension "${extension}" is not allowed for security reasons`);
      }

      // Check MIME type
      const detectedMimeType = this.detectMimeType(attachment.filename, attachment.content);
      if (config.attachments.blockedMimeTypes.includes(detectedMimeType)) {
        errors.push(`MIME type "${detectedMimeType}" is not allowed for security reasons`);
      }

      // Verify MIME type matches extension
      if (attachment.contentType !== detectedMimeType) {
        warnings.push(
          `Declared content type (${attachment.contentType}) differs from detected type (${detectedMimeType})`
        );
      }

      // Check for double extensions (e.g., file.pdf.exe)
      const doubleExtension = this.checkDoubleExtension(attachment.filename);
      if (doubleExtension) {
        warnings.push(`Suspicious double extension detected: ${doubleExtension}`);
      }

      // Virus scan if ClamAV is enabled
      if (config.clamav.enabled && errors.length === 0) {
        const scanResult = await this.scanForVirus(attachment.content);
        virusScanned = !scanResult.error;
        virusDetected = !scanResult.isClean;
        virusName = scanResult.virusName;

        if (virusDetected) {
          errors.push(`Virus detected: ${virusName}`);
        }

        if (scanResult.error) {
          warnings.push(`Virus scan failed: ${scanResult.error}`);
        }
      }

      // Check for encrypted/password-protected content
      if (this.isEncryptedContent(attachment.content, attachment.contentType)) {
        warnings.push('Attachment appears to be password-protected or encrypted');
      }

      return {
        ok: true,
        value: {
          isValid: errors.length === 0,
          errors,
          warnings,
          virusScanned,
          virusDetected,
          virusName,
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
   * Validate all attachments in a message
   */
  async validateAttachments(attachments: Attachment[]): Promise<Result<AttachmentValidation>> {
    const errors: string[] = [];
    const warnings: string[] = [];
    let virusScanned = true;
    let virusDetected = false;
    let virusName: string | undefined;

    try {
      // Check attachment count
      if (attachments.length > config.attachments.maxAttachmentCount) {
        errors.push(
          `Too many attachments: ${attachments.length} > ${config.attachments.maxAttachmentCount}`
        );
      }

      // Calculate total size
      const totalSize = attachments.reduce((sum, att) => sum + att.size, 0);
      if (totalSize > config.attachments.maxTotalMessageSize) {
        errors.push(
          `Total attachment size exceeds limit: ${this.formatSize(totalSize)} > ${this.formatSize(config.attachments.maxTotalMessageSize)}`
        );
      }

      // Validate each attachment
      for (const attachment of attachments) {
        const result = await this.validateAttachment(attachment);
        if (!result.ok) {
          return { ok: false, error: result.error };
        }

        errors.push(...result.value.errors);
        warnings.push(...result.value.warnings);
        virusScanned = virusScanned && result.value.virusScanned;
        
        if (result.value.virusDetected) {
          virusDetected = true;
          virusName = result.value.virusName;
        }
      }

      return {
        ok: true,
        value: {
          isValid: errors.length === 0,
          errors,
          warnings,
          virusScanned,
          virusDetected,
          virusName,
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
   * Pre-check message size before queuing
   */
  validateMessageSize(
    bodySize: number,
    attachments: { size: number }[],
    htmlSize?: number
  ): MessageSizeValidation {
    // Calculate estimated MIME message size
    let estimatedSize = 0;

    // Email headers (estimate ~1KB)
    estimatedSize += 1024;

    // Text body (assume plain text boundary + content)
    estimatedSize += bodySize + 200;

    // HTML body if present (boundary + content)
    if (htmlSize) {
      estimatedSize += htmlSize + 200;
    }

    // Attachments (base64 encoded)
    for (const attachment of attachments) {
      // Base64 encoding overhead + headers
      estimatedSize += Math.ceil(attachment.size * BASE64_OVERHEAD) + 500;
    }

    // MIME boundaries overhead
    estimatedSize += (attachments.length + 2) * 100;

    const maxSize = config.attachments.maxTotalMessageSize;

    if (estimatedSize > maxSize) {
      return {
        isValid: false,
        estimatedSize,
        maxSize,
        error: `Estimated message size (${this.formatSize(estimatedSize)}) exceeds maximum allowed (${this.formatSize(maxSize)})`,
      };
    }

    return {
      isValid: true,
      estimatedSize,
      maxSize,
    };
  }

  /**
   * Scan content for viruses using ClamAV
   */
  private async scanForVirus(content: Buffer): Promise<VirusScanResult> {
    const startTime = Date.now();

    try {
      return await new Promise((resolve) => {
        const socket = new net.Socket();
        let response = '';

        socket.setTimeout(config.clamav.timeout);

        socket.on('timeout', () => {
          socket.destroy();
          resolve({
            isClean: true,
            scanTime: Date.now() - startTime,
            error: 'Scan timeout',
          });
        });

        socket.on('error', (err) => {
          resolve({
            isClean: true,
            scanTime: Date.now() - startTime,
            error: err.message,
          });
        });

        socket.on('data', (data) => {
          response += data.toString();
        });

        socket.on('end', () => {
          const scanTime = Date.now() - startTime;
          
          // Parse ClamAV response
          // Format: "stream: FOUND" or "stream: OK"
          if (response.includes('OK')) {
            resolve({
              isClean: true,
              scanTime,
            });
          } else {
            const virusMatch = response.match(/stream:\s+(.+)\s+FOUND/);
            resolve({
              isClean: false,
              virusName: virusMatch?.[1] || 'Unknown',
              scanTime,
            });
          }
        });

        socket.connect(config.clamav.port, config.clamav.host, () => {
          // Send INSTREAM command
          const sizeBuffer = Buffer.alloc(4);
          sizeBuffer.writeUInt32BE(content.length, 0);

          socket.write('nINSTREAM\n');
          socket.write(sizeBuffer);
          socket.write(content);
          
          // Send zero-length chunk to signal end
          const endBuffer = Buffer.alloc(4);
          endBuffer.writeUInt32BE(0, 0);
          socket.write(endBuffer);
        });
      });
    } catch (error) {
      return {
        isClean: true,
        scanTime: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Detect MIME type from filename and content
   */
  private detectMimeType(filename: string, content: Buffer): string {
    // First try to detect from content (magic bytes)
    const magicType = this.detectFromMagicBytes(content);
    if (magicType) {
      return magicType;
    }

    // Fall back to extension-based detection
    return mimeTypes.lookup(filename) || 'application/octet-stream';
  }

  /**
   * Detect MIME type from magic bytes
   */
  private detectFromMagicBytes(content: Buffer): string | null {
    if (content.length < 4) return null;

    // PDF: %PDF
    if (content.slice(0, 4).toString() === '%PDF') {
      return 'application/pdf';
    }

    // ZIP: PK\x03\x04
    if (content[0] === 0x50 && content[1] === 0x4B && content[2] === 0x03 && content[3] === 0x04) {
      // Check for specific ZIP-based formats
      if (content.includes(Buffer.from('[Content_Types].xml'))) {
        // Office Open XML (docx, xlsx, pptx)
        return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
      }
      return 'application/zip';
    }

    // JPEG: FF D8 FF
    if (content[0] === 0xFF && content[1] === 0xD8 && content[2] === 0xFF) {
      return 'image/jpeg';
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (content[0] === 0x89 && content[1] === 0x50 && content[2] === 0x4E && content[3] === 0x47) {
      return 'image/png';
    }

    // GIF: GIF87a or GIF89a
    if (content.slice(0, 3).toString() === 'GIF') {
      return 'image/gif';
    }

    // Windows executable: MZ
    if (content[0] === 0x4D && content[1] === 0x5A) {
      return 'application/x-msdownload';
    }

    // RAR: Rar!
    if (content.slice(0, 4).toString() === 'Rar!') {
      return 'application/x-rar-compressed';
    }

    // 7z: 7z\xBC\xAF\x27\x1C
    if (content[0] === 0x37 && content[1] === 0x7A && content[2] === 0xBC && content[3] === 0xAF) {
      return 'application/x-7z-compressed';
    }

    return null;
  }

  /**
   * Get file extension from filename
   */
  private getFileExtension(filename: string): string {
    const lastDot = filename.lastIndexOf('.');
    if (lastDot === -1) return '';
    return filename.substring(lastDot);
  }

  /**
   * Check for suspicious double extensions
   */
  private checkDoubleExtension(filename: string): string | null {
    const dangerousExtensions = ['.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.js', '.vbs'];
    const parts = filename.split('.');

    if (parts.length > 2) {
      const lastExt = '.' + parts[parts.length - 1].toLowerCase();
      const secondLastExt = '.' + parts[parts.length - 2].toLowerCase();

      // Check if the last extension is dangerous
      if (dangerousExtensions.includes(lastExt)) {
        return `${secondLastExt}${lastExt}`;
      }
    }

    return null;
  }

  /**
   * Check if content appears to be encrypted
   */
  private isEncryptedContent(content: Buffer, contentType: string): boolean {
    // Check for password-protected PDF
    if (contentType === 'application/pdf') {
      const pdfString = content.toString('latin1');
      if (pdfString.includes('/Encrypt')) {
        return true;
      }
    }

    // Check for password-protected ZIP
    if (contentType === 'application/zip') {
      // Check for encryption flag in local file header
      if (content.length > 8 && (content[6] & 0x01) === 1) {
        return true;
      }
    }

    return false;
  }

  /**
   * Format file size for display
   */
  private formatSize(bytes: number): string {
    const units = ['B', 'KB', 'MB', 'GB'];
    let unitIndex = 0;
    let size = bytes;

    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }

    return `${size.toFixed(1)}${units[unitIndex]}`;
  }

  /**
   * Get attachment statistics
   */
  getAttachmentStats(attachments: Attachment[]): AttachmentStats {
    return {
      count: attachments.length,
      totalSize: attachments.reduce((sum, att) => sum + att.size, 0),
      mimeTypes: [...new Set(attachments.map(att => att.contentType))],
      hasInline: attachments.some(att => att.disposition === 'inline'),
      hasAttachment: attachments.some(att => att.disposition === 'attachment'),
    };
  }

  /**
   * Store attachment scan result
   */
  async recordScanResult(
    messageId: string,
    filename: string,
    result: AttachmentValidation
  ): Promise<Result<void>> {
    try {
      await this.pool.query(`
        INSERT INTO edge_attachment_scans (
          message_id, filename, is_valid, virus_scanned, virus_detected,
          virus_name, errors, warnings, scanned_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      `, [
        messageId,
        filename,
        result.isValid,
        result.virusScanned,
        result.virusDetected,
        result.virusName,
        JSON.stringify(result.errors),
        JSON.stringify(result.warnings),
      ]);

      return { ok: true, value: undefined };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error : new Error(String(error)),
      };
    }
  }
}
