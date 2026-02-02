/**
 * CLI Tool Service
 * 
 * Provides CLI for ApexMail operations:
 * - Email sending
 * - Domain management
 * - API key management
 * - Configuration
 * - Testing
 */

import type { Pool } from 'pg';
import { config } from '../config.js';

export interface CliCommand {
  name: string;
  description: string;
  usage: string;
  options: CliOption[];
  examples: string[];
  action: string;
}

export interface CliOption {
  flag: string;
  description: string;
  required: boolean;
  type: 'string' | 'boolean' | 'number';
  defaultValue?: string | boolean | number;
}

type Result<T, E = Error> = { ok: true; value: T } | { ok: false; error: E };

export class CliToolService {
  protected db: Pool;
  private commands: Map<string, CliCommand>;

  constructor(db: Pool) {
    this.db = db;
    this.commands = new Map();
    this.initializeCommands();
  }

  private initializeCommands(): void {
    // Configure command
    this.commands.set('configure', {
      name: 'configure',
      description: 'Configure ApexMail CLI with your API key',
      usage: 'apexmail configure [options]',
      options: [
        { flag: '--api-key <key>', description: 'Your ApexMail API key', required: false, type: 'string' },
        { flag: '--profile <name>', description: 'Profile name for multiple accounts', required: false, type: 'string', defaultValue: 'default' },
      ],
      examples: [
        'apexmail configure --api-key apx_live_abc123',
        'apexmail configure --profile production',
      ],
      action: 'configure',
    });

    // Send command
    this.commands.set('send', {
      name: 'send',
      description: 'Send an email',
      usage: 'apexmail send [options]',
      options: [
        { flag: '--from <email>', description: 'Sender email address', required: true, type: 'string' },
        { flag: '--to <emails>', description: 'Recipient email addresses (comma-separated)', required: true, type: 'string' },
        { flag: '--subject <text>', description: 'Email subject', required: true, type: 'string' },
        { flag: '--text <content>', description: 'Plain text content', required: false, type: 'string' },
        { flag: '--html <content>', description: 'HTML content', required: false, type: 'string' },
        { flag: '--template <id>', description: 'Template ID to use', required: false, type: 'string' },
        { flag: '--data <json>', description: 'Template data as JSON', required: false, type: 'string' },
        { flag: '--attachment <path>', description: 'File attachment path', required: false, type: 'string' },
        { flag: '--schedule <datetime>', description: 'Schedule for future delivery (ISO 8601)', required: false, type: 'string' },
        { flag: '--dry-run', description: 'Validate without sending', required: false, type: 'boolean', defaultValue: false },
      ],
      examples: [
        'apexmail send --from sender@example.com --to recipient@example.com --subject "Hello" --text "Hi there!"',
        'apexmail send --from sender@example.com --to user1@example.com,user2@example.com --subject "Newsletter" --html "<h1>News</h1>"',
        'apexmail send --from sender@example.com --to recipient@example.com --template tpl_abc123 --data \'{"name":"John"}\'',
      ],
      action: 'send',
    });

    // Domains command
    this.commands.set('domains', {
      name: 'domains',
      description: 'Manage sending domains',
      usage: 'apexmail domains <subcommand> [options]',
      options: [
        { flag: 'list', description: 'List all domains', required: false, type: 'string' },
        { flag: 'add <domain>', description: 'Add a new domain', required: false, type: 'string' },
        { flag: 'verify <domain>', description: 'Verify domain DNS records', required: false, type: 'string' },
        { flag: 'remove <domain>', description: 'Remove a domain', required: false, type: 'string' },
        { flag: 'dns <domain>', description: 'Show DNS records to configure', required: false, type: 'string' },
        { flag: '--format <type>', description: 'Output format (table, json, yaml)', required: false, type: 'string', defaultValue: 'table' },
      ],
      examples: [
        'apexmail domains list',
        'apexmail domains add example.com',
        'apexmail domains verify example.com',
        'apexmail domains dns example.com --format json',
      ],
      action: 'domains',
    });

    // Templates command
    this.commands.set('templates', {
      name: 'templates',
      description: 'Manage email templates',
      usage: 'apexmail templates <subcommand> [options]',
      options: [
        { flag: 'list', description: 'List all templates', required: false, type: 'string' },
        { flag: 'get <id>', description: 'Get template details', required: false, type: 'string' },
        { flag: 'create', description: 'Create a new template', required: false, type: 'string' },
        { flag: 'update <id>', description: 'Update a template', required: false, type: 'string' },
        { flag: 'delete <id>', description: 'Delete a template', required: false, type: 'string' },
        { flag: 'preview <id>', description: 'Preview template with sample data', required: false, type: 'string' },
        { flag: '--name <name>', description: 'Template name', required: false, type: 'string' },
        { flag: '--subject <text>', description: 'Template subject', required: false, type: 'string' },
        { flag: '--html-file <path>', description: 'Path to HTML file', required: false, type: 'string' },
        { flag: '--text-file <path>', description: 'Path to text file', required: false, type: 'string' },
        { flag: '--data <json>', description: 'Preview data as JSON', required: false, type: 'string' },
      ],
      examples: [
        'apexmail templates list',
        'apexmail templates create --name "Welcome" --subject "Welcome {{name}}!" --html-file welcome.html',
        'apexmail templates preview tpl_abc123 --data \'{"name":"John"}\'',
      ],
      action: 'templates',
    });

    // Webhooks command
    this.commands.set('webhooks', {
      name: 'webhooks',
      description: 'Manage webhook endpoints',
      usage: 'apexmail webhooks <subcommand> [options]',
      options: [
        { flag: 'list', description: 'List all webhooks', required: false, type: 'string' },
        { flag: 'create', description: 'Create a new webhook', required: false, type: 'string' },
        { flag: 'update <id>', description: 'Update a webhook', required: false, type: 'string' },
        { flag: 'delete <id>', description: 'Delete a webhook', required: false, type: 'string' },
        { flag: 'test <id>', description: 'Send a test event', required: false, type: 'string' },
        { flag: 'logs <id>', description: 'View delivery logs', required: false, type: 'string' },
        { flag: '--url <url>', description: 'Webhook URL', required: false, type: 'string' },
        { flag: '--events <events>', description: 'Events to subscribe to (comma-separated)', required: false, type: 'string' },
        { flag: '--enabled', description: 'Enable webhook', required: false, type: 'boolean' },
      ],
      examples: [
        'apexmail webhooks list',
        'apexmail webhooks create --url https://example.com/webhook --events email.delivered,email.bounced',
        'apexmail webhooks test wh_abc123',
      ],
      action: 'webhooks',
    });

    // API keys command
    this.commands.set('apikeys', {
      name: 'apikeys',
      description: 'Manage API keys',
      usage: 'apexmail apikeys <subcommand> [options]',
      options: [
        { flag: 'list', description: 'List all API keys', required: false, type: 'string' },
        { flag: 'create', description: 'Create a new API key', required: false, type: 'string' },
        { flag: 'revoke <id>', description: 'Revoke an API key', required: false, type: 'string' },
        { flag: '--name <name>', description: 'API key name', required: false, type: 'string' },
        { flag: '--scopes <scopes>', description: 'Scopes (comma-separated)', required: false, type: 'string' },
        { flag: '--expires <date>', description: 'Expiration date (ISO 8601)', required: false, type: 'string' },
      ],
      examples: [
        'apexmail apikeys list',
        'apexmail apikeys create --name "Production" --scopes emails:send,domains:read',
        'apexmail apikeys revoke key_abc123',
      ],
      action: 'apikeys',
    });

    // Analytics command
    this.commands.set('analytics', {
      name: 'analytics',
      description: 'View email analytics',
      usage: 'apexmail analytics [options]',
      options: [
        { flag: '--start <date>', description: 'Start date (ISO 8601)', required: false, type: 'string' },
        { flag: '--end <date>', description: 'End date (ISO 8601)', required: false, type: 'string' },
        { flag: '--domain <domain>', description: 'Filter by domain', required: false, type: 'string' },
        { flag: '--tag <tag>', description: 'Filter by tag', required: false, type: 'string' },
        { flag: '--format <type>', description: 'Output format (table, json, csv)', required: false, type: 'string', defaultValue: 'table' },
      ],
      examples: [
        'apexmail analytics --start 2024-01-01 --end 2024-01-31',
        'apexmail analytics --domain example.com --format json',
      ],
      action: 'analytics',
    });

    // Email command
    this.commands.set('email', {
      name: 'email',
      description: 'Get email details and events',
      usage: 'apexmail email <id> [options]',
      options: [
        { flag: '<id>', description: 'Email ID', required: true, type: 'string' },
        { flag: '--events', description: 'Show email events', required: false, type: 'boolean' },
        { flag: '--format <type>', description: 'Output format (table, json)', required: false, type: 'string', defaultValue: 'table' },
      ],
      examples: [
        'apexmail email msg_abc123',
        'apexmail email msg_abc123 --events',
      ],
      action: 'email',
    });

    // Validate command
    this.commands.set('validate', {
      name: 'validate',
      description: 'Validate email addresses',
      usage: 'apexmail validate <email> [options]',
      options: [
        { flag: '<email>', description: 'Email address to validate', required: true, type: 'string' },
        { flag: '--file <path>', description: 'File with email addresses (one per line)', required: false, type: 'string' },
        { flag: '--format <type>', description: 'Output format (table, json)', required: false, type: 'string', defaultValue: 'table' },
      ],
      examples: [
        'apexmail validate user@example.com',
        'apexmail validate --file emails.txt --format json',
      ],
      action: 'validate',
    });

    // Test command
    this.commands.set('test', {
      name: 'test',
      description: 'Test API connectivity and configuration',
      usage: 'apexmail test [options]',
      options: [
        { flag: '--verbose', description: 'Show detailed output', required: false, type: 'boolean' },
      ],
      examples: [
        'apexmail test',
        'apexmail test --verbose',
      ],
      action: 'test',
    });

    // Logs command
    this.commands.set('logs', {
      name: 'logs',
      description: 'View activity logs',
      usage: 'apexmail logs [options]',
      options: [
        { flag: '--limit <n>', description: 'Number of logs to show', required: false, type: 'number', defaultValue: 50 },
        { flag: '--type <type>', description: 'Filter by event type', required: false, type: 'string' },
        { flag: '--start <date>', description: 'Start date (ISO 8601)', required: false, type: 'string' },
        { flag: '--end <date>', description: 'End date (ISO 8601)', required: false, type: 'string' },
        { flag: '--follow', description: 'Follow logs in real-time', required: false, type: 'boolean' },
        { flag: '--format <type>', description: 'Output format (table, json)', required: false, type: 'string', defaultValue: 'table' },
      ],
      examples: [
        'apexmail logs',
        'apexmail logs --type email.bounced --limit 100',
        'apexmail logs --follow',
      ],
      action: 'logs',
    });
  }

  /**
   * Get all CLI commands
   */
  async getCommands(): Promise<Result<CliCommand[]>> {
    try {
      return { ok: true, value: Array.from(this.commands.values()) };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Get a specific command
   */
  async getCommand(name: string): Promise<Result<CliCommand | null>> {
    try {
      return { ok: true, value: this.commands.get(name) ?? null };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  /**
   * Generate CLI source code
   */
  async generateCli(): Promise<Result<{ files: CliFile[] }>> {
    try {
      const files: CliFile[] = [];

      // package.json
      files.push({
        path: 'package.json',
        content: JSON.stringify({
          name: '@apexmail/cli',
          version: '1.0.0',
          description: 'ApexMail CLI',
          type: 'module',
          bin: {
            apexmail: './dist/cli.js',
          },
          scripts: {
            build: 'tsc',
            start: 'node dist/cli.js',
          },
          dependencies: {
            commander: '^11.1.0',
            inquirer: '^9.2.12',
            chalk: '^5.3.0',
            ora: '^8.0.1',
            yaml: '^2.3.4',
            'cli-table3': '^0.6.3',
          },
          devDependencies: {
            '@types/node': '^20.10.0',
            typescript: '^5.3.3',
          },
          engines: { node: '>=18.0.0' },
          license: 'MIT',
        }, null, 2),
      });

      // Main CLI entry point
      files.push({
        path: 'src/cli.ts',
        content: this.generateMainCli(),
      });

      // Config manager
      files.push({
        path: 'src/config.ts',
        content: this.generateConfigManager(),
      });

      // HTTP client
      files.push({
        path: 'src/http.ts',
        content: this.generateHttpClient(),
      });

      // Commands
      for (const command of this.commands.values()) {
        files.push({
          path: `src/commands/${command.name}.ts`,
          content: this.generateCommandFile(command),
        });
      }

      // Utils
      files.push({
        path: 'src/utils/output.ts',
        content: this.generateOutputUtils(),
      });

      return { ok: true, value: { files } };
    } catch (error) {
      return { ok: false, error: error as Error };
    }
  }

  private generateMainCli(): string {
    return `#!/usr/bin/env node
/**
 * ApexMail CLI
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { configureCommand } from './commands/configure.js';
import { sendCommand } from './commands/send.js';
import { domainsCommand } from './commands/domains.js';
import { templatesCommand } from './commands/templates.js';
import { webhooksCommand } from './commands/webhooks.js';
import { apikeysCommand } from './commands/apikeys.js';
import { analyticsCommand } from './commands/analytics.js';
import { emailCommand } from './commands/email.js';
import { validateCommand } from './commands/validate.js';
import { testCommand } from './commands/test.js';
import { logsCommand } from './commands/logs.js';

const program = new Command();

program
  .name('apexmail')
  .description('ApexMail CLI - Send and manage transactional emails')
  .version('1.0.0')
  .option('--profile <name>', 'Use a specific profile', 'default')
  .option('--api-key <key>', 'API key (overrides profile)')
  .option('--json', 'Output as JSON')
  .option('--no-color', 'Disable colored output');

// Register commands
program.addCommand(configureCommand);
program.addCommand(sendCommand);
program.addCommand(domainsCommand);
program.addCommand(templatesCommand);
program.addCommand(webhooksCommand);
program.addCommand(apikeysCommand);
program.addCommand(analyticsCommand);
program.addCommand(emailCommand);
program.addCommand(validateCommand);
program.addCommand(testCommand);
program.addCommand(logsCommand);

// Error handling
program.configureOutput({
  writeErr: (str) => process.stderr.write(chalk.red(str)),
});

program.parseAsync(process.argv).catch((error) => {
  console.error(chalk.red('Error:'), error.message);
  process.exit(1);
});
`;
  }

  private generateConfigManager(): string {
    return `/**
 * Configuration Manager
 */

import { homedir } from 'os';
import { join } from 'path';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import yaml from 'yaml';

export interface Profile {
  apiKey: string;
  baseUrl?: string;
  apiVersion?: string;
}

export interface Config {
  defaultProfile: string;
  profiles: Record<string, Profile>;
}

const CONFIG_DIR = join(homedir(), '.apexmail');
const CONFIG_FILE = join(CONFIG_DIR, 'config.yaml');

export function ensureConfigDir(): void {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true });
  }
}

export function loadConfig(): Config {
  ensureConfigDir();
  
  if (!existsSync(CONFIG_FILE)) {
    return {
      defaultProfile: 'default',
      profiles: {},
    };
  }

  const content = readFileSync(CONFIG_FILE, 'utf-8');
  return yaml.parse(content) as Config;
}

export function saveConfig(config: Config): void {
  ensureConfigDir();
  const content = yaml.stringify(config);
  writeFileSync(CONFIG_FILE, content, 'utf-8');
}

export function getProfile(name: string): Profile | null {
  const config = loadConfig();
  return config.profiles[name] ?? null;
}

export function setProfile(name: string, profile: Profile): void {
  const config = loadConfig();
  config.profiles[name] = profile;
  saveConfig(config);
}

export function getApiKey(profileName?: string, overrideKey?: string): string {
  if (overrideKey) {
    return overrideKey;
  }

  const config = loadConfig();
  const name = profileName ?? config.defaultProfile;
  const profile = config.profiles[name];

  if (!profile?.apiKey) {
    throw new Error(
      \`No API key configured. Run 'apexmail configure' to set up your API key.\`
    );
  }

  return profile.apiKey;
}

export function getBaseUrl(profileName?: string): string {
  const config = loadConfig();
  const name = profileName ?? config.defaultProfile;
  const profile = config.profiles[name];
  return profile?.baseUrl ?? '${config.apiBaseUrl}';
}
`;
  }

  private generateHttpClient(): string {
    return `/**
 * HTTP Client for CLI
 */

import { getApiKey, getBaseUrl } from './config.js';

export interface RequestOptions {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined>;
  profile?: string;
  apiKey?: string;
}

export async function request<T>(options: RequestOptions): Promise<T> {
  const apiKey = getApiKey(options.profile, options.apiKey);
  const baseUrl = getBaseUrl(options.profile);

  let url = \`\${baseUrl}\${options.path}\`;

  if (options.query) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(options.query)) {
      if (value !== undefined) {
        params.set(key, String(value));
      }
    }
    const queryString = params.toString();
    if (queryString) {
      url += \`?\${queryString}\`;
    }
  }

  const response = await fetch(url, {
    method: options.method,
    headers: {
      'Authorization': \`Bearer \${apiKey}\`,
      'Content-Type': 'application/json',
      'User-Agent': 'apexmail-cli/1.0.0',
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.message ?? \`API error: \${response.status}\`);
  }

  return data as T;
}
`;
  }

  private generateCommandFile(command: CliCommand): string {
    return `/**
 * ${command.name} command
 */

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { request } from '../http.js';
import { formatOutput } from '../utils/output.js';

export const ${command.name}Command = new Command('${command.name}')
  .description('${command.description}')
${command.options.map(opt => {
  if (opt.type === 'boolean') {
    return `  .option('${opt.flag}', '${opt.description}')`;
  } else if (opt.defaultValue !== undefined) {
    return `  .option('${opt.flag}', '${opt.description}', '${opt.defaultValue}')`;
  } else {
    return `  .option('${opt.flag}', '${opt.description}')`;
  }
}).join('\n')}
  .action(async (options, cmd) => {
    const spinner = ora().start();
    
    try {
      const globalOpts = cmd.optsWithGlobals();
      
      // TODO: Implement ${command.name} command logic
      spinner.text = 'Processing...';
      
      // Example API call
      // const result = await request({
      //   method: 'GET',
      //   path: '/v1/...',
      //   profile: globalOpts.profile,
      //   apiKey: globalOpts.apiKey,
      // });
      
      spinner.succeed('Done');
      
      // Output result
      // formatOutput(result, globalOpts.json ? 'json' : options.format);
      
    } catch (error) {
      spinner.fail((error as Error).message);
      process.exit(1);
    }
  });
`;
  }

  private generateOutputUtils(): string {
    return `/**
 * Output formatting utilities
 */

import chalk from 'chalk';
import Table from 'cli-table3';

export function formatOutput(data: unknown, format: string = 'table'): void {
  switch (format) {
    case 'json':
      console.log(JSON.stringify(data, null, 2));
      break;
    case 'csv':
      formatCsv(data);
      break;
    case 'table':
    default:
      formatTable(data);
      break;
  }
}

function formatTable(data: unknown): void {
  if (Array.isArray(data)) {
    if (data.length === 0) {
      console.log(chalk.yellow('No results'));
      return;
    }

    const headers = Object.keys(data[0] as object);
    const table = new Table({
      head: headers.map(h => chalk.cyan(h)),
      style: { head: [], border: [] },
    });

    for (const row of data) {
      table.push(headers.map(h => formatValue((row as Record<string, unknown>)[h])));
    }

    console.log(table.toString());
  } else if (typeof data === 'object' && data !== null) {
    const table = new Table({
      style: { head: [], border: [] },
    });

    for (const [key, value] of Object.entries(data)) {
      table.push({ [chalk.cyan(key)]: formatValue(value) });
    }

    console.log(table.toString());
  } else {
    console.log(data);
  }
}

function formatCsv(data: unknown): void {
  if (!Array.isArray(data) || data.length === 0) {
    return;
  }

  const headers = Object.keys(data[0] as object);
  console.log(headers.join(','));

  for (const row of data) {
    const values = headers.map(h => {
      const value = (row as Record<string, unknown>)[h];
      if (typeof value === 'string' && value.includes(',')) {
        return \`"\${value.replace(/"/g, '""')}"\`;
      }
      return String(value ?? '');
    });
    console.log(values.join(','));
  }
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) {
    return chalk.dim('-');
  }
  if (typeof value === 'boolean') {
    return value ? chalk.green('✓') : chalk.red('✗');
  }
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (typeof value === 'object') {
    return JSON.stringify(value);
  }
  return String(value);
}

export function success(message: string): void {
  console.log(chalk.green('✓'), message);
}

export function error(message: string): void {
  console.error(chalk.red('✗'), message);
}

export function warn(message: string): void {
  console.warn(chalk.yellow('⚠'), message);
}

export function info(message: string): void {
  console.log(chalk.blue('ℹ'), message);
}
`;
  }

  /**
   * Get CLI installation instructions
   */
  getInstallInstructions(): string {
    return `# Install globally
npm install -g @apexmail/cli

# Or with npx
npx @apexmail/cli

# Configure
apexmail configure --api-key your_api_key

# Send your first email
apexmail send --from sender@example.com --to recipient@example.com --subject "Hello" --text "Hi there!"`;
  }
}

interface CliFile {
  path: string;
  content: string;
}
