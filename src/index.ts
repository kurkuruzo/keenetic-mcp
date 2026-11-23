#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { McpServer } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { runInitFromTerminal } from './cli/init.js';
import { configDir, readStoredConfig } from './config/discover.js';
import {
  loadConfig,
  storedIdentityMatches,
  type StoredCredentials
} from './config/load.js';
import { createSecretStore, spawnRunner } from './config/secrets.js';
import { createBackupGuard } from './router/backup.js';
import { createClient } from './router/client.js';
import { registerConfigTools } from './tools/config.js';
import { registerDeviceTools } from './tools/devices.js';
import { registerInterfaceTools } from './tools/interfaces.js';
import { registerNetworkTools } from './tools/network.js';
import { registerRawTool } from './tools/raw.js';
import type { ToolContext, ToolScope } from './tools/registry.js';
import { registerSegmentTools } from './tools/segments.js';
import { registerSystemTools } from './tools/system.js';
import { loadLocalEnv, resolveVersion } from './version.js';

function registerTools(server: McpServer, scope: ToolScope): void {
  registerSystemTools(server, scope);
  registerDeviceTools(server, scope);
  registerInterfaceTools(server, scope);
  registerNetworkTools(server, scope);
  registerSegmentTools(server, scope);
  registerConfigTools(server, scope);
  registerRawTool(server, scope);
}

export function createServer(ctx: ToolContext): McpServer {
  const server = new McpServer({ name: 'keenetic', version: resolveVersion() });
  registerTools(server, ctx);
  return server;
}

export function createMultiProfileServer(
  profiles: ReadonlyMap<string, () => Promise<ToolContext>>,
  readOnly: boolean
): McpServer {
  const server = new McpServer({ name: 'keenetic', version: resolveVersion() }, {
    instructions: 'Choose the router by its tool name prefix. References to other tools in ' +
      'descriptions and results use short names; use the same router prefix for those calls.'
  });
  for (const [profile, load] of profiles) {
    let pending: Promise<ToolContext> | undefined;
    registerTools(server, {
      profile,
      readOnly,
      getContext: () => pending ??= load().catch((error: unknown) => {
        pending = undefined;
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Keenetic profile "${profile}": ${message}`, { cause: error });
      })
    });
  }
  return server;
}

function readProfileArgs(argv: readonly string[]): Map<string, string> {
  const profiles = new Map<string, string>();
  for (const [index, arg] of argv.entries()) {
    if (arg !== '--profile') continue;
    const value = argv[index + 1] ?? '';
    const separator = value.indexOf('=');
    const name = value.slice(0, separator);
    const dir = value.slice(separator + 1);
    if (separator < 0 || !/^[a-z][a-z0-9-]{0,31}$/.test(name) || !isAbsolute(dir)) {
      throw new Error('--profile expects name=absolute-directory (lowercase ASCII name).');
    }
    if (profiles.has(name)) throw new Error(`Duplicate Keenetic profile "${name}".`);
    profiles.set(name, dir);
  }
  return profiles;
}

async function createToolContext(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  dir: string
): Promise<ToolContext> {
  const storedConfig = await readStoredConfig(dir);
  const store = createSecretStore(process.platform, spawnRunner, dir);

  const stored: StoredCredentials = {};
  let loadedStoredSecret = false;
  if (storedConfig) {
    stored.host = storedConfig.host;
    stored.login = storedConfig.login;

    // A local password is scoped to the exact stored host/login pair. If an
    // environment variable or --host redirects the connection, do not even read
    // (or migrate) the local secret: doing so could pair a router password with
    // a different target and leak it on the next authentication attempt.
    if (
      env['KEENETIC_PASSWORD'] === undefined &&
      storedIdentityMatches(argv, env, stored)
    ) {
      const secret = await store.read(`${storedConfig.login}@${storedConfig.host}`);
      if (secret !== null) {
        stored.password = secret;
        loadedStoredSecret = true;
      }
    }
  }

  const config = await loadConfig(argv, env, stored);

  if (loadedStoredSecret) await store.purgeLegacy();

  const client = createClient({
    host: config.host,
    login: config.login,
    password: config.password
  });
  return {
    client,
    maxResponseBytes: config.maxResponseBytes,
    readOnly: config.readOnly,
    backup: createBackupGuard(client.rci, config.host, () => new Date())
  };

}

async function main(): Promise<void> {
  loadLocalEnv();

  const argv = process.argv.slice(2);
  if (argv.includes('--version') || argv.includes('-v')) {
    process.stdout.write(`${resolveVersion()}\n`);
    return;
  }

  if (argv[0] === 'init') {
    process.exit(await runInitFromTerminal());
  }

  const profiles = readProfileArgs(argv);
  if (profiles.size > 0) {
    if (argv.includes('--host')) throw new Error('--host cannot be combined with --profile.');
    const loaders = new Map(
      Array.from(profiles, ([name, dir]) => [name, () => createToolContext(argv, {}, dir)])
    );
    await createMultiProfileServer(loaders, argv.includes('--read-only'))
      .connect(new StdioServerTransport());
    return;
  }

  const dir = configDir(process.platform, process.env);
  const ctx = await createToolContext(argv, process.env, dir);
  await createServer(ctx).connect(new StdioServerTransport());
}

function isProgramEntry(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
}

if (isProgramEntry()) {
  main().catch((error: unknown) => {
    process.stderr.write(`keenetic-mcp failed to start: ${(error as Error).message}\n`);
    process.exit(1);
  });
}
