#!/usr/bin/env node
import { realpathSync } from 'node:fs';
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
import type { ToolContext } from './tools/registry.js';
import { registerSegmentTools } from './tools/segments.js';
import { registerSystemTools } from './tools/system.js';
import { loadLocalEnv, resolveVersion } from './version.js';

export function createServer(ctx: ToolContext): McpServer {
  const server = new McpServer({ name: 'keenetic', version: resolveVersion() });
  registerSystemTools(server, ctx);
  registerDeviceTools(server, ctx);
  registerInterfaceTools(server, ctx);
  registerNetworkTools(server, ctx);
  registerSegmentTools(server, ctx);
  registerConfigTools(server, ctx);
  registerRawTool(server, ctx);
  return server;
}

async function main(): Promise<void> {
  loadLocalEnv();

  if (process.argv.includes('--version') || process.argv.includes('-v')) {
    process.stdout.write(`${resolveVersion()}\n`);
    return;
  }

  if (process.argv[2] === 'init') {
    process.exit(await runInitFromTerminal());
  }

  const argv = process.argv.slice(2);
  const dir = configDir(process.platform, process.env);
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
      process.env['KEENETIC_PASSWORD'] === undefined &&
      storedIdentityMatches(argv, process.env, stored)
    ) {
      const secret = await store.read(`${storedConfig.login}@${storedConfig.host}`);
      if (secret !== null) {
        stored.password = secret;
        loadedStoredSecret = true;
      }
    }
  }

  const config = await loadConfig(argv, process.env, stored);

  if (loadedStoredSecret) await store.purgeLegacy();

  const client = createClient({
    host: config.host,
    login: config.login,
    password: config.password
  });
  const ctx: ToolContext = {
    client,
    maxResponseBytes: config.maxResponseBytes,
    readOnly: config.readOnly,
    backup: createBackupGuard(client.rci, config.host, () => new Date())
  };

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
