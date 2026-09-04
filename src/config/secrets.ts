import { spawn } from 'node:child_process';
import { chmod, mkdir, readFile, unlink, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

const SERVICE = 'keenetic-mcp';
const WINDOWS_SECRET_FILE = 'secrets.dpapi.json';
const LEGACY_SECRET_FILE = 'secrets.json';

export type Runner = (
  command: string,
  args: string[],
  stdin?: string
) => Promise<{ code: number; stdout: string }>;

export interface SecretStore {
  /** Returns a human-readable description of where the secret went. */
  save(account: string, secret: string): Promise<string>;
  read(account: string): Promise<string | null>;
  remove(account: string): Promise<void>;
  /** Removes the old plaintext fallback only after the caller has committed config state. */
  purgeLegacy(): Promise<void>;
}

/**
 * How the secret reaches the OS secret-store helper.
 *
 * `stdin` is preferred, because argv is readable by other processes of the same
 * user. macOS leaves no choice: `security add-generic-password` takes the
 * password as an argument.
 */
export type SecretChannel = 'argv' | 'stdin';

export interface KeychainCommand {
  command: string;
  args: string[];
  secretVia: SecretChannel;
}

/** Runs a command, feeding stdin when given, and never echoes it. */
export const spawnRunner: Runner = (command, args, stdin) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'ignore'] });
    let stdout = '';
    child.stdout.on('data', chunk => {
      stdout += String(chunk);
    });
    child.on('error', reject);
    child.on('close', code => resolve({ code: code ?? 1, stdout }));
    child.stdin.end(stdin ?? '');
  });

/** Native keychain commands for macOS and Linux. */
export function keychainCommand(
  platform: NodeJS.Platform,
  op: 'save' | 'read' | 'remove',
  account: string
): KeychainCommand | null {
  if (platform === 'darwin') {
    if (op === 'save') {
      return {
        command: 'security',
        args: ['add-generic-password', '-U', '-a', account, '-s', SERVICE, '-w'],
        secretVia: 'argv'
      };
    }
    if (op === 'read') {
      return {
        command: 'security',
        args: ['find-generic-password', '-a', account, '-s', SERVICE, '-w'],
        secretVia: 'argv'
      };
    }
    return {
      command: 'security',
      args: ['delete-generic-password', '-a', account, '-s', SERVICE],
      secretVia: 'argv'
    };
  }

  if (platform === 'win32') return null;

  if (op === 'save') {
    return {
      command: 'secret-tool',
      args: ['store', '--label', SERVICE, 'service', SERVICE, 'account', account],
      secretVia: 'stdin'
    };
  }
  if (op === 'read') {
    return {
      command: 'secret-tool',
      args: ['lookup', 'service', SERVICE, 'account', account],
      secretVia: 'stdin'
    };
  }
  return {
    command: 'secret-tool',
    args: ['clear', 'service', SERVICE, 'account', account],
    secretVia: 'stdin'
  };
}

export function windowsDpapiCommand(op: 'protect' | 'unprotect'): KeychainCommand {
  const script =
    op === 'protect'
      ? [
          "$ErrorActionPreference = 'Stop'",
          '$plain = [Console]::In.ReadToEnd()',
          '$bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)',
          '$protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)',
          '[Console]::Out.Write([Convert]::ToBase64String($protected))'
        ].join('; ')
      : [
          "$ErrorActionPreference = 'Stop'",
          '$cipher = [Console]::In.ReadToEnd().Trim()',
          '$bytes = [Convert]::FromBase64String($cipher)',
          '$plain = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)',
          '[Console]::Out.Write([System.Text.Encoding]::UTF8.GetString($plain))'
        ].join('; ');

  return {
    command: 'powershell.exe',
    args: ['-NoProfile', '-NonInteractive', '-Command', script],
    secretVia: 'stdin'
  };
}

function isEnoent(error: unknown): boolean {
  return (error as NodeJS.ErrnoException).code === 'ENOENT';
}

function stripCommandLineEnding(value: string): string {
  if (value.endsWith('\r\n')) return value.slice(0, -2);
  if (value.endsWith('\n')) return value.slice(0, -1);
  return value;
}

async function readSecretFile(path: string): Promise<Record<string, string>> {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8')) as unknown;
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error(`${path} does not contain an object`);
    }

    const entries = Object.entries(parsed);
    if (!entries.every(([, value]) => typeof value === 'string')) {
      throw new Error(`${path} contains an invalid credential entry`);
    }
    return Object.fromEntries(entries) as Record<string, string>;
  } catch (error) {
    if (isEnoent(error)) return {};
    throw error;
  }
}

async function writeSecretFile(path: string, all: Record<string, string>): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(all, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600
  });
  await chmod(path, 0o600);
}

function legacySecretPath(configDir: string): string {
  return join(configDir, LEGACY_SECRET_FILE);
}

async function readLegacySecret(configDir: string, account: string): Promise<string | null> {
  const all = await readSecretFile(legacySecretPath(configDir));
  return all[account] ?? null;
}

/**
 * Older releases could accumulate several plaintext credentials in one file,
 * while the application itself stores only one active host/login in config.json.
 * The caller invokes this only after the active secure credential and config
 * state are committed, so every remaining legacy entry is orphaned plaintext.
 */
async function purgeLegacySecrets(configDir: string): Promise<void> {
  try {
    await unlink(legacySecretPath(configDir));
  } catch (error) {
    if (!isEnoent(error)) throw error;
  }
}

function createWindowsDpapiStore(run: Runner, configDir: string): SecretStore {
  const protectedFile = join(configDir, WINDOWS_SECRET_FILE);

  async function readAll(): Promise<Record<string, string>> {
    return readSecretFile(protectedFile);
  }

  async function writeAll(all: Record<string, string>): Promise<void> {
    await writeSecretFile(protectedFile, all);
  }

  async function protect(secret: string): Promise<string> {
    const cmd = windowsDpapiCommand('protect');
    const { code, stdout } = await run(cmd.command, cmd.args, secret);
    const cipher = stdout.trim();
    if (code !== 0 || cipher.length === 0) {
      throw new Error('Windows DPAPI failed to protect the password');
    }
    return cipher;
  }

  async function unprotect(cipher: string): Promise<string> {
    const cmd = windowsDpapiCommand('unprotect');
    const { code, stdout } = await run(cmd.command, cmd.args, cipher);
    if (code !== 0) throw new Error('Windows DPAPI failed to unprotect the password');
    return stdout;
  }

  async function saveSecure(account: string, secret: string): Promise<string> {
    const cipher = await protect(secret);
    if ((await unprotect(cipher)) !== secret) {
      throw new Error('Windows DPAPI verification failed; password was not saved');
    }

    const all = await readAll();
    all[account] = cipher;
    await writeAll(all);
    return 'Windows DPAPI (CurrentUser)';
  }

  return {
    save: saveSecure,

    async read(account) {
      const all = await readAll();
      const cipher = all[account];
      if (cipher !== undefined) return unprotect(cipher);

      // Migrate the active legacy value into secure storage, but deliberately
      // keep the legacy file until the caller has successfully resolved/written
      // the configuration that makes this account active.
      const legacy = await readLegacySecret(configDir, account);
      if (legacy === null) return null;
      await saveSecure(account, legacy);
      return legacy;
    },

    async remove(account) {
      const all = await readAll();
      if (!(account in all)) return;
      delete all[account];

      if (Object.keys(all).length === 0) {
        try {
          await unlink(protectedFile);
        } catch (error) {
          if (!isEnoent(error)) throw error;
        }
        return;
      }

      await writeAll(all);
    },

    purgeLegacy: () => purgeLegacySecrets(configDir)
  };
}

export function createSecretStore(
  platform: NodeJS.Platform,
  run: Runner,
  configDir: string
): SecretStore {
  if (platform === 'win32') return createWindowsDpapiStore(run, configDir);

  async function readKeychain(account: string): Promise<string | null> {
    const cmd = keychainCommand(platform, 'read', account);
    if (!cmd) return null;
    try {
      const { code, stdout } = await run(cmd.command, cmd.args);
      if (code !== 0) return null;
      const secret = stripCommandLineEnding(stdout);
      return secret.length > 0 ? secret : null;
    } catch {
      // Missing or inaccessible keychain is reported by save().
      return null;
    }
  }

  async function saveSecure(account: string, secret: string): Promise<string> {
    const cmd = keychainCommand(platform, 'save', account);
    if (!cmd) throw new Error(`No secure credential store is available on ${platform}`);

    try {
      const args = cmd.secretVia === 'argv' ? [...cmd.args, secret] : cmd.args;
      const stdin = cmd.secretVia === 'stdin' ? secret : undefined;
      const { code } = await run(cmd.command, args, stdin);
      if (code === 0 && (await readKeychain(account)) === secret) {
        return 'the system keychain';
      }
    } catch (error) {
      throw new Error(
        `Could not store the password in the system keychain: ${(error as Error).message}`
      );
    }

    throw new Error(
      'Could not verify the password in the system keychain; no plaintext fallback was written'
    );
  }

  return {
    save: saveSecure,

    async read(account) {
      const fromKeychain = await readKeychain(account);
      if (fromKeychain !== null) return fromKeychain;

      // Migrate the active legacy value into secure storage, but keep the
      // plaintext file until the caller has committed its configuration state.
      const legacy = await readLegacySecret(configDir, account);
      if (legacy === null) return null;
      await saveSecure(account, legacy);
      return legacy;
    },

    async remove(account) {
      const cmd = keychainCommand(platform, 'remove', account);
      if (!cmd) return;
      try {
        await run(cmd.command, cmd.args);
      } catch {
        // Removal is idempotent. Legacy cleanup is a separate transaction.
      }
    },

    purgeLegacy: () => purgeLegacySecrets(configDir)
  };
}
