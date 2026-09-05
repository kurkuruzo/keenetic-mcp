import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  createSecretStore,
  keychainCommand,
  spawnRunner,
  windowsDpapiCommand,
  type Runner
} from '../../src/config/secrets.js';

const SERVICE = 'keenetic-mcp';
const DPAPI_BLOB = Buffer.from('encrypted-dpapi-blob', 'utf8').toString('base64');

function runner(result: { code: number; stdout: string }): Runner {
  return vi.fn().mockResolvedValue(result) as unknown as Runner;
}

function dpapiRunner(secret = 'hunter2'): Runner {
  return vi.fn(async (_command: string, args: string[]) => {
    const script = args.at(-1) ?? '';
    if (script.includes('::Protect(')) return { code: 0, stdout: DPAPI_BLOB };
    if (script.includes('::Unprotect(')) {
      return { code: 0, stdout: Buffer.from(secret, 'utf8').toString('base64') };
    }
    return { code: 1, stdout: '' };
  }) as unknown as Runner;
}

describe('keychainCommand', () => {
  it('uses security on macOS', () => {
    const cmd = keychainCommand('darwin', 'read', 'admin@192.0.2.1');
    expect(cmd?.command).toBe('security');
    expect(cmd?.args).toContain('find-generic-password');
    expect(cmd?.args).toContain(SERVICE);
  });

  it('uses secret-tool on Linux', () => {
    const cmd = keychainCommand('linux', 'read', 'admin@192.0.2.1');
    expect(cmd?.command).toBe('secret-tool');
    expect(cmd?.args[0]).toBe('lookup');
  });

  it('does not use the old undeclared PowerShell credential helpers on Windows', () => {
    expect(keychainCommand('win32', 'read', 'admin@192.0.2.1')).toBeNull();
  });

  it('declares stdin wherever the native tool supports it', () => {
    expect(keychainCommand('linux', 'save', 'a')?.secretVia).toBe('stdin');
  });

  it('declares argv on macOS, where the tool gives no alternative', () => {
    expect(keychainCommand('darwin', 'save', 'a')?.secretVia).toBe('argv');
  });
});

describe('windowsDpapiCommand', () => {
  it.skipIf(process.platform !== 'win32')('round-trips a password through native Windows DPAPI', async () => {
    const encoded = Buffer.from('  test-пароль-🔑  ', 'utf8').toString('base64');
    const protect = windowsDpapiCommand('protect');
    const encrypted = await spawnRunner(protect.command, protect.args, encoded);
    expect(encrypted.code).toBe(0);
    expect(encrypted.stdout.trim()).not.toBe('');
    const unprotect = windowsDpapiCommand('unprotect');
    const decrypted = await spawnRunner(unprotect.command, unprotect.args, encrypted.stdout);
    expect(decrypted.code).toBe(0);
    expect(decrypted.stdout.trim()).toBe(encoded);
  }, 15_000);

  it('uses PowerShell and DPAPI CurrentUser', () => {
    const cmd = windowsDpapiCommand('protect');
    expect(cmd.command).toBe('powershell.exe');
    expect(cmd.secretVia).toBe('stdin');
    expect(cmd.args.join(' ')).toContain('ProtectedData');
    expect(cmd.args.join(' ')).toContain('CurrentUser');
  });

  it('uses Base64 for both sides of the PowerShell pipe', () => {
    const protect = windowsDpapiCommand('protect').args.join(' ');
    const unprotect = windowsDpapiCommand('unprotect').args.join(' ');
    expect(protect).toContain('FromBase64String');
    expect(protect).toContain('ToBase64String');
    expect(unprotect).toContain('FromBase64String');
    expect(unprotect).toContain('ToBase64String');
  });

  it('never puts the password in argv', () => {
    const cmd = windowsDpapiCommand('protect');
    expect(cmd.args.join(' ')).not.toContain('hunter2');
  });
});

describe('createSecretStore', () => {
  it('reads a secret back out of the macOS keychain', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const store = createSecretStore('darwin', runner({ code: 0, stdout: 'hunter2\n' }), dir);
    await expect(store.read('admin@192.0.2.1')).resolves.toBe('hunter2');
  });

  it('preserves leading and trailing spaces in native keychain passwords', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const secret = '  hunter2  ';
    const store = createSecretStore('linux', runner({ code: 0, stdout: `${secret}\n` }), dir);

    await expect(store.save('admin@192.0.2.1', secret)).resolves.toMatch(/keychain/i);
    await expect(store.read('admin@192.0.2.1')).resolves.toBe(secret);
  });

  it('preserves an empty native keychain password instead of treating it as missing', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const store = createSecretStore('linux', runner({ code: 0, stdout: '\n' }), dir);

    await expect(store.save('admin@192.0.2.1', '')).resolves.toMatch(/keychain/i);
    await expect(store.read('admin@192.0.2.1')).resolves.toBe('');
  });

  it('returns null when the keychain has no entry', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const store = createSecretStore('darwin', runner({ code: 44, stdout: '' }), dir);
    await expect(store.read('admin@192.0.2.1')).resolves.toBeNull();
  });

  it('reports a missing native keychain executable instead of treating it as no entry', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const failing = vi.fn().mockRejectedValue(new Error('ENOENT'));
    const store = createSecretStore('linux', failing as unknown as Runner, dir);
    await expect(store.read('admin@192.0.2.1')).rejects.toThrow(/system keychain/i);
  });

  it('passes the secret on stdin where the platform supports it', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const spy = vi.fn().mockResolvedValue({ code: 0, stdout: 'hunter2\n' });
    const store = createSecretStore('linux', spy as unknown as Runner, dir);
    await store.save('admin@192.0.2.1', 'hunter2');

    const [, args, stdin] = spy.mock.calls[0]!;
    expect((args as string[]).join(' ')).not.toContain('hunter2');
    expect(stdin).toBe('hunter2');
  });

  it('appends the secret as the final argument on macOS', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const spy = vi.fn().mockResolvedValue({ code: 0, stdout: 'hunter2\n' });
    const store = createSecretStore('darwin', spy as unknown as Runner, dir);
    await store.save('admin@192.0.2.1', 'hunter2');

    const [, args] = spy.mock.calls[0]!;
    expect((args as string[]).at(-1)).toBe('hunter2');
  });

  it('fails closed when the keychain claims success but stored nothing', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    let calls = 0;
    const lying = vi.fn(async (_command: string, args: string[]) => {
      calls += 1;
      if (args[0] === 'store') return { code: 0, stdout: '' };
      if (args[0] === 'lookup') return { code: 1, stdout: '' };
      return { code: 0, stdout: '' };
    });
    const store = createSecretStore('linux', lying as unknown as Runner, dir);

    await expect(store.save('admin@192.0.2.1', 'hunter2')).rejects.toThrow(/no plaintext/i);
    expect(calls).toBeGreaterThanOrEqual(2);
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).rejects.toThrow();
  });

  it('fails closed when the Linux keychain tool is missing', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const failing = vi.fn().mockRejectedValue(new Error('ENOENT'));
    const store = createSecretStore('linux', failing as unknown as Runner, dir);

    await expect(store.save('admin@192.0.2.1', 'hunter2')).rejects.toThrow(/system keychain/i);
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).rejects.toThrow();
  });

  it('says where the secret went so the wizard can report it', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const store = createSecretStore('darwin', runner({ code: 0, stdout: 'hunter2\n' }), dir);
    await expect(store.save('admin@192.0.2.1', 'hunter2')).resolves.toMatch(/keychain/i);
  });

  it('removes a native keychain entry without touching legacy plaintext', async () => {
    const spy = vi.fn().mockResolvedValue({ code: 0, stdout: '' });
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    await writeFile(join(dir, 'secrets.json'), '{"old@router":"old"}\n', 'utf8');
    const store = createSecretStore('darwin', spy as unknown as Runner, dir);
    await store.remove('admin@192.0.2.1');

    expect((spy.mock.calls[0]![1] as string[]).join(' ')).toContain('delete-generic-password');
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).resolves.toContain('old@router');
  });

  it('stores Windows passwords only as DPAPI ciphertext', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const spy = dpapiRunner();
    const store = createSecretStore('win32', spy, dir);

    await expect(store.save('admin@192.0.2.1', 'hunter2')).resolves.toMatch(/DPAPI/i);
    const stored = await readFile(join(dir, 'secrets.dpapi.json'), 'utf8');
    expect(stored).toContain(DPAPI_BLOB);
    expect(stored).not.toContain('hunter2');
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).rejects.toThrow();
  });

  it('sends Windows plaintext to PowerShell only as Base64 UTF-8', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const secret = 'Пароль-ä-密码';
    const encoded = Buffer.from(secret, 'utf8').toString('base64');
    const spy = vi.fn(async (_command: string, args: string[], stdin?: string) => {
      const script = args.at(-1) ?? '';
      if (script.includes('::Protect(')) {
        expect(stdin).toBe(encoded);
        expect(stdin).not.toContain(secret);
        return { code: 0, stdout: DPAPI_BLOB };
      }
      if (script.includes('::Unprotect(')) {
        expect(stdin).toBe(DPAPI_BLOB);
        return { code: 0, stdout: encoded };
      }
      return { code: 1, stdout: '' };
    });
    const store = createSecretStore('win32', spy as unknown as Runner, dir);

    await expect(store.save('admin@192.0.2.1', secret)).resolves.toMatch(/DPAPI/i);
    await expect(store.read('admin@192.0.2.1')).resolves.toBe(secret);
  });

  it('round-trips a non-ASCII Windows password through the DPAPI store abstraction', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const secret = 'Пароль-ä-密码';
    const store = createSecretStore('win32', dpapiRunner(secret), dir);

    await expect(store.save('admin@192.0.2.1', secret)).resolves.toMatch(/DPAPI/i);
    await expect(store.read('admin@192.0.2.1')).resolves.toBe(secret);
  });

  it('reads Windows passwords through DPAPI', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const store = createSecretStore('win32', dpapiRunner(), dir);

    await store.save('admin@192.0.2.1', 'hunter2');
    await expect(store.read('admin@192.0.2.1')).resolves.toBe('hunter2');
  });

  it('migrates a legacy Windows password securely but defers plaintext deletion', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    await writeFile(
      join(dir, 'secrets.json'),
      `${JSON.stringify({ 'admin@192.0.2.1': 'hunter2' })}\n`,
      'utf8'
    );
    const store = createSecretStore('win32', dpapiRunner(), dir);

    await expect(store.read('admin@192.0.2.1')).resolves.toBe('hunter2');
    const stored = await readFile(join(dir, 'secrets.dpapi.json'), 'utf8');
    expect(stored).toContain(DPAPI_BLOB);
    expect(stored).not.toContain('hunter2');
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).resolves.toContain('hunter2');

    await store.purgeLegacy();
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).rejects.toThrow();
  });

  it('does not delete legacy plaintext just because a Windows DPAPI credential exists', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    await writeFile(
      join(dir, 'secrets.dpapi.json'),
      `${JSON.stringify({ 'admin@192.0.2.1': DPAPI_BLOB })}\n`,
      'utf8'
    );
    await writeFile(
      join(dir, 'secrets.json'),
      `${JSON.stringify({ 'admin@192.0.2.1': 'hunter2' })}\n`,
      'utf8'
    );
    const store = createSecretStore('win32', dpapiRunner(), dir);

    await expect(store.read('admin@192.0.2.1')).resolves.toBe('hunter2');
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).resolves.toContain('hunter2');
  });

  it('migrates a legacy Linux password into the keychain but defers plaintext deletion', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    await writeFile(
      join(dir, 'secrets.json'),
      `${JSON.stringify({ 'admin@192.0.2.1': 'hunter2' })}\n`,
      'utf8'
    );

    let stored = false;
    const spy = vi.fn(async (_command: string, args: string[]) => {
      if (args[0] === 'lookup') {
        return stored ? { code: 0, stdout: 'hunter2\n' } : { code: 1, stdout: '' };
      }
      if (args[0] === 'store') {
        stored = true;
        return { code: 0, stdout: '' };
      }
      return { code: 0, stdout: '' };
    });
    const store = createSecretStore('linux', spy as unknown as Runner, dir);

    await expect(store.read('admin@192.0.2.1')).resolves.toBe('hunter2');
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).resolves.toContain('hunter2');
    await store.purgeLegacy();
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).rejects.toThrow();
  });

  it('clears a partially-created native credential when legacy migration verification fails', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    await writeFile(
      join(dir, 'secrets.json'),
      `${JSON.stringify({ 'admin@192.0.2.1': 'hunter2' })}\n`,
      'utf8'
    );

    let stored = false;
    let cleared = false;
    const spy = vi.fn(async (_command: string, args: string[]) => {
      if (args[0] === 'lookup') {
        return stored ? { code: 0, stdout: 'wrong-password\n' } : { code: 1, stdout: '' };
      }
      if (args[0] === 'store') {
        stored = true;
        return { code: 0, stdout: '' };
      }
      if (args[0] === 'clear') {
        cleared = true;
        stored = false;
        return { code: 0, stdout: '' };
      }
      return { code: 1, stdout: '' };
    });
    const store = createSecretStore('linux', spy as unknown as Runner, dir);

    await expect(store.read('admin@192.0.2.1')).rejects.toThrow(/plaintext|verify|keychain/i);
    expect(cleared).toBe(true);
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).resolves.toContain('hunter2');
  });

  it('does not report a failed native cleanup as successful', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    let stored = true;
    const spy = vi.fn(async (_command: string, args: string[]) => {
      if (args[0] === 'clear') return { code: 1, stdout: '' };
      if (args[0] === 'lookup') {
        return stored ? { code: 0, stdout: 'still-there\n' } : { code: 1, stdout: '' };
      }
      return { code: 0, stdout: '' };
    });
    const store = createSecretStore('linux', spy as unknown as Runner, dir);

    await expect(store.remove('admin@192.0.2.1')).rejects.toThrow(/remove.*system keychain/i);
    expect(stored).toBe(true);
  });

  it('does not keep using a legacy plaintext password if the secure store is unavailable', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    await writeFile(
      join(dir, 'secrets.json'),
      `${JSON.stringify({ 'admin@192.0.2.1': 'hunter2' })}\n`,
      'utf8'
    );
    const failing = vi.fn().mockRejectedValue(new Error('ENOENT'));
    const store = createSecretStore('linux', failing as unknown as Runner, dir);

    await expect(store.read('admin@192.0.2.1')).rejects.toThrow(/system keychain/i);
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).resolves.toContain('hunter2');
  });

  it('removes Windows DPAPI entries without purging legacy plaintext', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    await writeFile(join(dir, 'secrets.json'), '{"old@router":"old"}\n', 'utf8');
    const store = createSecretStore('win32', dpapiRunner(), dir);

    await store.save('a@192.0.2.1', 'hunter2');
    await store.remove('a@192.0.2.1');

    await expect(store.read('a@192.0.2.1')).resolves.toBeNull();
    await expect(readFile(join(dir, 'secrets.dpapi.json'), 'utf8')).rejects.toThrow();
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).resolves.toContain('old@router');
  });
});
