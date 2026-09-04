import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  createSecretStore,
  keychainCommand,
  windowsDpapiCommand,
  type Runner
} from '../../src/config/secrets.js';

const SERVICE = 'keenetic-mcp';

function runner(result: { code: number; stdout: string }): Runner {
  return vi.fn().mockResolvedValue(result) as unknown as Runner;
}

function dpapiRunner(secret = 'hunter2'): Runner {
  return vi.fn(async (_command: string, args: string[]) => {
    const script = args.at(-1) ?? '';
    if (script.includes('::Protect(')) return { code: 0, stdout: 'encrypted-dpapi-blob' };
    if (script.includes('::Unprotect(')) return { code: 0, stdout: secret };
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

  // stdin is preferred because argv is readable by other processes of the same
  // user. macOS leaves no choice: `security` takes the password as an argument.
  it('declares stdin wherever the native tool supports it', () => {
    expect(keychainCommand('linux', 'save', 'a')?.secretVia).toBe('stdin');
  });

  it('declares argv on macOS, where the tool gives no alternative', () => {
    expect(keychainCommand('darwin', 'save', 'a')?.secretVia).toBe('argv');
  });
});

describe('windowsDpapiCommand', () => {
  it('uses PowerShell and DPAPI CurrentUser', () => {
    const cmd = windowsDpapiCommand('protect');
    expect(cmd.command).toBe('powershell.exe');
    expect(cmd.secretVia).toBe('stdin');
    expect(cmd.args.join(' ')).toContain('ProtectedData');
    expect(cmd.args.join(' ')).toContain('CurrentUser');
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

  it('returns null when the keychain has no entry', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const store = createSecretStore('darwin', runner({ code: 44, stdout: '' }), dir);
    await expect(store.read('admin@192.0.2.1')).resolves.toBeNull();
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
    const lying = vi.fn().mockResolvedValue({ code: 0, stdout: '' });
    const store = createSecretStore('darwin', lying as unknown as Runner, dir);

    await expect(store.save('admin@192.0.2.1', 'hunter2')).rejects.toThrow(/no plaintext/i);
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

  it('removes a native keychain entry', async () => {
    const spy = vi.fn().mockResolvedValue({ code: 0, stdout: '' });
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const store = createSecretStore('darwin', spy as unknown as Runner, dir);
    await store.remove('admin@192.0.2.1');
    expect((spy.mock.calls[0]![1] as string[]).join(' ')).toContain('delete-generic-password');
  });

  it('stores Windows passwords only as DPAPI ciphertext', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const spy = dpapiRunner();
    const store = createSecretStore('win32', spy, dir);

    await expect(store.save('admin@192.0.2.1', 'hunter2')).resolves.toMatch(/DPAPI/i);
    const stored = await readFile(join(dir, 'secrets.dpapi.json'), 'utf8');
    expect(stored).toContain('encrypted-dpapi-blob');
    expect(stored).not.toContain('hunter2');
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).rejects.toThrow();
  });

  it('reads Windows passwords through DPAPI', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const store = createSecretStore('win32', dpapiRunner(), dir);

    await store.save('admin@192.0.2.1', 'hunter2');
    await expect(store.read('admin@192.0.2.1')).resolves.toBe('hunter2');
  });

  it('migrates a legacy plaintext Windows password into DPAPI and deletes the old file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    await writeFile(
      join(dir, 'secrets.json'),
      `${JSON.stringify({ 'admin@192.0.2.1': 'hunter2' })}\n`,
      'utf8'
    );
    const store = createSecretStore('win32', dpapiRunner(), dir);

    await expect(store.read('admin@192.0.2.1')).resolves.toBe('hunter2');
    const stored = await readFile(join(dir, 'secrets.dpapi.json'), 'utf8');
    expect(stored).toContain('encrypted-dpapi-blob');
    expect(stored).not.toContain('hunter2');
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).rejects.toThrow();
  });

  it('removes legacy plaintext when a Windows DPAPI credential already exists', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    await writeFile(
      join(dir, 'secrets.dpapi.json'),
      `${JSON.stringify({ 'admin@192.0.2.1': 'encrypted-dpapi-blob' })}\n`,
      'utf8'
    );
    await writeFile(
      join(dir, 'secrets.json'),
      `${JSON.stringify({ 'admin@192.0.2.1': 'hunter2' })}\n`,
      'utf8'
    );
    const store = createSecretStore('win32', dpapiRunner(), dir);

    await expect(store.read('admin@192.0.2.1')).resolves.toBe('hunter2');
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).rejects.toThrow();
  });

  it('migrates a legacy Linux password into the system keychain and deletes the old file', async () => {
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
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).rejects.toThrow();
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
  });

  it('removes Windows DPAPI entries', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-sec-'));
    const store = createSecretStore('win32', dpapiRunner(), dir);

    await store.save('a@192.0.2.1', 'hunter2');
    await store.remove('a@192.0.2.1');

    await expect(store.read('a@192.0.2.1')).resolves.toBeNull();
    await expect(readFile(join(dir, 'secrets.dpapi.json'), 'utf8')).rejects.toThrow();
  });
});
