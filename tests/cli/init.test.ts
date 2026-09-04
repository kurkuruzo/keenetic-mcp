import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { runInit, type InitDeps } from '../../src/cli/init.js';
import { readStoredConfig } from '../../src/config/discover.js';

async function makeDeps(
  over: Partial<InitDeps> = {}
): Promise<{ deps: InitDeps; out: string[]; dir: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'kn-init-'));
  const out: string[] = [];
  const deps: InitDeps = {
    configDir: dir,
    prompt: vi.fn(async () => ''),
    hidden: vi.fn(async () => 'hunter2'),
    out: line => out.push(line),
    store: {
      save: vi.fn(async () => 'the system keychain'),
      read: vi.fn(async () => null),
      remove: vi.fn(async () => undefined),
      purgeLegacy: vi.fn(async () => undefined)
    },
    discoverGateway: vi.fn(async () => '192.0.2.1'),
    identify: vi.fn(async () => ({ realm: 'Keenetic Ultra' })),
    verify: vi.fn(async () => ({
      ok: true as const,
      model: 'Keenetic Ultra (KN-1811)',
      firmware: '5.1.3',
      components: 43
    })),
    ...over
  };
  return { deps, out, dir };
}

describe('runInit', () => {
  it('discovers, verifies and stores', async () => {
    const { deps, out, dir } = await makeDeps();
    await expect(runInit(deps)).resolves.toBe(0);

    await expect(readStoredConfig(dir)).resolves.toEqual({ host: '192.0.2.1', login: 'admin' });
    expect(deps.store.save).toHaveBeenCalledWith('admin@192.0.2.1', 'hunter2');
    expect(deps.store.purgeLegacy).toHaveBeenCalledTimes(1);
    expect(out.join('\n')).toMatch(/Keenetic Ultra \(KN-1811\)/);
    expect(out.join('\n')).toMatch(/5\.1\.3/);
  });

  it('never prints the password', async () => {
    const { deps, out } = await makeDeps();
    await runInit(deps);
    expect(out.join('\n')).not.toContain('hunter2');
  });

  it('names both agents, not just one, plus the generic config', async () => {
    const { deps, out } = await makeDeps();
    await runInit(deps);
    const text = out.join('\n');
    expect(text).toMatch(/Claude Code/);
    expect(text).toMatch(/Codex/);
    expect(text).toMatch(/plugin marketplace add salatmaster\/keenetic-mcp/);
    expect(text).toMatch(/"command": "npx"/);
    expect(text).toMatch(/"keenetic-mcp"/);
  });

  it('fails with a usable message when nothing answers at the gateway', async () => {
    const { deps, out } = await makeDeps({ identify: vi.fn(async () => null) });
    await expect(runInit(deps)).resolves.toBe(1);
    expect(out.join('\n')).toMatch(/Keenetic/i);
  });

  it('stores nothing when the credentials are rejected', async () => {
    const { deps, out, dir } = await makeDeps({
      verify: vi.fn(async () => ({ ok: false as const, reason: 'HTTP 401' }))
    });
    await expect(runInit(deps)).resolves.toBe(1);
    expect(deps.store.save).not.toHaveBeenCalled();
    expect(deps.store.purgeLegacy).not.toHaveBeenCalled();
    await expect(readStoredConfig(dir)).resolves.toBeNull();
    expect(out.join('\n')).toMatch(/rejected|401/i);
  });

  it('fails closed and writes no settings when secure password storage fails', async () => {
    const remove = vi.fn(async () => undefined);
    const { deps, out, dir } = await makeDeps({
      store: {
        save: vi.fn(async () => {
          throw new Error('secure store unavailable');
        }),
        read: vi.fn(async () => null),
        remove,
        purgeLegacy: vi.fn(async () => undefined)
      }
    });

    await expect(runInit(deps)).resolves.toBe(1);
    await expect(readStoredConfig(dir)).resolves.toBeNull();
    expect(remove).toHaveBeenCalledWith('admin@192.0.2.1');
    expect(out.join('\n')).toMatch(/store the password securely/i);
    expect(out.join('\n')).toMatch(/no plaintext/i);
  });

  it('restores the previous credential when a keychain save changes it but verification fails', async () => {
    let current = 'old-password';
    let saveCalls = 0;
    const save = vi.fn(async (_account: string, secret: string) => {
      current = secret;
      saveCalls += 1;
      if (saveCalls === 1) throw new Error('verification failed');
      return 'the system keychain';
    });
    const { deps } = await makeDeps({
      store: {
        read: vi.fn(async () => current),
        save,
        remove: vi.fn(async () => undefined),
        purgeLegacy: vi.fn(async () => undefined)
      }
    });

    await expect(runInit(deps)).resolves.toBe(1);
    expect(current).toBe('old-password');
    expect(save).toHaveBeenNthCalledWith(1, 'admin@192.0.2.1', 'hunter2');
    expect(save).toHaveBeenNthCalledWith(2, 'admin@192.0.2.1', 'old-password');
  });

  it('takes the host the user types over the discovered one', async () => {
    const { deps } = await makeDeps({ prompt: vi.fn(async () => '198.51.100.7') });
    await runInit(deps);
    expect(deps.identify).toHaveBeenCalledWith('198.51.100.7');
  });

  it('falls back to a sensible default when no gateway is found', async () => {
    const { deps } = await makeDeps({ discoverGateway: vi.fn(async () => null) });
    await runInit(deps);
    expect(deps.identify).toHaveBeenCalledWith('192.168.1.1');
  });

  it('reports where the secret went', async () => {
    const { deps, out } = await makeDeps();
    await runInit(deps);
    expect(out.join('\n')).toMatch(/system keychain/);
  });

  it('verifies before it writes anything and purges legacy last', async () => {
    const order: string[] = [];
    const { deps } = await makeDeps({
      verify: vi.fn(async () => {
        order.push('verify');
        return { ok: true as const, model: 'M', firmware: '5.1.3', components: 1 };
      }),
      store: {
        save: vi.fn(async () => {
          order.push('save');
          return 'the system keychain';
        }),
        read: vi.fn(async () => null),
        remove: vi.fn(async () => undefined),
        purgeLegacy: vi.fn(async () => {
          order.push('purge');
        })
      }
    });
    await runInit(deps);
    expect(order).toEqual(['verify', 'save', 'purge']);
  });

  it('restores the prior credential and does not purge legacy when writing settings fails', async () => {
    const base = await mkdtemp(join(tmpdir(), 'kn-init-blocked-'));
    const blocked = join(base, 'not-a-directory');
    await writeFile(blocked, 'blocked', 'utf8');

    let current = 'old-password';
    const save = vi.fn(async (_account: string, secret: string) => {
      current = secret;
      return 'the system keychain';
    });
    const purgeLegacy = vi.fn(async () => undefined);
    const { deps } = await makeDeps({
      configDir: blocked,
      store: {
        read: vi.fn(async () => current),
        save,
        remove: vi.fn(async () => undefined),
        purgeLegacy
      }
    });

    await expect(runInit(deps)).resolves.toBe(1);
    expect(current).toBe('old-password');
    expect(save).toHaveBeenNthCalledWith(1, 'admin@192.0.2.1', 'hunter2');
    expect(save).toHaveBeenNthCalledWith(2, 'admin@192.0.2.1', 'old-password');
    expect(purgeLegacy).not.toHaveBeenCalled();
  });

  it('does not purge the old active legacy credential when changing accounts and config write fails', async () => {
    const base = await mkdtemp(join(tmpdir(), 'kn-init-change-blocked-'));
    const blocked = join(base, 'not-a-directory');
    await writeFile(blocked, 'blocked', 'utf8');

    const remove = vi.fn(async () => undefined);
    const purgeLegacy = vi.fn(async () => undefined);
    const { deps } = await makeDeps({
      configDir: blocked,
      prompt: vi
        .fn()
        .mockResolvedValueOnce('198.51.100.7')
        .mockResolvedValueOnce('newadmin'),
      store: {
        read: vi.fn(async () => null),
        save: vi.fn(async () => 'the system keychain'),
        remove,
        purgeLegacy
      }
    });

    await expect(runInit(deps)).resolves.toBe(1);
    expect(remove).toHaveBeenCalledWith('newadmin@198.51.100.7');
    expect(purgeLegacy).not.toHaveBeenCalled();
  });

  it('reports incomplete migration if legacy plaintext cannot be removed after success', async () => {
    const { deps, out, dir } = await makeDeps({
      store: {
        read: vi.fn(async () => null),
        save: vi.fn(async () => 'the system keychain'),
        remove: vi.fn(async () => undefined),
        purgeLegacy: vi.fn(async () => {
          throw new Error('access denied');
        })
      }
    });

    await expect(runInit(deps)).resolves.toBe(1);
    await expect(readStoredConfig(dir)).resolves.toEqual({ host: '192.0.2.1', login: 'admin' });
    expect(out.join('\n')).toMatch(/legacy plaintext/i);
    expect(out.join('\n')).toMatch(/access denied/i);
  });
});
