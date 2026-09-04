import { describe, expect, it } from 'vitest';
import { loadConfig, storedIdentityMatches } from '../../src/config/load.js';

const STORED = { host: '198.51.100.1', login: 'stored-user', password: 'stored-pass' };

describe('loadConfig precedence', () => {
  it('uses stored values when the environment is empty', async () => {
    const cfg = await loadConfig([], {} as NodeJS.ProcessEnv, STORED);
    expect(cfg).toMatchObject({
      host: '198.51.100.1',
      login: 'stored-user',
      password: 'stored-pass'
    });
  });

  it('lets the environment override every stored value', async () => {
    const cfg = await loadConfig(
      [],
      {
        KEENETIC_HOST: '192.0.2.9',
        KEENETIC_USER: 'env-user',
        KEENETIC_PASSWORD: 'env-pass'
      } as NodeJS.ProcessEnv,
      STORED
    );
    expect(cfg).toMatchObject({ host: '192.0.2.9', login: 'env-user', password: 'env-pass' });
  });

  it('does not reuse the stored password when --host points at another router', async () => {
    await expect(
      loadConfig(['--host', '192.0.2.5'], {} as NodeJS.ProcessEnv, STORED)
    ).rejects.toThrow(/KEENETIC_PASSWORD|init/);
  });

  it('does not reuse the stored password when KEENETIC_HOST points at another router', async () => {
    await expect(
      loadConfig([], { KEENETIC_HOST: '192.0.2.9' } as NodeJS.ProcessEnv, STORED)
    ).rejects.toThrow(/KEENETIC_PASSWORD|init/);
  });

  it('does not reuse the stored password for another login', async () => {
    await expect(
      loadConfig([], { KEENETIC_USER: 'other-user' } as NodeJS.ProcessEnv, STORED)
    ).rejects.toThrow(/KEENETIC_PASSWORD|init/);
  });

  it('allows a redirected host when an explicit environment password is supplied', async () => {
    const cfg = await loadConfig(
      ['--host', '192.0.2.5'],
      { KEENETIC_PASSWORD: 'env-pass' } as NodeJS.ProcessEnv,
      STORED
    );
    expect(cfg).toMatchObject({
      host: '192.0.2.5',
      login: 'stored-user',
      password: 'env-pass'
    });
  });

  it('lets the environment beat the flag when the environment supplies credentials', async () => {
    const cfg = await loadConfig(
      ['--host', '192.0.2.5'],
      { KEENETIC_HOST: '192.0.2.9', KEENETIC_PASSWORD: 'env-pass' } as NodeJS.ProcessEnv,
      STORED
    );
    expect(cfg.host).toBe('192.0.2.9');
  });

  it('identifies whether a stored secret belongs to the final router identity', () => {
    expect(storedIdentityMatches([], {} as NodeJS.ProcessEnv, STORED)).toBe(true);
    expect(
      storedIdentityMatches(['--host', '192.0.2.5'], {} as NodeJS.ProcessEnv, STORED)
    ).toBe(false);
    expect(
      storedIdentityMatches([], { KEENETIC_USER: 'other-user' } as NodeJS.ProcessEnv, STORED)
    ).toBe(false);
  });

  it('points at the wizard when nothing is configured', async () => {
    await expect(loadConfig([], {} as NodeJS.ProcessEnv, undefined)).rejects.toThrow(
      /keenetic-mcp init/
    );
  });

  it('points at the wizard when the host is known but the password is not', async () => {
    await expect(
      loadConfig([], {} as NodeJS.ProcessEnv, { host: '192.0.2.1', login: 'admin' })
    ).rejects.toThrow(/keenetic-mcp init/);
  });

  it('defaults the login to admin', async () => {
    const cfg = await loadConfig([], {} as NodeJS.ProcessEnv, {
      host: '192.0.2.1',
      password: 'p'
    });
    expect(cfg.login).toBe('admin');
  });

  it('still honours --read-only and --max-response-bytes', async () => {
    const cfg = await loadConfig(
      ['--read-only', '--max-response-bytes', '8000'],
      {} as NodeJS.ProcessEnv,
      STORED
    );
    expect(cfg.readOnly).toBe(true);
    expect(cfg.maxResponseBytes).toBe(8000);
  });

  it('rejects a nonsense --max-response-bytes', async () => {
    await expect(
      loadConfig(['--max-response-bytes', 'lots'], {} as NodeJS.ProcessEnv, STORED)
    ).rejects.toThrow(/positive integer/);
  });
});
