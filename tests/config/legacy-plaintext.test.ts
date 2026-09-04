import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { createSecretStore, type Runner } from '../../src/config/secrets.js';

function dpapiRunner(secret = 'active-password'): Runner {
  return vi.fn(async (_command: string, args: string[]) => {
    const script = args.at(-1) ?? '';
    if (script.includes('::Protect(')) return { code: 0, stdout: 'encrypted-active-password' };
    if (script.includes('::Unprotect(')) return { code: 0, stdout: secret };
    return { code: 1, stdout: '' };
  }) as unknown as Runner;
}

describe('legacy plaintext cleanup', () => {
  it('keeps legacy credentials during migration and removes the whole file only on explicit commit', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'kn-legacy-'));
    await writeFile(
      join(dir, 'secrets.json'),
      `${JSON.stringify({
        'admin@192.0.2.1': 'active-password',
        'admin@198.51.100.9': 'orphaned-old-password'
      })}\n`,
      'utf8'
    );

    const store = createSecretStore('win32', dpapiRunner(), dir);
    await expect(store.read('admin@192.0.2.1')).resolves.toBe('active-password');

    const protectedFile = await readFile(join(dir, 'secrets.dpapi.json'), 'utf8');
    expect(protectedFile).toContain('encrypted-active-password');
    expect(protectedFile).not.toContain('active-password');
    expect(protectedFile).not.toContain('orphaned-old-password');

    const legacyBeforeCommit = await readFile(join(dir, 'secrets.json'), 'utf8');
    expect(legacyBeforeCommit).toContain('active-password');
    expect(legacyBeforeCommit).toContain('orphaned-old-password');

    await store.purgeLegacy();
    await expect(readFile(join(dir, 'secrets.json'), 'utf8')).rejects.toThrow();
  });
});
