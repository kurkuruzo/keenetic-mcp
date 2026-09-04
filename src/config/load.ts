export interface AppConfig {
  host: string;
  login: string;
  password: string;
  readOnly: boolean;
  maxResponseBytes: number;
}

export interface StoredCredentials {
  host?: string;
  login?: string;
  password?: string;
}

export const DEFAULT_MAX_RESPONSE_BYTES = 25_000;

export function flagValue(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  return argv[index + 1];
}

/**
 * True only when the final router identity still matches the stored identity.
 * A stored password is scoped to that exact host/login pair and must never be
 * reused when an environment variable or CLI flag redirects the connection.
 */
export function storedIdentityMatches(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  stored?: StoredCredentials
): boolean {
  if (!stored?.host) return false;

  const host = env['KEENETIC_HOST'] ?? flagValue(argv, '--host') ?? stored.host;
  const login = env['KEENETIC_USER'] ?? stored.login ?? 'admin';
  return host === stored.host && login === (stored.login ?? 'admin');
}

/**
 * Merges the three sources of configuration.
 *
 * The environment wins over both the flag and the stored value: a container or
 * a CI run has no keychain to read, and must never be redirected by whatever
 * happens to be configured on a developer machine.
 */
export async function loadConfig(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  stored?: StoredCredentials
): Promise<AppConfig> {
  const host = env['KEENETIC_HOST'] ?? flagValue(argv, '--host') ?? stored?.host;
  const login = env['KEENETIC_USER'] ?? stored?.login ?? 'admin';
  const password =
    env['KEENETIC_PASSWORD'] ??
    (storedIdentityMatches(argv, env, stored) ? stored?.password : undefined);

  const rawMax = flagValue(argv, '--max-response-bytes');
  const parsedMax = rawMax === undefined ? DEFAULT_MAX_RESPONSE_BYTES : Number.parseInt(rawMax, 10);
  if (!Number.isFinite(parsedMax) || parsedMax <= 0) {
    throw new Error(`--max-response-bytes must be a positive integer, got "${rawMax}"`);
  }

  if (!host || password === undefined) {
    throw new Error(
      'No router configured. Run "npx keenetic-mcp init" to set one up, or set ' +
        'KEENETIC_HOST and KEENETIC_PASSWORD in the environment.'
    );
  }

  return {
    host,
    login,
    password,
    readOnly: argv.includes('--read-only'),
    maxResponseBytes: parsedMax
  };
}
