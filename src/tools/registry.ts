import { KeeneticError } from '../router/errors.js';
import type { BackupGuard } from '../router/backup.js';
import type { KeeneticClient } from '../router/client.js';
import { capText } from '../shape/budget.js';

export interface ToolContext {
  client: KeeneticClient;
  maxResponseBytes: number;
  readOnly: boolean;
  /** Snapshots the startup config once, before the first mutating call. */
  backup: BackupGuard;
}

export type ToolScope = ToolContext | {
  profile: string;
  readOnly: boolean;
  getContext: () => Promise<ToolContext>;
};

export function toolName(scope: ToolScope, name: string): string {
  return 'profile' in scope ? `${scope.profile}_${name}` : name;
}

/**
 * The SDK types a tool result structurally and requires an index signature, so
 * a closed interface is not assignable to it. The extra members stay declared
 * because they are what this codebase actually produces.
 */
export interface ToolResult {
  [key: string]: unknown;
  content: Array<{ type: 'text'; text: string }>;
  isError?: true;
}

/** `maxBytes` caps the serialised payload; omit it for responses already shaped. */
export function ok(payload: unknown, maxBytes?: number): ToolResult {
  const text = JSON.stringify(payload, null, 2);
  return {
    content: [{ type: 'text', text: maxBytes === undefined ? text : capText(text, maxBytes) }]
  };
}

/**
 * Every handler funnels failures through here. The text is read by a model, so
 * it must say what happened and what to do next - never a bare stack trace.
 */
export function fail(error: unknown, systemInfoTool = 'get_system_info'): ToolResult {
  const text =
    error instanceof KeeneticError
      ? error.message
      : error instanceof Error
        ? `${error.message} Retry, or call ${systemInfoTool} to check connectivity.`
        : `${String(error)} Retry, or call ${systemInfoTool} to check connectivity.`;
  return { content: [{ type: 'text', text }], isError: true };
}

/** Wraps a handler so it can never reject - the SDK expects a result, not a throw. */
export function guard<A>(
  scope: ToolScope,
  handler: (ctx: ToolContext, args: A) => Promise<ToolResult>
): (args: A) => Promise<ToolResult> {
  return async (args: A) => {
    try {
      const ctx = 'getContext' in scope ? await scope.getContext() : scope;
      return await handler(ctx, args);
    } catch (error) {
      return fail(error, toolName(scope, 'get_system_info'));
    }
  };
}

export const READ_ONLY = { readOnlyHint: true, openWorldHint: false } as const;

/**
 * A note on `inputSchema`.
 *
 * Tools here pass a raw shape (`{ mac: z.string() }`) rather than the
 * `z.object({...})` the SDK documents and marks as preferred. That is not a
 * style choice: in @modelcontextprotocol/server 2.0.0 the preferred overload
 * declares `OutputArgs extends StandardSchemaWithJSON` with no default, so
 * without an explicit `outputSchema` the generic cannot be inferred, the call
 * falls through to the raw-shape overload, and a `z.object()` is then rejected.
 *
 * The raw-shape form is fully typed and infers handler arguments correctly.
 * When the SDK gives `OutputArgs` a default, switching is mechanical.
 */
