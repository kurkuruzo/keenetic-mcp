import type { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import { fail, guard, ok, toolName, type ToolScope, type ToolResult } from './registry.js';

type RawBody = string | Record<string, unknown> | unknown[];

type Decoded = { ok: true; body: unknown } | { ok: false; message: string };

/**
 * Accepts a body that arrived as text and turns it back into a command tree.
 *
 * The schema for `body` used to be `z.unknown()`, which emits a JSON Schema
 * carrying no `type` at all. A client given nothing to go on may serialise the
 * argument to a string; that string was then JSON-encoded a second time on the
 * way out, so the router received a bare string, matched no command and
 * answered `{}`. Shaped like success, a no-op in fact - the exact failure this
 * server exists to prevent everywhere else.
 *
 * Decoding keeps those callers working. Anything that still is not a command
 * tree afterwards is refused rather than sent.
 */
function decodeBody(body: RawBody): Decoded {
  if (typeof body !== 'string') return { ok: true, body };

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return {
      ok: false,
      message:
        `The body is a string that is not JSON: ${body.slice(0, 60)}. Send the command as ` +
        'JSON, for example {"show": {"version": {}}}.'
    };
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return {
      ok: false,
      message:
        `The body decoded to a ${typeof parsed}, not a command tree. Send an object such as ` +
        '{"show": {"version": {}}}, or an array of them for a batch.'
    };
  }

  return { ok: true, body: parsed };
}

export function registerRawTool(server: McpServer, scope: ToolScope): void {
  server.registerTool(
    toolName(scope, 'rci_call'),
    {
      title: 'Call the router API directly',
      description:
        'Sends a raw request to the router RCI interface, for anything the other tools do ' +
        'not cover. GET reads a path such as "show/version" or "interface/Bridge0"; POST ' +
        'sends a command object mirroring the CLI tree. The response is capped, so ask for ' +
        'a narrow path rather than a broad one: show/ip/nat alone is over 100 KB.',
      inputSchema: {
        method: z.enum(['GET', 'POST']).describe('GET reads, POST executes a command.'),
        path: z
          .string()
          .optional()
          .describe('Path after /rci/, for GET. Example: show/interface/Bridge0'),
        // Typed as a union rather than z.unknown() so the emitted schema tells a
        // client what shape to send; see decodeBody for what the loose form cost.
        body: z
          .union([z.record(z.string(), z.unknown()), z.array(z.unknown()), z.string()])
          .optional()
          .describe(
            'Command object for POST, mirroring the CLI tree, or an array of them for a ' +
              'batch. Send JSON, not a stringified object.'
          ),
        max_bytes: z
          .number()
          .int()
          .min(200)
          .optional()
          .describe('Lower the response ceiling for this call. It can never raise it.')
      },
      // In read-only mode POST is refused, so the tool genuinely cannot modify
      // anything and the annotation says so rather than overstating the risk.
      annotations: scope.readOnly
        ? { readOnlyHint: true, openWorldHint: false }
        : { readOnlyHint: false, destructiveHint: true, openWorldHint: false }
    },
    guard(scope, async (ctx, { method, path, body, max_bytes }): Promise<ToolResult> => {
      let payload: unknown;

      if (method === 'GET') {
        if (path === undefined || path.length === 0) {
          return fail(new Error('GET needs a path, for example "show/version".'));
        }
      } else {
        if (ctx.readOnly) {
          return fail(
            new Error(
              'This server is running read-only, so POST is refused. Use GET to read, or ' +
                'ask the user to restart the server without --read-only.'
            )
          );
        }
        if (body === undefined) {
          return fail(new Error('POST needs a body, for example {"show": {"version": {}}}.'));
        }
        const decoded = decodeBody(body);
        if (!decoded.ok) return fail(new Error(decoded.message));
        payload = decoded.body;
      }

      const result =
        method === 'GET' ? await ctx.client.rci.get(path as string) : await ctx.client.rci.post(payload);

      // max_bytes may only tighten the ceiling: a tool argument must not be able
      // to overrun the budget the operator configured with --max-response-bytes.
      const ceiling = Math.min(ctx.maxResponseBytes, max_bytes ?? ctx.maxResponseBytes);
      return ok(result, ceiling);
    })
  );
}
