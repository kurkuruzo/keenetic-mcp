import type { McpServer } from '@modelcontextprotocol/server';
import { readConfigState } from '../router/config-state.js';
import { guard, ok, READ_ONLY, toolName, type ToolScope } from './registry.js';

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : {};
}

export function registerSystemTools(server: McpServer, scope: ToolScope): void {
  server.registerTool(
    toolName(scope, 'get_system_info'),
    {
      title: 'Router system information',
      description:
        'Model, firmware version, uptime, CPU and memory load, and the list of installed ' +
        'KeeneticOS components. Call this first when you need to know what the router supports: ' +
        'the component list tells you which features exist on this device.',
      inputSchema: {},
      annotations: READ_ONLY
    },
    guard(scope, async (ctx) => {
      const [caps, system] = await Promise.all([
        ctx.client.capabilities(),
        ctx.client.rci.get('show/system')
      ]);
      const s = asRecord(system);

      return ok({
        model: caps.model,
        hardwareId: caps.hwId,
        firmware: caps.firmware,
        hostname: s['hostname'] ?? '',
        uptimeSeconds: Number(s['uptime'] ?? 0),
        cpuLoad: s['cpuload'] ?? null,
        memoryTotalKb: s['memtotal'] ?? null,
        memoryFreeKb: s['memfree'] ?? null,
        connectionsTotal: s['conntotal'] ?? null,
        connectionsFree: s['connfree'] ?? null,
        components: [...caps.components].sort(),
        features: [...caps.features].sort()
      });
    })
  );

  server.registerTool(
    toolName(scope, 'get_config_state'),
    {
      title: 'Configuration state',
      description:
        'Whether the running configuration has unsaved changes, who last changed it and when, ' +
        'and the state of the router fail-safe timer. Unsaved changes are lost on reboot. ' +
        'unsavedChanges is null when the saved checksum could not be read - treat that as ' +
        'unknown, not as saved.',
      inputSchema: {},
      annotations: READ_ONLY
    },
    guard(scope, async (ctx) => ok(await readConfigState(ctx.client.rci)))
  );
}
