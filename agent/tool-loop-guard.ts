import { AIMessage, ToolMessage, createMiddleware } from 'langchain';

export const EXACT_TOOL_CALL_LIMIT = 3;

export interface ToolCallLike {
  id?: string;
  name?: string;
  args?: unknown;
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(',')}}`;
  return JSON.stringify(value);
}

export function exactToolCallKey(call: ToolCallLike): string {
  return `${String(call.name || 'unknown')}:${stable(call.args || {})}`;
}

export class ExactToolCallGuard {
  private readonly counts = new Map<string, number>();
  private readonly seenCallIds = new Set<string>();

  constructor(readonly limit = EXACT_TOOL_CALL_LIMIT) {
    if (!Number.isInteger(limit) || limit < 1) throw new Error('Exact tool-call limit must be a positive integer.');
  }

  register(call: ToolCallLike): { allowed: boolean; count: number; key: string } {
    const key = exactToolCallKey(call);
    if (call.id && this.seenCallIds.has(call.id)) return { allowed: (this.counts.get(key) || 0) <= this.limit, count: this.counts.get(key) || 0, key };
    if (call.id) this.seenCallIds.add(call.id);
    const count = (this.counts.get(key) || 0) + 1;
    this.counts.set(key, count);
    return { allowed: count <= this.limit, count, key };
  }
}

/**
 * Stops an investigation before executing a fourth semantically identical tool
 * request. The guard is per agent instance, so its state cannot cross scans.
 */
export function exactToolCallLimitMiddleware(limit = EXACT_TOOL_CALL_LIMIT) {
  const guard = new ExactToolCallGuard(limit);
  return createMiddleware({
    name: 'ExactToolCallLimitMiddleware',
    afterModel: {
      canJumpTo: ['end'],
      hook: (state) => {
        const last = state.messages.at(-1) as { tool_calls?: ToolCallLike[] } | undefined;
        const calls = last?.tool_calls || [];
        if (!calls.length) return;
        const checked = calls.map((call) => ({ call, result: guard.register(call) }));
        const violation = checked.find((item) => !item.result.allowed);
        if (!violation) return;

        const tool = String(violation.call.name || 'unknown');
        const reason = `Exact tool-call repetition guard stopped the investigation before executing call ${violation.result.count}: ${tool} received the same canonical parameters more than ${limit} times.`;
        const toolMessages = calls.map((call, index) => new ToolMessage({
          content: `${reason} No request from this model turn was executed.`,
          tool_call_id: String(call.id || `repetition-guard-${index}`),
          name: String(call.name || 'unknown'),
          status: 'error'
        }));
        return { jumpTo: 'end' as const, messages: [...toolMessages, new AIMessage(reason)] };
      }
    }
  });
}
