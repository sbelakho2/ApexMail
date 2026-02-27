export const ATOMIC_DRAIN_SCRIPT = `
local events = redis.call('LRANGE', KEYS[1], 0, tonumber(ARGV[1]) - 1)
if #events > 0 then
  redis.call('LTRIM', KEYS[1], #events, -1)
end
return events
`;

interface MockRedisState {
  list: string[];
  evalCalls: Array<{ script: string; keys: string[]; args: string[] }>;
}

export function createMockRedis(): MockRedisState & {
  rpush: (key: string, value: string) => void;
  eval: (script: string, numKeys: number, key: string, ...args: string[]) => string[];
} {
  const state: MockRedisState = { list: [], evalCalls: [] };
  return {
    ...state,
    rpush: (_key: string, value: string) => {
      state.list.push(value);
    },
    eval: (script: string, _numKeys: number, key: string, ...args: string[]) => {
      state.evalCalls.push({ script, keys: [key], args });
      const batchSize = parseInt(args[0] ?? '100', 10);
      const events = state.list.splice(0, batchSize);
      return events;
    },
  };
}
