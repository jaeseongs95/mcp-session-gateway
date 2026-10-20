import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { type PublicJwk, signProof } from './pop.ts';

type Reply = Record<string, unknown>;

// One shim process per agent session, started by the host over stdio. Its Ed25519 key and its token live only in this
// process's memory and never appear in a tool result, so the model never sees either.
export function createShim(gatewayUrl: string, env: NodeJS.ProcessEnv = process.env): McpServer {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicJwk = publicKey.export({ format: 'jwk' }) as PublicJwk;
  let reg: { id: string; generation: number } | undefined;
  let registering: Promise<void> | undefined;
  let token: Promise<string> | undefined;
  // Issuing a token replaces the previous one on the gateway, so at most one request for it is in flight.
  function freshToken(): Promise<string> {
    const pending = post('/agent/token', 'token', {}).then((r) => String(r.token));
    token = pending;
    pending.catch(() => {
      if (token === pending) token = undefined;
    });
    return pending;
  }

  const server = new McpServer({ name: 'mcp-session-gateway-shim', version: '0.0.0' });

  async function post(path: string, method: string, payload: unknown, bearer?: string): Promise<Reply> {
    const body = JSON.stringify(payload);
    const proof = signProof(
      privateKey,
      { method, registrationId: reg?.id ?? '', generation: reg?.generation ?? 0, requestId: randomUUID(), iat: Date.now(), nonce: randomUUID() },
      body,
    );
    const headers: Record<string, string> = { 'content-type': 'application/json', 'x-proof': `${proof.payload}.${proof.sig}` };
    if (bearer) headers.authorization = `Bearer ${bearer}`;
    const res = await fetch(new URL(path, gatewayUrl), { method: 'POST', headers, body });
    const reply = (await res.json().catch(() => ({}))) as Reply;
    if (!res.ok) throw Object.assign(new Error('refused'), { code: String(reply.error ?? res.status) });
    return reply;
  }

  // Labels are display only. Claude Code passes its session id in the environment; Codex sends threadId in tool-call _meta.
  function ensureRegistered(meta: Record<string, unknown> | undefined, requestedScopes: unknown[] = []): Promise<void> {
    registering ??= (async () => {
      const hostClaim = server.server.getClientVersion()?.name ?? 'unknown';
      const sessionLabel = env.CLAUDE_CODE_SESSION_ID ?? (typeof meta?.threadId === 'string' ? meta.threadId : 'unknown');
      const r = await post('/agent/register', 'register', { displayName: env.MCP_SESSION_NAME ?? hostClaim, sessionLabel, hostClaim, publicJwk, requestedScopes });
      reg = { id: String(r.id), generation: Number(r.generation) };
    })().catch((err) => {
      registering = undefined;
      throw err;
    });
    return registering;
  }

  async function reply(fn: () => Promise<unknown>) {
    try {
      return { content: [{ type: 'text' as const, text: JSON.stringify(await fn()) }] };
    } catch (err) {
      return { isError: true, content: [{ type: 'text' as const, text: `refused: ${(err as { code?: string }).code ?? 'GATEWAY_UNREACHABLE'}` }] };
    }
  }

  const scope = z.object({ project: z.string(), task: z.string(), mode: z.enum(['READ', 'WRITE']) });

  server.registerTool(
    'gateway_status',
    {
      description:
        'Register this session with the access gateway (first call only) and show its approval state, granted scopes and key fingerprint. ' +
        'Access is granted only by a human admin on the gateway page.',
      inputSchema: { requestedScopes: z.array(scope).optional() },
    },
    ({ requestedScopes }, extra) =>
      reply(async () => {
        await ensureRegistered(extra._meta as Record<string, unknown> | undefined, requestedScopes);
        return post('/agent/status', 'status', {});
      }),
  );

  server.registerTool(
    'ledger_call',
    {
      description: 'Run one allowlisted ledger operation through the gateway, limited to what the admin granted this session.',
      inputSchema: { op: z.string(), project: z.string(), task: z.string(), args: z.record(z.string(), z.unknown()).optional() },
    },
    ({ op, project, task, args }, extra) =>
      reply(async () => {
        await ensureRegistered(extra._meta as Record<string, unknown> | undefined);
        const body = { op, project, task, args: args ?? {} };
        const used = token ?? freshToken();
        try {
          return (await post('/agent/invoke', 'invoke', body, await used)).result;
        } catch (err) {
          // A grant change voids the token before the operation runs, so fetching a new one and sending once more is safe.
          // Parallel calls share one replacement; otherwise each new token would void the one another call just fetched.
          if ((err as { code?: string }).code !== 'AUTHN_BAD_TOKEN') throw err;
          const next = token === used ? freshToken() : (token ?? freshToken());
          return (await post('/agent/invoke', 'invoke', body, await next)).result;
        }
      }),
  );

  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await createShim(process.env.GATEWAY_URL ?? 'http://127.0.0.1:8787').connect(new StdioServerTransport());
}
