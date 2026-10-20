# mcp-session-gateway

Per-session, human-approved access for AI agent sessions that reach a database through MCP.

**Status: prototype.** It runs against a synthetic backend and a synthetic account pool. It is not production-ready and makes no claim about real host identity (see Limits).

## How it works

```
agent host (stdio) ── shim ── HTTPS ── gateway ── allowlisted operations ── backend
                       │                  │
          one-time Ed25519 key       registrations, grants, leases, audit
          token, in memory only      admin page (passkey with user verification)
```

1. **Register.** Each agent session starts its own shim process. The shim makes a one-time Ed25519 key, then registers with a request signed by that key. The registration starts as `PENDING`, and a pending registration can read only its own status.
2. **Approve.** On the admin page, a human sees the session name, session ID, claimed host (always shown as *unverified*), requested scopes and granted scopes. They approve, change, rename or revoke a session. Each of these needs a fresh passkey assertion with user presence and user verification. The assertion is bound server-side to that exact action and version, and a signed-in page alone cannot change anything.
3. **Lease.** An approval reserves one database pool account for that session alone (an exclusive lease), valid until the grant expires. Only the gateway holds the account's secret. Revoking or expiring the grant returns the account to the pool.
4. **Call.** Every call carries both the session token and a fresh proof signed with the shim's key. The proof covers method, registration, generation, request ID, time, nonce and a body digest. A copied token without the key is refused. The grant is re-checked inside the same transaction as the operation, so whichever of a call and a revoke commits first wins.

Names, session labels, host claims and requested scopes are display data only. They never grant anything.

## Limits (by design, not yet solved)

- **Host identity is not proven.** Neither MCP host offers a way to prove "this exact session". So every registration is *host unverified*, and **WRITE is never granted.** No switch turns this off.
- **Same-OS-user processes.** Another process running as the same OS user can read the shim's memory or pose as a shim.
- **Admin enrollment** is first-come. It is open only while no admin passkey exists, and it needs a code whose SHA-256 the operator configured. Enroll before you expose the page.
- **No rate limiting.** Enrollment-code attempts, registrations, login challenges and audit rows are not throttled or capped. Keep the gateway on a trusted network.
- **Browser.** The admin page uses the browser's built-in WebAuthn JSON helpers (`PublicKeyCredential.parseRequestOptionsFromJSON`, `toJSON`).
- **Backend and pool are synthetic.** A PostgreSQL adapter for pool roles is not written yet. Design notes:
  - Pool roles are created `NOLOGIN` without a password.
  - A lease sets a fresh SCRAM-SHA-256 verifier, `LOGIN` and `VALID UNTIL`. The gateway computes the verifier, so the plain password never leaves the gateway process.
  - A return sets `NOLOGIN` and `PASSWORD NULL`, then terminates the role's backends.
  - The gateway gets `EXECUTE` on two `SECURITY DEFINER` functions (`lease_open`, `lease_close`) that act only on the pool roles. It gets no `CREATEROLE` and no `pg_signal_backend`. The functions and their owner are set up on the database side and are not part of this repository.
- **Database connection path is open.** If the database accepts connections only from its own host, the gateway cannot reach it from another machine. Where the gateway (or its adapter) runs relative to the database is not decided yet.

## Run

Requires Node.js 24 or later.

```
pnpm install
pnpm typecheck
pnpm test
```

Gateway: `ADMIN_ENROLL_CODE_SHA256=<base64url sha256 of your code> GATEWAY_POOL_ACCOUNTS=ags_ledger_ro_01,ags_ledger_ro_02,ags_ledger_ro_03 pnpm gateway`. Then open `http://localhost:8787/admin`.

Shim (configured in the agent host as a stdio MCP server): `GATEWAY_URL=http://127.0.0.1:8787 node src/shim.ts`. Set `MCP_SESSION_NAME` to choose the display name.

## License

Apache-2.0
