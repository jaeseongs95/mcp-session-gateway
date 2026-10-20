import { type Db, GateError, audit, auditRejection, one } from './store.ts';

// Exclusive lease (decision D5): a pool account serves at most one registration at a time, so the database's session_user
// plus the lease rows in the audit log attribute every database session to one agent session. Only the gateway ever holds
// an account secret (decision D6); agents never see one.
export interface AccountAdmin {
  // Give the account a fresh secret known only to this gateway process, allow LOGIN, set VALID UNTIL.
  lend(account: string, validUntil: number): Promise<void>;
  // Disallow LOGIN, drop the secret and end every open session of the account.
  reclaim(account: string): Promise<void>;
}

// D1: WRITE is never granted, so only the read tier is ever lent.
export const LEASE_TIER = 'READ';

interface LeaseRow {
  account: string;
  state: 'FREE' | 'LENDING' | 'LENT' | 'RETURNING';
  registration_id: string | null;
  valid_until: number | null;
}

export function syncPool(db: Db, accounts: string[], now: number): void {
  for (const account of accounts) {
    // Names end up as SQL identifiers in the database adapter, so only plain lower-case identifiers are accepted.
    if (!/^[a-z_][a-z0-9_]{0,62}$/.test(account)) throw new Error(`invalid pool account name: ${account}`);
    db.prepare("INSERT OR IGNORE INTO account_leases (account, tier, state, changed_at) VALUES (?, ?, 'FREE', ?)").run(account, LEASE_TIER, now);
  }
}

// Called inside the grant transaction, so a grant never exists without its reserved account. A changed grant re-lends the
// same account, which moves VALID UNTIL.
export function reserveLease(db: Db, registrationId: string, validUntil: number, now: number): string {
  const held = one<LeaseRow>(db, "SELECT * FROM account_leases WHERE registration_id = ? AND state IN ('LENDING', 'LENT')", registrationId);
  const account =
    held?.account ??
    one<LeaseRow>(db, "SELECT * FROM account_leases WHERE state = 'FREE' AND tier = ? ORDER BY account LIMIT 1", LEASE_TIER)?.account;
  if (!account) throw new GateError('AUTHZ_POOL_EXHAUSTED');
  db.prepare("UPDATE account_leases SET state = 'LENDING', registration_id = ?, valid_until = ?, changed_at = ? WHERE account = ?").run(
    registrationId,
    validUntil,
    now,
    account,
  );
  return account;
}

// Called inside the revoke transaction. The account stops serving immediately; the database side follows in settleLeases.
export function releaseLease(db: Db, registrationId: string, now: number): void {
  db.prepare("UPDATE account_leases SET state = 'RETURNING', changed_at = ? WHERE registration_id = ? AND state IN ('LENDING', 'LENT')").run(
    now,
    registrationId,
  );
}

export function leasedAccount(db: Db, registrationId: string, now: number): string {
  const lease = one<LeaseRow>(db, "SELECT * FROM account_leases WHERE registration_id = ? AND state = 'LENT'", registrationId);
  if (!lease || lease.valid_until === null || lease.valid_until <= now) throw new GateError('AUTHZ_LEASE_NOT_READY');
  return lease.account;
}

// A restarted gateway has lost every secret it held, so each lent account is lent again with a new one.
export function restartLeases(db: Db, now: number): void {
  db.prepare("UPDATE account_leases SET state = 'LENDING', changed_at = ? WHERE state = 'LENT'").run(now);
}

// A hung database call must not hold up every later reclaim behind it. The late call may still finish; the row then stays
// as it was and the next pass repeats the step with a fresh secret.
export const LEASE_STEP_MS = 10_000;

function withDeadline(step: Promise<void>): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new GateError('LEASE_TIMEOUT')), LEASE_STEP_MS);
  });
  return Promise.race([step, deadline]).finally(() => clearTimeout(timer));
}

// Drives the database side to match the lease rows. Safe to repeat: a failed step leaves its row as it was for the next pass,
// and a row that changed while the database call was in flight is not overwritten. The caller runs one pass at a time.
export async function settleLeases(db: Db, admin: AccountAdmin, now: number): Promise<void> {
  db.prepare("UPDATE account_leases SET state = 'RETURNING', changed_at = ? WHERE state IN ('LENDING', 'LENT') AND valid_until <= ?").run(now, now);
  const accounts = db.prepare("SELECT account FROM account_leases WHERE state IN ('RETURNING', 'LENDING') ORDER BY account").all() as unknown as { account: string }[];
  for (const { account } of accounts) {
    // Re-read each row: a revoke that committed while an earlier row was awaiting turns LENDING into RETURNING.
    const lease = one<LeaseRow>(db, 'SELECT * FROM account_leases WHERE account = ?', account);
    if (!lease || (lease.state !== 'RETURNING' && lease.state !== 'LENDING')) continue;
    const returning = lease.state === 'RETURNING';
    const entry = { at: now, actor: 'gateway', action: returning ? 'lease:reclaim' : 'lease:lend', target: lease.account, detail: lease.registration_id ?? undefined };
    try {
      if (returning) {
        await withDeadline(admin.reclaim(lease.account));
        db.prepare("UPDATE account_leases SET state = 'FREE', registration_id = NULL, valid_until = NULL, changed_at = ? WHERE account = ? AND state = 'RETURNING'").run(
          now,
          lease.account,
        );
      } else {
        await withDeadline(admin.lend(lease.account, lease.valid_until ?? now));
        db.prepare(
          "UPDATE account_leases SET state = 'LENT', changed_at = ? WHERE account = ? AND state = 'LENDING' AND registration_id = ? AND valid_until = ?",
        ).run(now, lease.account, lease.registration_id, lease.valid_until);
      }
      audit(db, entry, 'ok');
    } catch (err) {
      auditRejection(db, entry, err);
    }
  }
}

// Synthetic pool for the prototype and its tests: it only records which accounts a real database adapter would have opened.
export function memoryAccountAdmin(): AccountAdmin & { loggedIn: Set<string> } {
  const loggedIn = new Set<string>();
  return {
    loggedIn,
    lend: async (account) => {
      loggedIn.add(account);
    },
    reclaim: async (account) => {
      loggedIn.delete(account);
    },
  };
}
