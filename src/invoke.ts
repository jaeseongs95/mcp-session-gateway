import { type Db, GateError } from './store.ts';
import { type Mode, runUnderGrant } from './grants.ts';
import { type Registration, label } from './registry.ts';
import { checkToken } from './tokens.ts';
import { leasedAccount } from './leases.ts';

interface Operation {
  mode: Mode;
  run: (db: Db, project: string, task: string, args: Record<string, unknown>, now: number) => unknown;
}

// Synthetic stand-in for the ledger backend (decision D3): only these named operations exist and there is no SQL passthrough.
// ponytail: the synthetic table shares the gate's SQLite connection so check and write share one transaction;
// a real backend gets its own READ and WRITE pools and moves the check into that backend transaction.
const OPERATIONS: Record<string, Operation> = {
  'ledger.read_entries': {
    mode: 'READ',
    run: (db, project, task) =>
      db.prepare('SELECT note, at FROM synthetic_ledger WHERE project = ? AND task = ? ORDER BY id').all(project, task),
  },
  'schedule.update_task': {
    mode: 'WRITE',
    run: (db, project, task, args, now) => {
      db.prepare('INSERT INTO synthetic_ledger (project, task, note, at) VALUES (?, ?, ?, ?)').run(project, task, label(args.note, 'note'), now);
      return { written: 1 };
    },
  },
};

// The READ path runs with the connection in query_only mode and always switches it back, so nothing leaks into the next request.
export function readOnly<T>(db: Db, fn: () => T): T {
  db.exec('PRAGMA query_only = ON');
  try {
    return fn();
  } finally {
    db.exec('PRAGMA query_only = OFF');
  }
}

// body is the exact JSON the shim signed: {op, project, task, args}. Caller identity comes only from the verified proof.
export function invoke(db: Db, reg: Registration, requestId: string, body: string, token: unknown, now: number): unknown {
  let req: Record<string, unknown> | null;
  try {
    req = JSON.parse(body);
  } catch {
    throw new GateError('INVALID_INPUT', 'body');
  }
  const name = req?.op;
  if (typeof name !== 'string' || !Object.hasOwn(OPERATIONS, name)) throw new GateError('AUTHZ_UNKNOWN_OPERATION');
  const op = OPERATIONS[name];
  const project = label(req?.project, 'project');
  const task = label(req?.task, 'task');
  const args = req?.args && typeof req.args === 'object' ? (req.args as Record<string, unknown>) : {};
  return runUnderGrant(db, reg, { project, task, mode: op.mode }, requestId, now, (grantVersion) => {
    checkToken(db, reg.id, grantVersion, token);
    // A real backend runs the operation on this account's own connection; the synthetic one only requires the lease to be live.
    leasedAccount(db, reg.id, now);
    const run = () => op.run(db, project, task, args, now);
    return op.mode === 'READ' ? readOnly(db, run) : run();
  });
}
