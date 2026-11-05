import type { BackupState, FailureCode, JobStatus, OperationsHealth } from './types';

export const JOB_STATUSES: readonly JobStatus[] = ['PENDING', 'PROCESSING', 'DONE', 'FAILED'];
export const FAILURE_CODES: readonly FailureCode[] = ['RULE_PROCESSING_FAILED', 'ATTEMPTS_EXHAUSTED', 'STALE_CONTEXT'];
const BACKUP_STATES: readonly BackupState[] = ['CURRENT', 'DUE', 'OVERDUE', 'NONE', 'UNAVAILABLE'];
const JOB_KEYS = ['by_status', 'unknown_status', 'expired_leases', 'missing_leases', 'oldest_pending_available_age_seconds', 'failures_by_code', 'unclassified_failures'];
const BACKUP_KEYS = ['status', 'last_verified_utc', 'age_seconds', 'interval_hours', 'rpo_hours', 'basis'];

const record = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const count = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const exact = (value: Record<string, unknown>, keys: readonly string[]) => Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const utc = (value: unknown): value is string => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && Number.isFinite(Date.parse(value));
const counts = <K extends string>(value: unknown, keys: readonly K[]): Record<K, number> | null =>
  record(value) && exact(value, keys) && keys.every(key => count(value[key])) ? Object.fromEntries(keys.map(key => [key, value[key]])) as Record<K, number> : null;

// The response stays untrusted: anything missing or inconsistent shows as
// unavailable, never as an all-clear zero.
export function parseOperationsHealth(value: unknown): OperationsHealth | null {
  if (!record(value) || !exact(value, ['schema_version', 'scope', 'generated_utc', 'jobs', 'backup']) || value.schema_version !== 1 || value.scope !== 'ORGANIZATION' || !utc(value.generated_utc)) return null;
  const { jobs, backup } = value;
  if (!record(jobs) || !exact(jobs, JOB_KEYS) || !record(backup) || !exact(backup, BACKUP_KEYS)) return null;
  const byStatus = counts(jobs.by_status, JOB_STATUSES), failures = counts(jobs.failures_by_code, FAILURE_CODES);
  const oldest = jobs.oldest_pending_available_age_seconds;
  if (!byStatus || !failures || ![jobs.unknown_status, jobs.expired_leases, jobs.missing_leases, jobs.unclassified_failures].every(count) || oldest !== null && !count(oldest)) return null;
  if ((oldest === null) !== (byStatus.PENDING === 0)) return null;
  if (FAILURE_CODES.reduce((sum, code) => sum + failures[code], jobs.unclassified_failures as number) !== byStatus.FAILED) return null;
  if ((jobs.expired_leases as number) + (jobs.missing_leases as number) > byStatus.PROCESSING) return null;
  const state = backup.status;
  if (typeof state !== 'string' || !BACKUP_STATES.includes(state as BackupState) || backup.basis !== 'RECORDED_VERIFIED_AT_CREATION' || !count(backup.interval_hours) || !count(backup.rpo_hours)) return null;
  const known = state === 'CURRENT' || state === 'DUE' || state === 'OVERDUE';
  if (known ? !utc(backup.last_verified_utc) || !count(backup.age_seconds) : backup.last_verified_utc !== null || backup.age_seconds !== null) return null;
  return {
    generated_utc: value.generated_utc,
    jobs: { by_status: byStatus, unknown_status: jobs.unknown_status as number, expired_leases: jobs.expired_leases as number, missing_leases: jobs.missing_leases as number,
      oldest_pending_available_age_seconds: oldest as number | null, failures_by_code: failures, unclassified_failures: jobs.unclassified_failures as number },
    backup: { status: state as BackupState, last_verified_utc: backup.last_verified_utc as string | null, age_seconds: backup.age_seconds as number | null,
      interval_hours: backup.interval_hours, rpo_hours: backup.rpo_hours },
  };
}

export function formatAge(seconds: number): string {
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} h ${minutes % 60} min`;
  return `${Math.floor(hours / 24)} days ${hours % 24} h`;
}
