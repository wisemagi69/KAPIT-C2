import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api';
import { Icon } from './icons';
import { formatAge, parseOperationsHealth } from './healthStatus';
import type { OperationsHealth as Health } from './types';

const BACKUP_LABELS: Record<Health['backup']['status'], string> = {
  CURRENT: 'Backed up', DUE: 'Backup due', OVERDUE: 'Backup overdue', NONE: 'No backup found', UNAVAILABLE: 'Unavailable',
};

function backupDetail(backup: Health['backup']): string {
  const age = backup.age_seconds === null ? '' : `${formatAge(backup.age_seconds)} ago`;
  switch (backup.status) {
    case 'CURRENT': return `${age}. The next backup runs after ${backup.interval_hours} h.`;
    case 'DUE': return `${age}. The running website starts one at its next hourly check.`;
    case 'OVERDUE': return `${age}. Older than the ${backup.rpo_hours} h recovery point target.`;
    case 'NONE': return 'No verified backup record was found.';
    case 'UNAVAILABLE': return 'Backup status is available only on the local runtime.';
  }
}

function warnings(health: Health): string[] {
  const { jobs, backup } = health;
  const list: string[] = [];
  if (jobs.expired_leases) list.push(`${jobs.expired_leases} processing jobs have an expired lease. The worker retries them when it next claims work.`);
  if (jobs.missing_leases) list.push(`${jobs.missing_leases} processing jobs have no lease recorded.`);
  if (jobs.unknown_status) list.push(`${jobs.unknown_status} jobs have an unrecognized status.`);
  if (backup.status === 'OVERDUE' || backup.status === 'NONE') list.push('Create a backup now: run python infra/local.py native-backup, or restart the website with infra/Start KAPIT.cmd.');
  return list;
}

export default function OperationsHealth() {
  const [health, setHealth] = useState<Health | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const sequence = useRef(0);

  const refresh = useCallback(async () => {
    const current = ++sequence.current;
    setLoading(true); setFailed(false);
    try {
      const parsed = parseOperationsHealth(await api.operationsHealth());
      if (current !== sequence.current) return;
      setHealth(parsed); setFailed(parsed === null);
    } catch {
      if (current !== sequence.current) return;
      setHealth(null); setFailed(true);
    } finally { if (current === sequence.current) setLoading(false); }
  }, []);
  useEffect(() => { void refresh(); return () => { sequence.current++; }; }, [refresh]);

  const shown = !loading && !failed ? health : null;
  const jobs = shown?.jobs, backup = shown?.backup;
  const value = (number: number | undefined) => number === undefined ? '—' : number;
  const notes = shown ? warnings(shown) : [];
  const failedDetail = jobs ? [jobs.failures_by_code.RULE_PROCESSING_FAILED && `${jobs.failures_by_code.RULE_PROCESSING_FAILED} rule processing`,
    jobs.failures_by_code.ATTEMPTS_EXHAUSTED && `${jobs.failures_by_code.ATTEMPTS_EXHAUSTED} attempts exhausted`,
    jobs.failures_by_code.STALE_CONTEXT && `${jobs.failures_by_code.STALE_CONTEXT} stale context`,
    jobs.unclassified_failures && `${jobs.unclassified_failures} other`].filter(Boolean).join(' · ') || 'No failed jobs' : '';

  return <section className="card operations-health" aria-labelledby="operations-health-title" aria-busy={loading}>
    <div className="card-heading"><div><h3 id="operations-health-title">Operations health</h3><p>Processing jobs in your organization, and the last verified backup of the whole local database. Counts only, never report content.</p></div>
      <button type="button" className="button secondary small" onClick={() => void refresh()} disabled={loading}><Icon name="refresh" size={16} />Refresh health</button></div>
    <p className="report-activity-message" role="status">{loading ? 'Checking operations health…' : !shown ? 'Operations health unavailable. Account administration still works.' : `Checked ${shown.generated_utc.replace('T', ' ').replace('Z', ' UTC')}.`}</p>
    <dl className="health-grid">
      <div className="health-tile"><dt>Waiting jobs</dt><dd><strong>{value(jobs?.by_status.PENDING)}</strong><span>{jobs ? jobs.oldest_pending_available_age_seconds === null ? 'Nothing waiting' : `Oldest waiting ${formatAge(jobs.oldest_pending_available_age_seconds)}` : ''}</span></dd></div>
      <div className={'health-tile' + (jobs?.expired_leases ? ' is-warning' : '')}><dt>Processing</dt><dd><strong>{value(jobs?.by_status.PROCESSING)}</strong><span>{jobs ? `${jobs.expired_leases} expired leases` : ''}</span></dd></div>
      <div className={'health-tile' + (jobs?.by_status.FAILED ? ' is-warning' : '')}><dt>Failed jobs</dt><dd><strong>{value(jobs?.by_status.FAILED)}</strong><span>{failedDetail}</span></dd></div>
      <div className="health-tile"><dt>Completed jobs</dt><dd><strong>{value(jobs?.by_status.DONE)}</strong><span>{jobs ? 'All time' : ''}</span></dd></div>
      <div className={'health-tile' + (backup && backup.status !== 'CURRENT' ? ' is-warning' : '')}><dt>Database backup</dt><dd><strong className="health-text">{backup ? BACKUP_LABELS[backup.status] : '—'}</strong><span>{backup ? backupDetail(backup) : ''}</span>{backup?.last_verified_utc && <span>Verified when created {backup.last_verified_utc.replace('T', ' ').replace('Z', ' UTC')}</span>}</dd></div>
    </dl>
    {notes.length > 0 && <ul className="health-warnings">{notes.map(note => <li key={note}><Icon name="alert" size={16} />{note}</li>)}</ul>}
  </section>;
}
