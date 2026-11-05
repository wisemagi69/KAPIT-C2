import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError, errorMessage } from './api';
import { BackButton, Loading, Notice, SectionHeading, SourceFields, StatusBadge } from './components';
import { dateLabel } from './domain';
import { Icon } from './icons';
import type { SourceDetail, WithdrawalOperation } from './types';
import WorkflowTimeline from './WorkflowTimeline';
import PrivateEvidence from './PrivateEvidence';

export default function SourceRecord({ id, revision, onBack, onCorrect, reviewer = false, allowWithdrawal = false, onWriteLockChange }: { id: string; revision: number; onBack: () => void; onCorrect?: (detail: SourceDetail) => void; reviewer?: boolean; allowWithdrawal?: boolean; onWriteLockChange?: (locked: boolean) => void }) {
  const [selectedRevision, setSelectedRevision] = useState(revision);
  const [generation, setGeneration] = useState(0);
  const [detail, setDetail] = useState<SourceDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [withdrawReason, setWithdrawReason] = useState('');
  const [withdrawal, setWithdrawal] = useState<WithdrawalOperation | null>(null);
  const [busy, setBusy] = useState(false), [uncertain, setUncertain] = useState(false), [withdrawn, setWithdrawn] = useState(false);
  const [withdrawError, setWithdrawError] = useState(''), [stale, setStale] = useState(false);
  const [evidenceLocked, setEvidenceLocked] = useState(false);
  const ownWriteLock = useRef(false), evidenceWriteLock = useRef(false);
  ownWriteLock.current = busy || uncertain;
  const lockEvidence = useCallback((next: boolean) => {
    evidenceWriteLock.current = next; setEvidenceLocked(next);
    onWriteLockChange?.(next || ownWriteLock.current);
  }, [onWriteLockChange]);
  const sending = useRef(false), alive = useRef(true);
  const locked = busy || uncertain || evidenceLocked;
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    onWriteLockChange?.(locked);
    const preventLeave = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    if (locked) window.addEventListener('beforeunload', preventLeave);
    return () => { window.removeEventListener('beforeunload', preventLeave); onWriteLockChange?.(false); };
  }, [locked, onWriteLockChange]);
  const withdraw = async () => {
    if (sending.current || stale || !allowWithdrawal || !withdrawal && !detail?.workflow?.is_current) return;
    if (!withdrawal && (!withdrawReason.trim() || [...withdrawReason.trim()].length > 500)) { setWithdrawError('Enter a private withdrawal reason of up to 500 characters.'); return; }
    const frozen = withdrawal ?? { operation_id: crypto.randomUUID(), expected_revision_no: detail!.receipt.revision_no, reason: withdrawReason.trim() };
    const recovering = uncertain; sending.current = true; onWriteLockChange?.(true); setWithdrawal(frozen); setBusy(true); setWithdrawError('');
    try {
      await api.withdraw(id, frozen);
      if (!alive.current) return;
      setUncertain(false); setWithdrawal(null); setWithdrawn(true); setGeneration(value => value + 1);
    } catch (failure) {
      if (!alive.current) return;
      const unresolved = recovering || failure instanceof ApiError && failure.uncertain;
      setUncertain(unresolved); setWithdrawError(errorMessage(failure));
      if (!unresolved) setWithdrawal(null);
      if (failure instanceof ApiError && failure.status === 409 && !unresolved) { setStale(true); setDetail(null); setError('This source changed. Refresh before withdrawing.'); }
      if (failure instanceof ApiError && [401, 403, 404].includes(failure.status) && !failure.code.toLowerCase().includes('csrf')) { setDetail(null); setError('This source is no longer available to your account.'); }
    } finally { sending.current = false; if (alive.current) setBusy(false); }
  };
  const heading = useRef<HTMLDivElement>(null);
  const evidenceRevision = detail && detail.report.id === id && detail.receipt.report_id === id &&
    detail.receipt.revision_no === selectedRevision && detail.workflow?.revision_no === selectedRevision &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(detail.receipt.revision_id) ? detail.receipt.revision_id : null;
  useEffect(() => {
    let active = true;
    setLoading(true); setDetail(null); setError(''); setStale(false);
    api.source(id, selectedRevision).then(response => { if (active) setDetail(response); }).catch(failure => { if (active) setError(errorMessage(failure)); }).finally(() => { if (active) { setLoading(false); heading.current?.focus(); } });
    return () => { active = false; };
  }, [id, selectedRevision, generation]);
  return <>
    <BackButton onClick={() => { if (!locked && !evidenceWriteLock.current) onBack(); }}>{reviewer ? 'Back to review queue' : 'Back to reports'}</BackButton>
    <div tabIndex={-1} ref={heading}><SectionHeading eyebrow="PRIVATE SOURCE" title={detail?.report.reference ?? 'Report details'} text="Each accepted revision keeps its own original, receipt and review history." action={<button className="button secondary" disabled={loading || locked} onClick={() => setGeneration(value => value + 1)}><Icon name="refresh" />Refresh</button>} /></div>
    {withdrawn && <Notice tone="success"><strong>Withdrawal committed.</strong> Previously viewed copies cannot be recalled.</Notice>}
    {withdrawError && <Notice tone={uncertain ? 'warning' : 'error'}>{withdrawError}{uncertain && <><p>Withdrawal result not yet confirmed. Retry the same operation before leaving.</p><button className="button primary" disabled={busy} onClick={() => void withdraw()}>Retry same withdrawal</button></>}</Notice>}
    {loading ? <Loading text="Loading authorized original…" /> : error ? <Notice tone="error">{error}</Notice> : detail && <>
      <div className="source-status-bar"><StatusBadge status={detail.report.status} /><span>Revision {selectedRevision} · Received {dateLabel(detail.history?.find(item => item.revision_no === selectedRevision)?.received_at ?? detail.report.created_at, true)}</span></div>
      {detail.correction_reason && <Notice><strong>Private correction reason:</strong> {detail.correction_reason}</Notice>}
      {detail.report.feedback && <Notice tone={detail.report.status === 'RETURNED' ? 'warning' : 'info'}><strong>Reviewer feedback:</strong> {detail.report.feedback}</Notice>}
      {detail.can_correct && onCorrect && <div className="correction-callout"><div><h3>Create a corrected revision</h3><p>Send a new revision of this report. The accepted original and feedback stay in its history, and the correction goes through processing and human review again.</p></div><button className="button primary" disabled={locked} onClick={() => onCorrect(detail)}>Correct this report<Icon name="arrow" /></button></div>}
      {detail.report.status === 'FAILED' && <Notice tone="warning">Processing did not complete. This source stays private. A failed job never publishes a report.</Notice>}
      {detail.workflow ? <WorkflowTimeline workflow={detail.workflow} /> : <Notice tone="warning">Current workflow progress could not be confirmed. Refresh to check processing, review and sharing.</Notice>}
      {reviewer && allowWithdrawal && detail.workflow?.is_current && !withdrawn && detail.workflow.sharing.state !== 'WITHDRAWN' && <section className="card withdrawal-card"><div className="card-heading"><span className="card-icon danger"><Icon name="alert" /></span><div><h3>Withdraw this report</h3><p>Stops future retrieval of this report's published representations. Previously viewed copies cannot be recalled. This does not delete the private original.</p></div></div><div className="card-body"><label className="field"><span>Private withdrawal reason <span className="required">*</span></span><textarea aria-label="Private withdrawal reason" rows={3} maxLength={500} disabled={locked || stale} value={withdrawReason} onChange={event => setWithdrawReason(event.target.value)} /><span className="field-hint">Up to 500 characters. This reason stays private.</span></label><div className="button-row"><button className="button danger-outline" disabled={locked || stale || !withdrawReason.trim()} onClick={() => void withdraw()}>Withdraw report</button></div></div></section>}
      <div className="detail-layout"><section className="card"><div className="card-heading"><span className="card-icon"><Icon name="lock" /></span><div><h3>Immutable original</h3><p>Exact source revision {selectedRevision}</p></div></div><SourceFields payload={detail.payload} /></section><section className="card"><div className="card-heading"><div><h3>Delivery receipt</h3><p>Recorded once at committed acceptance</p></div></div><dl className="receipt-fields"><div><dt>Delivery</dt><dd>Received by server</dd></div><div><dt>Source revision</dt><dd>{detail.receipt.revision_no}</dd></div><div><dt>Initial processing</dt><dd>Pending</dd></div><div><dt>Shared at acceptance</dt><dd>No</dd></div><div><dt>Operation reference</dt><dd className="mono">{detail.receipt.operation_id}</dd></div></dl></section></div>
      {evidenceRevision && <PrivateEvidence key={`${evidenceRevision}:${reviewer}:${detail.workflow?.is_current === true}`} revisionId={evidenceRevision} canUpload={!reviewer && detail.workflow?.is_current === true} onLockChange={lockEvidence} />}
      <section className="card revision-card"><div className="card-heading"><div><h3>Revision history</h3><p>Newest first. Each revision requires its own review.</p></div><span className="count-pill">{detail.history?.length ?? 1} revisions</span></div><ol className="revision-list">{(detail.history ?? [{ revision_no: selectedRevision, received_at: detail.report.created_at, status: detail.report.status }]).map(item => <li key={item.revision_no}><span className={'revision-number ' + (item.revision_no === selectedRevision ? 'selected' : '')}>{item.revision_no}</span><div><button className="text-button" disabled={locked || item.revision_no === selectedRevision} aria-current={item.revision_no === selectedRevision ? 'step' : undefined} onClick={() => setSelectedRevision(item.revision_no)}>Revision {item.revision_no}{item.revision_no === selectedRevision ? ' · viewing' : ''}</button><p>{dateLabel(item.received_at, true)}</p></div><StatusBadge status={item.status} /></li>)}</ol></section>
    </>}
  </>;
}
