import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError, errorMessage } from '../api';
import { BackButton, EmptyState, Loading, MetricCard, Modal, Notice, Pagination, ProjectionCard, ReportFilterBar, ReportTable, SectionHeading, SourceFields, StatusBadge } from '../components';
import { ageLabel, CATEGORY_LABELS, dateLabel, profileLabel } from '../domain';
import { Icon } from '../icons';
import type { DecisionOperation, DecisionResult, ReviewAction, ReviewDetail, User } from '../types';
import { useReportList } from '../useReportList';
import BatchReview from '../BatchReview';
import SourceRecord from '../SourceRecord';
import ReportActivity from '../ReportActivity.tsx';

interface Props { user: User; page: string; onNavigate: (page: string) => void; onWriteLockChange: (locked: boolean) => void; onSignOut: () => void }
export default function Reviewer({ user, page, onNavigate, onWriteLockChange, onSignOut }: Props) {
  const { data, activity, filters, setFilters, loading, error, refreshed, refresh } = useReportList(true);
  const queue = data.results;
  const [source, setSource] = useState<{ id: string; revision: number } | null>(null);
  const [batch, setBatch] = useState<{ id: string; revision: number } | null>(null);
  const openReport = (report: { id: string; revision_no: number; variant_id: string | null }) => {
    if (user.channels !== undefined) { setBatch({ id: report.id, revision: report.revision_no }); onNavigate('review'); }
    else if (report.variant_id) void open(report.variant_id);
  };
  const [variantId, setVariantId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ReviewDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [action, setAction] = useState<ReviewAction | null>(null);
  const [reason, setReason] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [decision, setDecision] = useState<DecisionOperation | null>(null);
  const [busy, setBusy] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const [stale, setStale] = useState(false);
  const [decisionError, setDecisionError] = useState('');
  const [result, setResult] = useState<DecisionResult | null>(null);
  const alive = useRef(true);
  const detailSequence = useRef(0);

  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const open = async (id: string) => {
    if (uncertain || busy) return;
    const sequence = ++detailSequence.current;
    setVariantId(id); setDetail(null); setDetailError(''); setDetailLoading(true); setStale(false); setResult(null); setDecisionError(''); setAction(null); setDecision(null); setReason(''); onNavigate('review');
    try { const response = await api.review(id); if (alive.current && sequence === detailSequence.current) setDetail(response); }
    catch (failure) { if (alive.current && sequence === detailSequence.current) setDetailError(errorMessage(failure)); }
    finally { if (alive.current && sequence === detailSequence.current) setDetailLoading(false); }
  };
  const closeModal = useCallback(() => { if (!busy && !uncertain) { setAction(null); setDecisionError(''); setConfirmed(false); } }, [busy, uncertain]);
  const choose = (next: ReviewAction) => { setAction(next); setReason(''); setConfirmed(false); setDecisionError(''); setDecision(null); };
  const decide = async () => {
    if (!detail || !variantId || !action || busy || stale) return;
    if (!decision && action !== 'APPROVE' && !reason.trim()) { setDecisionError('Enter a clear, private reason for this decision.'); return; }
    if (!decision && action === 'APPROVE' && !confirmed) { setDecisionError('Confirm that you have checked the exact candidate and audience.'); return; }
    const frozen = decision ?? { operation_id: crypto.randomUUID(), action, expected: { ...detail.binding, channel_ids: [...detail.binding.channel_ids] }, reason: reason.trim() };
    const recovering = uncertain && decision !== null;
    setDecision(frozen); setBusy(true); setDecisionError('');
    try {
      const response = await api.decide(variantId, frozen);
      if (!alive.current) return;
      setResult(response); setUncertain(false); setAction(null); setDecision(null); void refresh();
    } catch (failure) {
      if (!alive.current) return;
      setDecisionError(errorMessage(failure));
      // Once a decision may have committed, another failure cannot authorize a new key,
      // action or binding. Only replay confirmation resolves this in-memory operation.
      const unresolved = recovering || failure instanceof ApiError && failure.uncertain;
      setUncertain(unresolved);
      if (!unresolved) setDecision(null);
      if (failure instanceof ApiError && failure.status === 409 && !unresolved) { setStale(true); setAction(null); setDetailError('This review is no longer current. Reload before making any decision.'); }
      const csrfFailure = failure instanceof ApiError && failure.code.toLowerCase().includes('csrf');
      if (failure instanceof ApiError && [401, 403, 404].includes(failure.status) && !csrfFailure) { setDetail(null); setAction(null); setDetailError('This review is no longer available to your account.'); }
    } finally { if (alive.current) setBusy(false); }
  };
  const audience = detail?.binding.channel_ids.map(id => user.channel?.id === id ? `${user.channel.name} (${user.channel.code})` : `Sharing channel · ${id}`) ?? [];
  const leaveDetail = () => { if (busy || uncertain) return; detailSequence.current++; setVariantId(null); setDetail(null); setResult(null); };

  if (page === 'review' && source) return <SourceRecord key={`${source.id}-${source.revision}`} id={source.id} revision={source.revision} onBack={() => { setSource(null); leaveDetail(); }} reviewer onWriteLockChange={onWriteLockChange} allowWithdrawal={user.channels !== undefined} />;

  if (page === 'review' && batch) return <BatchReview onSignOut={onSignOut} key={`${batch.id}-${batch.revision}`} {...batch} user={user} onWriteLockChange={onWriteLockChange} onBack={() => setBatch(null)} onSource={() => setSource(batch)} onCommitted={() => void refresh()} />;

  if (page === 'review' && variantId) return <>
    <BackButton onClick={leaveDetail}>Back to review queue</BackButton>
    <SectionHeading eyebrow="ORIGINATING UNIT REVIEW" title={detail?.report.reference ?? 'Review report'} text="Read the complete original and reduced candidate before deciding. No content is shared without your explicit approval." action={<button className="button secondary" disabled={detailLoading || busy || uncertain} onClick={() => void open(variantId)}><Icon name="refresh" />Reload review</button>} />
    {detailLoading ? <Loading text="Loading authorized review and exact binding…" /> : <>
      {detailError && <Notice tone={stale ? 'warning' : 'error'}>{detailError}</Notice>}
      {result && <Notice tone="success"><strong>{result.action === 'APPROVE' ? 'Approval committed.' : result.action === 'RETURN' ? 'Report returned for correction.' : 'Report rejected.'}</strong> {result.action === 'APPROVE' ? 'The exact reduced candidate is now published to the confirmed audience.' : 'Your private feedback was recorded. No publication was created.'}<div className="notice-buttons"><button className="text-button" onClick={leaveDetail}>Return to queue<Icon name="arrow" size={16} /></button></div></Notice>}
      {detail && <>
        <div className="review-context"><StatusBadge status={result ? result.report_status : detail.report.status} /><span><Icon name="lock" size={15} />Private review workspace</span><span>Origin: {user.unit?.code ?? 'Assigned source unit'}</span></div>
        <button className="text-button history-link" disabled={busy || uncertain} onClick={() => setSource({ id: detail.report.id, revision: detail.binding.revision_no })}>View revision history<Icon name="arrow" size={16} /></button>
        <div className="comparison-grid"><section className="card original-panel"><div className="card-heading"><span className="card-icon"><Icon name="lock" /></span><div><h3>Original report</h3><p>Private · source revision {detail.binding.revision_no}</p></div><span className="panel-label">BEFORE</span></div><SourceFields payload={detail.source} /></section><section className="card candidate-panel"><div className="card-heading"><span className="card-icon"><Icon name="shield" /></span><div><h3>Reduced candidate</h3><p>{result?.action === 'APPROVE' ? 'Approved for the confirmed channel' : 'Awaiting your decision · not shared'}</p></div><span className="panel-label teal">AFTER</span></div><ProjectionCard projection={detail.candidate} candidate={!result || result.action !== 'APPROVE'} /><div className="candidate-footnote"><Icon name="eye" size={17} />This is the entire representation the recipient will see.</div></section></div>
        {detail.warnings.length > 0 && <Notice tone="warning"><strong>Review notes</strong><ul className="warning-list">{detail.warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul></Notice>}
        <section className="card binding-card"><div className="binding-summary"><div><h3>Exact approval context</h3><p>Any source, content, policy or audience change invalidates this review.</p></div><div className="context-pills"><span>{detail.binding.profile}</span><span>{detail.binding.policy_version}</span><span>Revision {detail.binding.revision_no}</span></div></div><dl className="binding-fields"><div><dt>Sharing audience</dt><dd>{audience.join(', ')}</dd></div><div><dt>Source revision ID</dt><dd className="mono">{detail.binding.revision_id}</dd></div><div><dt>Candidate SHA-256</dt><dd className="mono">{detail.binding.candidate_hash}</dd></div><div><dt>Policy SHA-256</dt><dd className="mono">{detail.binding.policy_hash}</dd></div></dl></section>
        {!result && <div className="review-actions"><p><Icon name="shield" size={18} />You are making a human review decision for this exact candidate.</p><div className="button-row"><button className="button danger-outline" onClick={() => choose('REJECT')} disabled={stale || busy || uncertain}>Reject</button><button className="button secondary" onClick={() => choose('RETURN')} disabled={stale || busy || uncertain}>Return for correction</button><button className="button primary" onClick={() => choose('APPROVE')} disabled={stale || busy || uncertain}>Review & approve<Icon name="check" /></button></div></div>}
      </>}
    </>}
    {action && detail && <Modal title={action === 'APPROVE' ? 'Confirm approval & sharing' : action === 'RETURN' ? 'Return for correction' : 'Reject this report'} onClose={closeModal} locked={busy || uncertain}>
      {action === 'APPROVE' ? <><p className="modal-intro">Approving publishes the exact reduced content below to the confirmed audience. The private original is never included.</p><div className="confirmation-projection"><ProjectionCard projection={detail.candidate} candidate /></div><div className="confirmation-audience"><Icon name="feed" /><div><strong>Confirmed sharing audience</strong><p>{audience.join(', ')}</p><span>{detail.binding.profile} · {detail.binding.policy_version} · Revision {detail.binding.revision_no}</span></div></div><label className="checkbox-field"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={busy || uncertain} /><span>I have checked the complete candidate, source revision, policy and sharing audience.</span></label></> : <><p className="modal-intro">{action === 'RETURN' ? 'Give the submitter clear corrections for the next revision of this report. All accepted originals remain unchanged.' : 'Record why this report should not proceed to sharing.'} This feedback stays private.</p><label className="field" htmlFor="decision-reason"><span>Private reason <span className="required">*</span></span><textarea id="decision-reason" rows={4} value={reason} onChange={event => setReason(event.target.value)} maxLength={500} disabled={busy || uncertain} placeholder={action === 'RETURN' ? 'Explain what needs to be corrected…' : 'Explain why the report is rejected…'} /><span className="field-hint">Up to 500 characters.</span></label></>}
      {decisionError && <Notice tone={uncertain ? 'warning' : 'error'}>{uncertain && <strong>Decision result not yet confirmed. </strong>}{decisionError}{uncertain && <p>Retry confirms the same action, content and operation reference. Do not make a different decision until this result is confirmed.</p>}</Notice>}
      <div className="modal-footer"><button className="button secondary" onClick={closeModal} disabled={busy || uncertain}>Cancel</button><button className={'button ' + (action === 'REJECT' ? 'danger' : 'primary')} disabled={busy || (!uncertain && (action === 'APPROVE' ? !confirmed : !reason.trim()))} onClick={() => void decide()}>{busy ? 'Committing decision…' : uncertain ? 'Retry same decision' : action === 'APPROVE' ? 'Approve & share' : action === 'RETURN' ? 'Return report' : 'Reject report'}<Icon name={uncertain ? 'refresh' : action === 'APPROVE' ? 'check' : 'arrow'} /></button></div>
    </Modal>}
  </>;

  const waiting = queue.filter(report => report.status === 'AWAITING_REVIEW' && report.variant_id);
  // Priority first, then the longest-waiting candidate on the loaded page.
  const next = [...waiting].sort((a, b) => a.urgency === b.urgency ? a.created_at.localeCompare(b.created_at) : a.urgency === 'PRIORITY' ? -1 : 1)[0];
  const oldest = waiting.reduce<string | null>((earliest, report) => !earliest || report.created_at < earliest ? report.created_at : earliest, null);
  const priority = queue.filter(report => report.urgency === 'PRIORITY').length;
  return <>
    <SectionHeading hero={page === 'overview'} eyebrow={page === 'overview' ? 'REVIEW WORKSPACE' : 'HUMAN REVIEW'} title={page === 'overview' ? `Welcome, ${user.display_name}.` : 'Review queue'} text="Compare private originals with reduced candidates and decide what may be shared." meta={page === 'overview' ? <><span><Icon name="shield" size={14} />{user.unit?.code ?? 'Assigned source unit'}</span><span>{user.channel?.code ?? 'Eligible channel'}</span><span>{profileLabel(user.profile)} disclosure</span></> : undefined} action={<button className="button secondary" onClick={() => void refresh()} disabled={loading}><Icon name="refresh" />Refresh queue</button>} />
    <ReportActivity activity={activity} filters={filters} loading={loading} error={error} onApply={setFilters} />
    {page === 'overview' && <>
      <div className="metrics-grid review-metrics"><MetricCard label={filters.status === 'AWAITING_REVIEW' ? 'Awaiting review' : 'Matching reports'} value={data.count} detail="Within your assigned source unit" icon="review" tone="amber" /><MetricCard label="Priority reports" value={priority} detail={`Of ${queue.length} shown on this page`} icon="alert" tone="blue" share={{ value: priority, of: queue.length, label: `${priority} of ${queue.length} reports on this page are priority` }} /><MetricCard label="Longest waiting" value={oldest ? ageLabel(oldest) : '—'} detail="Oldest candidate on this page" icon="clock" /><div className="review-principle"><Icon name="shield" size={28} /><div><strong>Human judgment, every time.</strong><p>Rules prepare a candidate. You approve the exact content and audience.</p></div></div></div>
      <div className="dashboard-grid">
        <section className="card" aria-labelledby="up-next-title"><div className="card-heading"><span className="card-icon"><Icon name="review" /></span><div><h3 id="up-next-title">Up next</h3><p>Priority first, then the longest waiting on this page</p></div></div>
          {loading && !queue.length ? <Loading text="Checking your review queue…" /> : next ? <div className="up-next"><div className="up-next-top"><span className="up-next-ref">{next.reference}</span><StatusBadge status={next.status} /><span className={'urgency-label ' + (next.urgency === 'PRIORITY' ? 'priority' : '')}>{next.urgency === 'PRIORITY' ? 'Priority' : 'Routine'}</span></div><dl><div><dt>Category</dt><dd>{CATEGORY_LABELS[next.category]}</dd></div><div><dt>Area</dt><dd>{next.area_label}</dd></div><div><dt>Received</dt><dd>{dateLabel(next.created_at)}</dd></div><div><dt>Waiting</dt><dd>{ageLabel(next.created_at)}</dd></div></dl><div className="up-next-actions"><p><Icon name="lock" size={15} />Opens the private original beside its reduced candidate.</p><button className="button primary" onClick={() => openReport(next)} disabled={busy || uncertain} aria-label={`Start review of ${next.reference}`}>Start review<Icon name="arrow" /></button></div></div> : <div className="attention-clear"><Icon name="check" /><div><strong>Nothing waiting on this page</strong><p>New candidates appear here after processing completes.</p></div></div>}
        </section>
        <section className="card" aria-labelledby="checklist-title"><div className="card-heading"><span className="card-icon"><Icon name="shield" /></span><div><h3 id="checklist-title">Before you decide</h3><p>A short checklist for every review</p></div></div><ol className="guide-steps">
          <li><span><Icon name="eye" size={17} /></span><div><strong>Read the whole original</strong><p>Every field, including the private description.</p></div></li>
          <li><span><Icon name="lock" size={17} /></span><div><strong>Check what is withheld</strong><p>Names, site and narrative must stay out of the candidate.</p></div></li>
          <li><span><Icon name="feed" size={17} /></span><div><strong>Confirm the audience</strong><p>Approval covers this exact revision, policy and channel.</p></div></li>
          <li><span><Icon name="review" size={17} /></span><div><strong>Decide explicitly</strong><p>Approve, return with clear feedback, or reject.</p></div></li>
        </ol></section>
      </div>
    </>}
    <section className="card reports-card"><div className="card-heading"><div><h3>{filters.status === 'AWAITING_REVIEW' ? 'Candidates awaiting your review' : 'Report history in your unit'}</h3><p>{refreshed ? `Last refreshed ${dateLabel(refreshed, true)}` : 'Only the assigned originating unit’s queue'}</p></div><span className="count-pill">{data.count} matching</span></div><ReportFilterBar filters={filters} onApply={setFilters} busy={loading} />{error && <Notice tone="error">{error}</Notice>}{loading ? <Loading rows={5} text="Loading your assigned review queue…" /> : queue.length ? <ReportTable reports={queue} onOpen={report => { if (report.status === 'AWAITING_REVIEW' && report.variant_id) openReport(report); else { setSource({ id: report.id, revision: report.revision_no }); onNavigate('review'); } }} reviewer /> : <EmptyState icon="review" title={filters.status === 'AWAITING_REVIEW' ? "Your review queue is clear" : "No matching reports"} text="Adjust your filters to find reports. A candidate becomes available for review after processing completes." />}{!error && <Pagination data={data} busy={loading} onPage={page => setFilters({ ...filters, page })} onPageSize={page_size => setFilters({ ...filters, page_size, page: 1 })} />}</section>
  </>;
}
