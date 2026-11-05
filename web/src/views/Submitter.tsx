import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { api, ApiError, errorMessage } from '../api';
import { EmptyState, Loading, MetricCard, Notice, Pagination, ReportFilterBar, ReportTable, SectionHeading, StatusBadge } from '../components';
import { AREAS, ASSISTANCE, CATEGORY_LABELS, createOperation, dateLabel, localDateTime, profileLabel, validateCorrectionReason, validatePayload } from '../domain';
import { Icon } from '../icons';
import type { Operation, Payload, Receipt, SourceDetail, User } from '../types';
import SourceRecord from '../SourceRecord';
import { useReportList } from '../useReportList';
import ReportActivity from '../ReportActivity.tsx';

interface Props { user: User; page: string; onNavigate: (page: string) => void; onWriteLockChange?: (locked: boolean) => void }
interface Draft extends Omit<Payload, 'observed_at'> { observed_at: string }
const initialDraft = (): Draft => ({ observed_at: localDateTime(), category: 'INFRASTRUCTURE', urgency: 'ROUTINE', area_label: 'Area C', site_label: '', reporter_label: '', narrative: '', assistance_requested: 'Repair assistance' });

export default function Submitter({ user, page, onNavigate, onWriteLockChange }: Props) {
  const { data, activity, filters, setFilters, loading, error, refreshed, refresh } = useReportList();
  const reports = data.results;
  const [selected, setSelected] = useState<{ id: string; revision: number } | null>(null);
  const [correction, setCorrection] = useState<{ report_id: string; expected_revision: number; reference: string; feedback: string | null } | null>(null);
  const [draft, setDraft] = useState<Draft>(initialDraft);
  const [correctionReason, setCorrectionReason] = useState('');
  const [operation, setOperation] = useState<Operation | null>(null);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [uncertain, setUncertain] = useState(false);
  const [staleCorrection, setStaleCorrection] = useState(false);
  const alive = useRef(true);
  const submitInFlight = useRef(false);
  const errorSummary = useRef<HTMLDivElement>(null);

  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => { if (Object.keys(fieldErrors).length || formError) errorSummary.current?.focus(); }, [fieldErrors, formError]);

  const open = (id: string, revision: number) => { setSelected({ id, revision }); onNavigate('reports'); };
  const startCorrection = (detail: SourceDetail) => {
    if (uncertain || submitInFlight.current) { onNavigate('new'); return; }
    setDraft({ ...detail.payload, observed_at: localDateTime(new Date(detail.payload.observed_at)) });
    setCorrectionReason('');
    setCorrection({ report_id: detail.report.id, expected_revision: detail.report.revision_no, reference: detail.report.reference, feedback: detail.report.feedback });
    setReceipt(null); setOperation(null); setFormError(''); setFieldErrors({}); setStaleCorrection(false); onNavigate('new');
  };
  const submit = async (event?: FormEvent, retry = false) => {
    event?.preventDefault();
    if (submitInFlight.current || staleCorrection || uncertain && !retry) return;
    const recovering = retry && uncertain && operation !== null;
    let frozen = operation;
    if (!retry || !frozen) {
      const observed = new Date(draft.observed_at);
      const payload: Payload = { ...draft, observed_at: Number.isFinite(observed.getTime()) ? observed.toISOString() : draft.observed_at };
      const validation = validatePayload(payload);
      if (correction) {
        const issue = validateCorrectionReason(correctionReason);
        if (issue) validation.correction_reason = issue;
      }
      setFieldErrors(validation);
      if (Object.keys(validation).length) return;
      frozen = createOperation(payload, correction ? { ...correction, correction_reason: correctionReason } : undefined); setOperation(frozen);
    }
    submitInFlight.current = true; setSubmitting(true); setFormError('');
    try {
      const accepted = await api.submit(frozen);
      if (!alive.current) return;
      setReceipt(accepted); setUncertain(false); void refresh();
    } catch (failure) {
      if (!alive.current) return;
      setFormError(errorMessage(failure));
      // A later rejection does not resolve an earlier request that may have committed.
      // Preserve its identity/body until an authoritative receipt confirms the result.
      const unresolved = recovering || failure instanceof ApiError && failure.uncertain;
      setUncertain(unresolved);
      if (!unresolved && correction && failure instanceof ApiError && failure.status === 409) {
        setStaleCorrection(true);
        setFormError('This source revision has changed. Reload the report history and review the current revision before making another correction.');
      }
      if (!unresolved) { setOperation(null); if (failure instanceof ApiError) setFieldErrors(failure.fields); }
    } finally { submitInFlight.current = false; if (alive.current) setSubmitting(false); }
  };
  const checkReceipt = async () => {
    if (!operation || submitInFlight.current) return;
    submitInFlight.current = true; setSubmitting(true); setFormError('');
    try { const accepted = await api.receipt(operation.operation_id); if (alive.current) { setReceipt(accepted); setUncertain(false); void refresh(); } }
    catch (failure) { if (alive.current) setFormError(failure instanceof ApiError && failure.status === 404 ? 'A committed receipt is not available yet. Retry the same submission to confirm acceptance.' : errorMessage(failure)); }
    finally { submitInFlight.current = false; if (alive.current) setSubmitting(false); }
  };
  const reset = () => { if (uncertain || submitInFlight.current) return; setDraft(initialDraft()); setCorrectionReason(''); setCorrection(null); setReceipt(null); setOperation(null); setUncertain(false); setStaleCorrection(false); setFormError(''); setFieldErrors({}); };
  const field = (name: keyof Draft) => ({ value: draft[name], onChange: (event: { target: { value: string } }) => setDraft(current => ({ ...current, [name]: event.target.value })), 'aria-invalid': !!fieldErrors[name], 'aria-describedby': fieldErrors[name] ? `${name}-error` : undefined });
  const fieldError = (name: string) => fieldErrors[name] ? <span className="field-error" id={`${name}-error`}>{fieldErrors[name]}</span> : null;
  const awaiting = reports.filter(report => ['PENDING', 'PROCESSING', 'AWAITING_REVIEW'].includes(report.status)).length;
  const approved = reports.filter(report => report.status === 'APPROVED').length;
  const needsAttention = reports.filter(report => ['RETURNED', 'REJECTED', 'FAILED'].includes(report.status)).length;

  if (page === 'new') return <>
    <SectionHeading eyebrow={correction ? 'REPORT CORRECTION' : 'REPORT ENTRY'} title={correction ? `Correction for ${correction.reference}` : 'Make a maintenance report'} text={correction ? `Create revision ${correction.expected_revision + 1}. Your accepted originals remain intact; a separate reviewer will review this correction.` : 'Describe the maintenance issue. Your original stays private until a separate reviewer decides what can be shared.'} />
    {correction?.feedback && !receipt && <Notice tone="warning"><strong>Requested correction:</strong> {correction.feedback}</Notice>}
    {staleCorrection && correction && <Notice tone="warning" action={<button className="button secondary" onClick={() => open(correction.report_id, correction.expected_revision)}>Reload report history<Icon name="refresh" /></button>}>This correction is out of date. Its fields and submission are locked.</Notice>}
    {receipt ? <div className="receipt-layout"><section className="card receipt-card"><span className="receipt-icon"><Icon name="check" size={28} /></span><p className="eyebrow">SERVER RECEIPT CONFIRMED</p><h3>Your report was received.</h3><p>The server committed your submission. Processing and human review happen next; this receipt does not mean your report has been shared.</p><dl className="receipt-fields"><div><dt>Delivery</dt><dd><span className="status-badge status-approved">Received by server</span></dd></div><div><dt>At acceptance</dt><dd>Awaiting processing</dd></div><div><dt>Source revision</dt><dd>{receipt.revision_no}</dd></div><div><dt>Operation reference</dt><dd className="mono">{receipt.operation_id}</dd></div></dl><div className="button-row"><button className="button primary" onClick={() => void open(receipt.report_id, receipt.revision_no)}>View current report status<Icon name="arrow" /></button><button className="button secondary" onClick={reset}>Make another report</button></div></section><ProcessAside received /></div> : <div className="form-layout"><form className="card report-form" onSubmit={event => void submit(event)} noValidate>
      <div className="card-heading"><span className="card-icon"><Icon name="report" /></span><div><h3>Report details</h3><p>Maintenance report · {user.unit?.code}</p></div><span className="private-label"><Icon name="lock" size={14} />Private original</span></div>
      {(formError || Object.keys(fieldErrors).length > 0) && <div tabIndex={-1} ref={errorSummary}>{formError && <Notice tone={uncertain ? 'warning' : 'error'}>{uncertain ? <><strong>Receipt not yet confirmed.</strong> {formError} The exact request is held in memory; retrying uses the same operation reference.</> : formError}</Notice>}{Object.keys(fieldErrors).length > 0 && <Notice tone="error">Check the highlighted fields before submitting.</Notice>}</div>}
      <fieldset disabled={submitting || uncertain || staleCorrection}><legend className="sr-only">Report details</legend><div className="form-grid">
        <label className="field" htmlFor="reporter_label"><span>Reporter label <span className="required">*</span></span><input id="reporter_label" placeholder="e.g. Team lead, Unit 2" maxLength={100} autoComplete="off" {...field('reporter_label')} />{fieldError('reporter_label')}</label>
        <label className="field" htmlFor="site_label"><span>Site label <span className="required">*</span></span><input id="site_label" placeholder="e.g. Pump station 3" maxLength={100} autoComplete="off" {...field('site_label')} />{fieldError('site_label')}</label>
        <label className="field" htmlFor="category"><span id="category-label">Category</span><select id="category" aria-labelledby="category-label" {...field('category')}>{Object.entries(CATEGORY_LABELS).map(([key, label]) => <option value={key} key={key}>{label}</option>)}</select>{fieldError('category')}</label>
        <label className="field" htmlFor="urgency"><span id="urgency-label">Urgency</span><select id="urgency" aria-labelledby="urgency-label" {...field('urgency')}><option value="ROUTINE">Routine</option><option value="PRIORITY">Priority</option></select>{fieldError('urgency')}</label>
        <label className="field" htmlFor="area_label"><span id="area_label-label">Area</span><select id="area_label" aria-labelledby="area_label-label" {...field('area_label')}>{AREAS.map(area => <option key={area}>{area}</option>)}</select>{fieldError('area_label')}</label>
        <label className="field" htmlFor="observed_at"><span>Observed date & time <span className="required">*</span></span><input id="observed_at" type="datetime-local" {...field('observed_at')} /><span className="field-hint">Your browser’s local time zone.</span>{fieldError('observed_at')}</label>
        <label className="field full" htmlFor="assistance_requested"><span>Assistance needed</span><select id="assistance_requested" {...field('assistance_requested')}>{ASSISTANCE.map(value => <option key={value}>{value}</option>)}</select>{fieldError('assistance_requested')}</label>
        <label className="field full" htmlFor="narrative"><span>Describe the issue <span className="required">*</span></span><textarea id="narrative" rows={5} placeholder="Describe the damage and the assistance needed. Use no real names or operational information." maxLength={2000} {...field('narrative')} /><span className="field-hint narrative-count">Private description<span>{draft.narrative.length} / 2,000</span></span>{fieldError('narrative')}</label>
        {correction && <label className="field full" htmlFor="correction_reason"><span>Private correction reason <span className="required">*</span></span><textarea id="correction_reason" rows={3} required maxLength={500} value={correctionReason} onChange={event => setCorrectionReason(event.target.value)} aria-invalid={!!fieldErrors.correction_reason} aria-describedby={fieldErrors.correction_reason ? 'correction_reason-hint correction_reason-error' : 'correction_reason-hint'} /><span className="field-hint" id="correction_reason-hint">Explain what changed for the originating reviewer. This reason is private and stays with this source revision.</span>{fieldError('correction_reason')}</label>}
      </div></fieldset>
      <div className="form-footer"><p><Icon name="lock" size={15} />Draft and pending requests live only in this tab. Reloading or signing out clears them.</p>{uncertain ? <div className="button-row"><button className="button secondary" type="button" disabled={submitting} onClick={() => void checkReceipt()}>Check server receipt</button><button className="button primary" type="button" disabled={submitting} onClick={() => void submit(undefined, true)}>{submitting ? 'Confirming…' : 'Retry same submission'}<Icon name="refresh" /></button></div> : <button className="button primary" type="submit" disabled={submitting || staleCorrection}>{submitting ? 'Sending report…' : correction ? 'Submit correction' : 'Submit report'}<Icon name="arrow" /></button>}</div>
    </form><ProcessAside /></div>}
  </>;

  if (page === 'reports' && selected) return <SourceRecord key={`${selected.id}-${selected.revision}`} id={selected.id} revision={selected.revision} onBack={() => setSelected(null)} onCorrect={startCorrection} onWriteLockChange={onWriteLockChange} />;

  const shown = reports.length;
  const attention = reports.filter(report => ['RETURNED', 'REJECTED', 'FAILED'].includes(report.status));
  const share = (value: number, label: string) => ({ value, of: shown, label: `${value} of ${shown} reports on this page ${label}` });
  return <>
    <SectionHeading hero={page === 'overview'} eyebrow={page === 'overview' ? 'YOUR WORKSPACE' : 'SOURCE REPORTS'} title={page === 'overview' ? `Welcome, ${user.display_name}.` : 'Your reports'} text={page === 'overview' ? 'A clear path from private report to reviewed, approved information.' : 'Track server acceptance, processing and the reviewer’s decision.'} meta={page === 'overview' ? <><span><Icon name="shield" size={14} />{user.unit?.code ?? 'Assigned source unit'}</span><span>{profileLabel(user.profile)} disclosure</span><span>Maintenance report</span></> : undefined} action={<button className="button primary" onClick={() => onNavigate('new')}><Icon name="plus" />New report</button>} />
    <ReportActivity activity={activity} filters={filters} loading={loading} error={error} onApply={setFilters} />
    {page === 'overview' && <>
      <div className="metrics-grid"><MetricCard label="Your reports" value={data.count} detail="All reports matching the current filters" icon="report" /><MetricCard label="In progress" value={awaiting} detail={`Of ${shown} shown on this page`} icon="clock" tone="blue" share={share(awaiting, 'in progress')} /><MetricCard label="Approved" value={approved} detail={`Of ${shown} shown on this page`} icon="check" share={share(approved, 'approved')} /><MetricCard label="Needs attention" value={needsAttention} detail={`Of ${shown} shown on this page`} icon="alert" tone="amber" share={share(needsAttention, 'needing attention')} /></div>
      <div className="dashboard-grid">
        <section className="card" aria-labelledby="attention-title"><div className="card-heading"><span className="card-icon"><Icon name="alert" /></span><div><h3 id="attention-title">Needs your attention</h3><p>Returned, rejected or failed reports on this page</p></div><span className="count-pill">{attention.length}</span></div>
          {loading && !shown ? <Loading text="Checking your reports…" /> : attention.length ? <ul className="attention-list">{attention.slice(0, 4).map(report => <li key={report.id}><div><div className="attention-ref"><strong>{report.reference}</strong><StatusBadge status={report.status} /></div><p>{report.status === 'RETURNED' ? report.feedback ? `Reviewer feedback: ${report.feedback}` : 'Returned for correction. Open the report to see what to change.' : report.status === 'FAILED' ? 'Processing did not complete. The report stays private.' : 'The reviewer rejected this report. It will not be shared.'}</p></div><button className="button secondary small" onClick={() => open(report.id, report.revision_no)} aria-label={`View ${report.reference}`}>View<Icon name="arrow" size={15} /></button></li>)}</ul> : <div className="attention-clear"><Icon name="check" /><div><strong>All clear</strong><p>No returned, rejected or failed reports on this page.</p></div></div>}
        </section>
        <section className="card" aria-labelledby="guide-title"><div className="card-heading"><span className="card-icon"><Icon name="shield" /></span><div><h3 id="guide-title">How your report moves</h3><p>Your original stays private throughout</p></div></div><ol className="guide-steps">
          <li><span><Icon name="report" size={17} /></span><div><strong>Submit privately</strong><p>The server confirms receipt. Your original never changes.</p></div></li>
          <li><span><Icon name="cpu" size={17} /></span><div><strong>Reduced candidate</strong><p>Processing prepares a version without names, site or narrative.</p></div></li>
          <li><span><Icon name="review" size={17} /></span><div><strong>Human review</strong><p>A separate reviewer approves, returns or rejects it.</p></div></li>
          <li><span><Icon name="feed" size={17} /></span><div><strong>Shared once approved</strong><p>Only the approved version reaches the sharing channel.</p></div></li>
        </ol></section>
      </div>
    </>}
    <section className="card reports-card"><div className="card-heading"><div><h3>{page === 'overview' ? 'Recent reports' : 'Report history'}</h3><p>{refreshed ? `Last refreshed ${dateLabel(refreshed, true)}` : 'Only reports submitted by your account'}</p></div><button className="button secondary small" onClick={() => void refresh()} disabled={loading}><Icon name="refresh" size={16} />Refresh</button></div><ReportFilterBar filters={filters} onApply={setFilters} busy={loading} />{error && <Notice tone="error">{error}</Notice>}{loading ? <Loading rows={5} /> : reports.length ? <ReportTable reports={reports} onOpen={report => open(report.id, report.revision_no)} /> : <EmptyState title={filters.status !== 'ALL' || filters.date_from || filters.date_to || filters.page > 1 ? "No matching reports" : "No reports yet"} text="Adjust your filters or submit a maintenance issue to begin the workflow." action={<button className="button primary" onClick={() => onNavigate('new')}>Make a report<Icon name="arrow" /></button>} />}{!error && <Pagination data={data} busy={loading} onPage={page => setFilters({ ...filters, page })} onPageSize={page_size => setFilters({ ...filters, page_size, page: 1 })} />}</section>
  </>;
}

function ProcessAside({ received = false }: { received?: boolean }) {
  return <aside className="process-aside"><div className="aside-header"><Icon name="shield" size={23} /><h3>What happens next?</h3></div><ol className="process-steps"><li className={received ? 'complete' : 'active'}><span>{received ? <Icon name="check" size={15} /> : '1'}</span><div><h4>Receive your report</h4><p>The server accepts the original and provides a delivery receipt.</p></div></li><li><span>2</span><div><h4>Prepare a reduced candidate</h4><p>Reviewed rules use category, area and assistance. Private names and narrative stay out.</p></div></li><li><span>3</span><div><h4>Human review</h4><p>A separate reviewer checks the exact original, candidate and sharing audience.</p></div></li><li><span>4</span><div><h4>Share after approval</h4><p>Only the approved reduced content reaches the sharing channel.</p></div></li></ol><div className="aside-note"><Icon name="lock" size={17} /><p>Training and evaluation use only. Do not enter personal or sensitive information.</p></div></aside>;
}
