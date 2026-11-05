import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { CATEGORY_LABELS, dateLabel, profileLabel, STATUS_LABELS, validateReportFilters } from './domain';
import { Icon } from './icons';
import type { IconName } from './icons';
import type { PageResult, Payload, Projection, ReportFilters, ReportStatus, SourceSummary } from './types';

export function StatusBadge({ status }: { status: ReportStatus }) {
  return <span className={'status-badge status-' + status.toLowerCase()}><span className="status-dot" />{STATUS_LABELS[status]}</span>;
}
export function Notice({ children, tone = 'info', action }: { children: ReactNode; tone?: 'info' | 'error' | 'success' | 'warning'; action?: ReactNode }) {
  return <div className={'notice notice-' + tone} role={tone === 'error' ? 'alert' : 'status'}><Icon name={tone === 'success' ? 'check' : tone === 'error' || tone === 'warning' ? 'alert' : 'shield'} /><div>{children}</div>{action}</div>;
}
export function EmptyState({ title, text, action, icon = 'report' }: { title: string; text: string; action?: ReactNode; icon?: 'report' | 'review' | 'feed' | 'lock' }) {
  return <div className="empty-state"><span className="empty-icon"><Icon name={icon} size={30} /></span><h3>{title}</h3><p>{text}</p>{action}</div>;
}
export function Loading({ text = 'Loading your workspace…', rows = 0 }: { text?: string; rows?: number }) {
  if (!rows) return <div className="loading-state" role="status"><span className="spinner" />{text}</div>;
  // Skeleton rows reserve the list's space so content does not jump when results arrive.
  return <div className="loading-state is-skeleton" role="status"><span className="loading-label"><span className="spinner" />{text}</span>
    <span className="skeleton-rows" aria-hidden="true">{Array.from({ length: rows }, (_, index) => <span className="skeleton-row" key={index}><span /><span /><span /></span>)}</span></div>;
}
export function SectionHeading({ eyebrow, title, text, action, meta, hero = false }: { eyebrow?: string; title: string; text?: string; action?: ReactNode; meta?: ReactNode; hero?: boolean }) {
  return <div className={'section-heading' + (hero ? ' is-hero' : '')}><div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h2>{title}</h2>{text && <p>{text}</p>}{meta && <div className="section-meta">{meta}</div>}</div>{action}</div>;
}
export function BackButton({ onClick, children = 'Back to reports' }: { onClick: () => void; children?: ReactNode }) {
  return <button className="text-button back-button" onClick={onClick}><Icon name="arrow" />{children}</button>;
}
export function SourceFields({ payload }: { payload: Payload }) {
  return <dl className="detail-fields">
    <div><dt>Reporter</dt><dd>{payload.reporter_label}</dd></div><div><dt>Site</dt><dd>{payload.site_label}</dd></div>
    <div><dt>Observed</dt><dd>{dateLabel(payload.observed_at, true)}</dd></div><div><dt>Category</dt><dd>{CATEGORY_LABELS[payload.category]}</dd></div>
    <div><dt>Urgency</dt><dd>{payload.urgency === 'PRIORITY' ? 'Priority' : 'Routine'}</dd></div><div><dt>Area</dt><dd>{payload.area_label}</dd></div>
    <div><dt>Assistance requested</dt><dd>{payload.assistance_requested}</dd></div><div className="full"><dt>Original description</dt><dd className="narrative">{payload.narrative}</dd></div>
  </dl>;
}
export function ProjectionCard({ projection, candidate = false }: { projection: Projection; candidate?: boolean }) {
  return <div className="projection-content"><div className="projection-meta"><span className="category-pill">{CATEGORY_LABELS[projection.category]}</span><span className={'urgency-label ' + (projection.urgency === 'PRIORITY' ? 'priority' : '')}>{projection.urgency === 'PRIORITY' ? 'Priority' : 'Routine'}</span></div>
    <h3>{projection.title}</h3><p className="projection-text">{projection.text}</p><dl className="detail-fields compact">{projection.profile !== 'DEMO-SUMMARY' && <div><dt>Area</dt><dd>{projection.area_label}</dd></div>}<div><dt>{projection.profile === 'DEMO-SUMMARY' ? 'Observed week' : projection.profile === 'DEMO-FULL' ? 'Observed hour' : 'Observed date'}</dt><dd>{projection.profile === 'DEMO-SUMMARY' ? projection.observed_week : dateLabel(projection.profile === 'DEMO-FULL' ? projection.observed_hour : projection.observed_date, projection.profile === 'DEMO-FULL')}</dd></div>{projection.profile !== 'DEMO-SUMMARY' && <div className="full"><dt>Assistance</dt><dd>{projection.assistance_requested}</dd></div>}{projection.profile === 'DEMO-FULL' && <div><dt>Originating unit</dt><dd>{projection.originating_unit.name} · {projection.originating_unit.code}</dd></div>}<div><dt>Disclosure profile</dt><dd>{profileLabel(projection.profile)}</dd></div><div><dt>Verification</dt><dd>{candidate ? 'Awaiting human review' : projection.verification}</dd></div></dl>
  </div>;
}
export function ReportTable({ reports, onOpen, reviewer = false }: { reports: SourceSummary[]; onOpen: (report: SourceSummary) => void; reviewer?: boolean }) {
  return <div className="table-scroll"><table className="report-table"><thead><tr><th>Report</th><th>Area & urgency</th><th>Status</th><th>Received</th><th><span className="sr-only">Action</span></th></tr></thead><tbody>{reports.map(report => <tr key={report.id}><td className="cell-ref"><button className="report-link" onClick={() => onOpen(report)}>{report.reference}<span>{CATEGORY_LABELS[report.category]}</span></button></td><td className="cell-area"><strong>{report.area_label}</strong><span className={'cell-sub ' + (report.urgency === 'PRIORITY' ? 'priority' : '')}>{report.urgency === 'PRIORITY' ? 'Priority' : 'Routine'}</span></td><td className="cell-status"><StatusBadge status={report.status} /></td><td className="muted cell-date">{dateLabel(report.created_at)}</td><td className="row-action"><button className="icon-button" onClick={() => onOpen(report)} aria-label={`${reviewer ? 'Review' : 'Open'} ${report.reference}`}><Icon name="chevron" /></button></td></tr>)}</tbody></table></div>;
}
export function MetricCard({ label, value, detail, icon, tone = 'teal', share }: { label: string; value: number | string; detail: string; icon: IconName; tone?: 'teal' | 'amber' | 'blue'; share?: { value: number; of: number; label: string } }) {
  return <div className={'metric-card tone-' + tone}><div className="metric-top"><span>{label}</span><span className={'metric-icon ' + tone}><Icon name={icon} /></span></div><strong className="metric-value">{value}</strong>{share && <progress className="metric-bar" value={share.value} max={Math.max(share.of, 1)} aria-label={share.label} />}<p>{detail}</p></div>;
}
export function ReportFilterBar({ filters, onApply, busy = false }: { filters: ReportFilters; onApply: (next: ReportFilters) => void; busy?: boolean }) {
  const [draft, setDraft] = useState(filters);
  const [error, setError] = useState('');
  useEffect(() => { setDraft(filters); setError(''); }, [filters]);
  return <form className="report-filters" onSubmit={event => { event.preventDefault(); const issue = validateReportFilters(draft); setError(issue); if (!issue) onApply({ ...draft, page: 1 }); }} noValidate>
    <fieldset disabled={busy}><legend className="sr-only">Filter reports</legend><div className="filter-controls">
      <label className="field"><span>Report status</span><select value={draft.status} onChange={event => setDraft({ ...draft, status: event.target.value as ReportFilters['status'] })}><option value="ALL">All statuses</option>{Object.entries(STATUS_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <label className="field"><span>Created from (UTC)</span><input type="date" value={draft.date_from} onChange={event => setDraft({ ...draft, date_from: event.target.value })} aria-invalid={!!error} aria-describedby={error ? 'report-filter-error' : undefined} /></label>
      <label className="field"><span>Created to (UTC)</span><input type="date" value={draft.date_to} onChange={event => setDraft({ ...draft, date_to: event.target.value })} aria-invalid={!!error} aria-describedby={error ? 'report-filter-error' : undefined} /></label>
      <div className="button-row"><button className="button secondary" type="submit">Apply filters</button><button className="text-button" type="button" onClick={() => { setError(''); onApply({ ...filters, status: 'ALL', date_from: '', date_to: '', page: 1 }); }}>Clear filters</button></div>
    </div></fieldset>{error && <p className="field-error" id="report-filter-error" role="alert">{error}</p>}
  </form>;
}
export function Pagination({ data, busy, onPage, onPageSize }: { data: Omit<PageResult<unknown>, 'results'>; busy: boolean; onPage: (page: number) => void; onPageSize: (size: number) => void }) {
  const start = data.count === 0 || data.page > data.total_pages ? 0 : (data.page - 1) * data.page_size + 1;
  const end = start === 0 ? 0 : Math.min(data.page * data.page_size, data.count);
  return <nav className="pagination" aria-label="Results pages"><span role="status">{start}–{end} of {data.count} results</span><label className="page-size">Per page <select value={data.page_size} onChange={event => onPageSize(Number(event.target.value))} disabled={busy}>{[10, 25, 50].map(size => <option key={size}>{size}</option>)}</select></label><div className="button-row"><button className="button secondary small" aria-label="Previous page" disabled={busy || data.page <= 1} onClick={() => onPage(Math.max(1, Math.min(data.page - 1, data.total_pages)))}>Previous</button><span>Page {data.page} of {Math.max(1, data.total_pages)}</span><button className="button secondary small" aria-label="Next page" disabled={busy || data.page >= data.total_pages} onClick={() => onPage(data.page + 1)}>Next</button></div></nav>;
}
export function Modal({ title, children, onClose, locked = false }: { title: string; children: ReactNode; onClose: () => void; locked?: boolean }) {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prior = document.activeElement as HTMLElement | null;
    const controls = () => [...(box.current?.querySelectorAll<HTMLElement>('button:not([disabled]), input, textarea, select, [tabindex="0"]') ?? [])];
    const firstControl = controls()[0];
    if (firstControl) firstControl.focus(); else box.current?.focus();
    const handler = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !locked) { event.preventDefault(); onClose(); }
      if (event.key === 'Tab') {
        const items = controls(); if (!items.length) { event.preventDefault(); box.current?.focus(); return; }
        const first = items[0], last = items[items.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener('keydown', handler); return () => { document.removeEventListener('keydown', handler); prior?.focus(); };
  }, [onClose, locked]);
  return <div className="modal-backdrop"><div className="modal-box" role="dialog" aria-modal="true" aria-labelledby="modal-title" tabIndex={-1} ref={box}><div className="modal-heading"><h2 id="modal-title">{title}</h2><button className="icon-button" onClick={onClose} disabled={locked} aria-label="Close confirmation"><Icon name="close" /></button></div>{children}</div></div>;
}
