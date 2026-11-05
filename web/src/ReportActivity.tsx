import { STATUS_LABELS } from './domain';
import { ACTIVITY_STATUSES } from './reportActivity';
import type { ReportActivityCounts, ReportFilters } from './types';

interface Props {
  activity: ReportActivityCounts | null;
  filters: ReportFilters;
  loading: boolean;
  error: string;
  onApply: (filters: ReportFilters) => void;
}

export default function ReportActivity({ activity, filters, loading, error, onApply }: Props) {
  const available = !loading && !error ? activity : null;
  const select = (status: ReportFilters['status']) => onApply({ ...filters, status, page: 1 });
  return <section className="card report-activity" aria-labelledby="report-activity-title" aria-busy={loading}>
    <div className="card-heading"><div><h3 id="report-activity-title">Report activity</h3><p>All pages and all statuses within your selected dates. Only reports you can access.</p></div></div>
    <p className="report-activity-message" role="status">{loading ? 'Updating report activity…' : !available ? 'Activity counts unavailable. You can still filter the report list.' : 'Select a status to filter the list below.'}</p>
    <div className="report-activity-grid" role="group" aria-label="Filter reports by activity status">
      {(['ALL', ...ACTIVITY_STATUSES] as const).map(status => <button key={status} type="button" className={'report-activity-filter tone-' + status.toLowerCase()} disabled={loading} aria-pressed={filters.status === status} onClick={() => select(status)}>
        <span><i className="activity-dot" aria-hidden="true" />{status === 'ALL' ? 'All reports' : STATUS_LABELS[status]}</span>
        <strong aria-label={available ? `${status === 'ALL' ? available.total : available.by_status[status]} reports` : 'Count unavailable'}>{available ? status === 'ALL' ? available.total : available.by_status[status] : '—'}</strong>
      </button>)}
    </div>
    {available && available.unclassified > 0 && <p className="report-activity-message">{available.unclassified} reports have an unavailable status and are included in All reports.</p>}
  </section>;
}
