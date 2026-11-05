import type { ReportActivityCounts, ReportStatus } from './types';

export const ACTIVITY_STATUSES: readonly ReportStatus[] = ['PENDING', 'PROCESSING', 'AWAITING_REVIEW', 'APPROVED', 'RETURNED', 'REJECTED', 'FAILED'];
const record = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const count = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;

// Responses remain untrusted at runtime. A missing, partial or inconsistent
// aggregate must never appear as an authoritative zero-count summary.
export function parseReportActivity(value: unknown): ReportActivityCounts | null {
  if (!record(value) || Object.keys(value).length !== 3 || !count(value.total) || !count(value.unclassified) || !record(value.by_status)) return null;
  const statuses = value.by_status;
  if (Object.keys(statuses).length !== ACTIVITY_STATUSES.length || ACTIVITY_STATUSES.some(status => !Object.hasOwn(statuses, status) || !count(statuses[status]))) return null;
  const total = ACTIVITY_STATUSES.reduce((sum, status) => sum + (statuses[status] as number), value.unclassified);
  if (!Number.isSafeInteger(total) || total !== value.total) return null;
  return { total: value.total, unclassified: value.unclassified, by_status: Object.fromEntries(ACTIVITY_STATUSES.map(status => [status, statuses[status]])) as Record<ReportStatus, number> };
}
