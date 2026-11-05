import type { AccountFields, AdminContext, ChannelGrant, FeedFilters, MapCounts, Operation, Payload, Profile, Projection, ReportFilters, ReportStatus, User, Workflow } from './types';

export const CATEGORY_LABELS = { INFRASTRUCTURE: 'Infrastructure', WATER_SUPPLY: 'Water supply', EQUIPMENT: 'Equipment' } as const;
export const STATUS_LABELS: Record<ReportStatus, string> = {
  PENDING: 'Received · awaiting processing', PROCESSING: 'Processing', AWAITING_REVIEW: 'Awaiting human review',
  APPROVED: 'Review approved', RETURNED: 'Returned for correction', REJECTED: 'Rejected', FAILED: 'Processing failed',
};
export const AREAS = ['Area A', 'Area B', 'Area C'] as const;
export const PROFILE_RANK: Record<Profile, number> = { 'DEMO-SUMMARY': 1, 'DEMO-REDUCED': 2, 'DEMO-FULL': 3 };
export function allowedProfiles(ceiling: Profile): Profile[] {
  if (!Object.hasOwn(PROFILE_RANK, ceiling)) return [];
  return (['DEMO-FULL', 'DEMO-REDUCED', 'DEMO-SUMMARY'] as Profile[]).filter(profile => PROFILE_RANK[profile] <= PROFILE_RANK[ceiling]);
}
export function recipientGrants(user: User): ChannelGrant[] {
  const grants = user.grants ?? (user.channel && user.profile ? [{ channel: user.channel, profile_ceiling: user.profile }] : []);
  const seen = new Set<string>();
  return grants.filter(grant => {
    if (!grant?.channel?.id || !allowedProfiles(grant.profile_ceiling).length || seen.has(grant.channel.id)) return false;
    seen.add(grant.channel.id); return true;
  });
}
export function accessSignature(user: User): string {
  return JSON.stringify({ id: user.id, role: user.role, profile: user.profile, unit: user.unit?.id, channel: user.channel?.id,
    grants: recipientGrants(user).map(grant => [grant.channel.id, grant.profile_ceiling]).sort(),
    channels: user.channels?.map(channel => channel.id).sort() });
}
export function projectionObserved(projection: Projection): string {
  return projection.profile === 'DEMO-SUMMARY' ? projection.observed_week :
    projection.profile === 'DEMO-FULL' ? dateLabel(projection.observed_hour, true) : dateLabel(projection.observed_date);
}
export function publishedLabel(value: string, profile: Profile): string {
  return profile === 'DEMO-FULL' ? dateLabel(value, true) : profile === 'DEMO-SUMMARY' ? `Week of ${dateLabel(value.slice(0, 10))}` : dateLabel(value.slice(0, 10));
}
export function mapMatchesCount(map: MapCounts, count: number): boolean {
  if (!map || !Array.isArray(map.areas) || !Number.isSafeInteger(count) || count < 0 || !Number.isSafeInteger(map.unmapped) || map.unmapped < 0) return false;
  const seen = new Set<string>(); let total = map.unmapped;
  for (const area of map.areas) {
    if (!area || !['area-a', 'area-b', 'area-c'].includes(area.area_id) || seen.has(area.area_id) || !Number.isSafeInteger(area.count) || area.count < 0) return false;
    seen.add(area.area_id); total += area.count;
  }
  return Number.isSafeInteger(total) && total === count;
}
export const ASSISTANCE = ['Repair assistance', 'Inspection', 'Replacement parts'] as const;
export function localDateTime(now = new Date()): string {
  const adjusted = new Date(now.getTime() - now.getTimezoneOffset() * 60_000);
  return adjusted.toISOString().slice(0, 16);
}
export function validatePayload(payload: Payload, now = Date.now()): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const field of ['site_label', 'reporter_label', 'narrative'] as const) {
    if (!payload[field].trim()) errors[field] = 'Enter a ' + (field === 'narrative' ? 'description.' : field.replace('_label', '') + ' label.');
    else if (payload[field].length > (field === 'narrative' ? 2000 : 100)) errors[field] = 'Use no more than ' + (field === 'narrative' ? 2000 : 100) + ' characters.';
  }
  if (!Object.prototype.hasOwnProperty.call(CATEGORY_LABELS, payload.category)) errors.category = 'Choose a supported category.';
  if (!['ROUTINE', 'PRIORITY'].includes(payload.urgency)) errors.urgency = 'Choose a supported urgency.';
  if (!(AREAS as readonly string[]).includes(payload.area_label)) errors.area_label = 'Choose an area.';
  if (!(ASSISTANCE as readonly string[]).includes(payload.assistance_requested)) errors.assistance_requested = 'Choose the assistance needed.';
  const observed = Date.parse(payload.observed_at);
  if (!/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(payload.observed_at) || !Number.isFinite(observed)) errors.observed_at = 'Enter a valid observation date and time.';
  else if (observed > now + 300_000) errors.observed_at = 'Observation time cannot be more than five minutes in the future.';
  return errors;
}
export function validateCorrectionReason(reason: string): string {
  return typeof reason !== 'string' || !reason.trim() ? 'Enter a private reason for this correction.' : reason.length > 500 ? 'Use no more than 500 correction reason characters.' : '';
}
export function createOperation(payload: Payload, correction?: { report_id: string; expected_revision: number; correction_reason: string }): Operation {
  if (correction && (!correction.report_id || !Number.isSafeInteger(correction.expected_revision) || correction.expected_revision < 1)) throw new Error('A correction requires a current source revision.');
  if (correction && validateCorrectionReason(correction.correction_reason)) throw new Error('A correction requires a nonblank private reason of at most 500 characters.');
  return { operation_id: crypto.randomUUID(), report_id: correction?.report_id ?? crypto.randomUUID(), expected_revision: correction?.expected_revision ?? 0, template_version: 'demo-maintenance-v1', payload: { ...payload }, ...(correction ? { correction_reason: correction.correction_reason } : {}) };
}
export function dateLabel(value: string, withTime = false): string {
  if (!value) return '—';
  // Day-precision recipient dates must not shift with the browser timezone.
  if (!withTime && /^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return new Intl.DateTimeFormat('en-PH', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }).format(new Date(value + 'T00:00:00Z'));
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '—';
  return new Intl.DateTimeFormat('en-PH', { day: 'numeric', month: 'short', year: 'numeric', ...(withTime ? { hour: '2-digit', minute: '2-digit', timeZoneName: 'short' } : {}) }).format(date);
}
export function ageLabel(value: string, now = Date.now()): string {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return '—';
  const hours = Math.max(0, Math.floor((now - time) / 3_600_000));
  if (hours < 1) return 'Under 1 hour';
  if (hours < 48) return `${hours} ${hours === 1 ? 'hour' : 'hours'}`;
  return `${Math.floor(hours / 24)} days`;
}
// Disclosure profile codes are stable data identifiers; people see these names.
export function profileLabel(profile: string | null | undefined): string {
  if (!profile) return 'None';
  return profile === 'DEMO-FULL' ? 'Full' : profile === 'DEMO-REDUCED' ? 'Reduced' : profile === 'DEMO-SUMMARY' ? 'Summary' : profile;
}
export function roleLabel(role: string): string {
  return role === 'submitter' ? 'Report submitter' : role === 'reviewer' ? 'Originating reviewer' : role === 'administrator' ? 'Account administrator' : 'Channel recipient';
}
export function validateReportFilters(filters: Pick<ReportFilters, 'date_from' | 'date_to'>): string {
  for (const date of [filters.date_from, filters.date_to]) {
    if (date && (!/^\d{4}-\d{2}-\d{2}$/.test(date) || date.startsWith('0000') || !Number.isFinite(Date.parse(date)) || new Date(date).toISOString().slice(0, 10) !== date)) return 'Choose valid report creation dates.';
  }
  return filters.date_from && filters.date_to && filters.date_from > filters.date_to ? 'The end date must be on or after the start date.' : '';
}
export function eligibleChannels(context: AdminContext, unitId: string): AdminContext['channels'] {
  if (!context.units.some(unit => unit.id === unitId && unit.active)) return [];
  return context.channels.filter(channel => channel.active && context.channel_sources.some(source => source.active && source.unit_id === unitId && source.channel_id === channel.id));
}
export function validateAccount(fields: AccountFields, context: AdminContext): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!fields.display_name.trim()) errors.display_name = 'Enter a display name.';
  else if (fields.display_name.length > 120) errors.display_name = 'Use no more than 120 characters.';
  if (fields.role === 'administrator') {
    if (fields.unit_id || fields.channel_id) errors.role = 'Administrators have no source unit or recipient channel.';
  } else if (fields.role === 'recipient') {
    if (fields.unit_id) errors.unit_id = 'Recipients have no source unit.';
    if (!context.channels.some(channel => channel.active && channel.id === fields.channel_id)) errors.channel_id = 'Choose an active recipient channel.';
  } else if (fields.role === 'submitter' || fields.role === 'reviewer') {
    if (!context.units.some(unit => unit.active && unit.id === fields.unit_id)) errors.unit_id = 'Choose an active source unit.';
    const channels = eligibleChannels(context, fields.unit_id ?? '');
    if (channels.length !== 1 || channels[0]?.id !== fields.channel_id) errors.channel_id = 'The unit must have exactly one eligible active channel.';
  } else errors.role = 'Choose a supported account role.';
  return errors;
}
export function validatePasswordChange(current: string, next: string, confirmation: string): Record<string, string> {
  const errors: Record<string, string> = {};
  if (current.length < 1 || current.length > 128) errors.current_password = 'Enter your current password (up to 128 characters).';
  if (next.length < 12 || next.length > 128) errors.new_password = 'Use between 12 and 128 characters.';
  else if (next === current) errors.new_password = 'Choose a different password.';
  if (confirmation !== next) errors.confirmation = 'The new passwords must match exactly.';
  return errors;
}
export function validateFeedFilters(filters: Pick<FeedFilters, 'q' | 'category' | 'urgency'> & Partial<Pick<FeedFilters, 'area' | 'profile'>>): string {
  if (filters.q.trim().length > 120) return 'Use no more than 120 search characters.';
  if (filters.category !== 'ALL' && !Object.prototype.hasOwnProperty.call(CATEGORY_LABELS, filters.category)) return 'Choose a supported category.';
  if (!['ALL', 'ROUTINE', 'PRIORITY'].includes(filters.urgency)) return 'Choose a supported urgency.';
  if (filters.profile !== undefined && !allowedProfiles(filters.profile).length) return 'Choose a supported profile.';
  if (filters.area && filters.area !== 'ALL' && !(AREAS as readonly string[]).includes(filters.area)) return 'Choose a supported area.';
  if (filters.profile === 'DEMO-SUMMARY' && filters.area && filters.area !== 'ALL') return 'Area filters are unavailable for this profile.';
  return '';
}
export function sharingExplanation(state: Workflow['sharing']['state']): string {
  const explanations: Record<Workflow['sharing']['state'], string> = {
    NOT_SHARED: 'This revision has no available publication. Receiving or processing a report does not share it.',
    AVAILABLE: 'The approved publication is currently available. Each recipient must also hold a current channel grant.',
    WITHDRAWN: 'The publication was withdrawn. The earlier approval remains in this private history.',
    SUPERSEDED: 'A newer source revision replaced this one. Its earlier approval does not authorize the new revision.',
    UNAVAILABLE: 'The publication cannot currently be shared under its required approval, policy and channel checks.',
  };
  return explanations[state] ?? 'Current sharing availability could not be confirmed.';
}
