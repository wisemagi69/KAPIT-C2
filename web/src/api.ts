import type { BatchReviewDetail, BatchDecisionOperation, BatchDecisionResult, WithdrawalOperation, WithdrawalResult } from './types';
import type { AccountFields, AdminContext, AdminFilters, AdminUser, DecisionOperation, DecisionResult, DeviceRevocation, EnrolledDevice, EnrolledDevices, Feed, FeedFilters, MapCounts, Operation, PageResult, Publication, Receipt, RemovedPublication, ReportFilters, ReviewDetail, SourceDetail, SourceSummary, User } from './types';

const ROOT = '/api/v1';
let csrfToken = '';
export class ApiError extends Error {
  status: number;
  code: string;
  fields: Record<string, string>;
  constructor(status: number, code: string, message: string, fields: Record<string, string> = {}) {
    super(message); this.name = 'ApiError'; this.status = status; this.code = code; this.fields = fields;
  }
  get uncertain() { return this.status === 0 || this.status >= 500; }
}
export function clearApiMemory() { csrfToken = ''; }
export function isBackendUnavailable(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 0 || error.status >= 500 || error.code === 'BACKEND_UNAVAILABLE');
}
function unavailableResponse(status = 0): ApiError {
  return new ApiError(status, 'BACKEND_UNAVAILABLE', 'The workspace server is unavailable. Start the local application, then check the connection.');
}
export function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : 'The connection could not be completed. Please try again.';
}
async function csrf(): Promise<string> {
  if (csrfToken) return csrfToken;
  const result = await request<{ csrf_token: string }>('/auth/csrf/');
  if (typeof result.csrf_token !== 'string' || !result.csrf_token.trim()) throw unavailableResponse();
  csrfToken = result.csrf_token;
  return csrfToken;
}
async function boundedJson(response: Response, limit: number): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) return null;
  const chunks: Uint8Array[] = []; let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) { await reader.cancel(); return null; }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } finally { reader.releaseLock(); }
}
async function request<T>(path: string, init: RequestInit = {}, responseLimit?: number): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 15_000);
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body) headers.set('Content-Type', 'application/json');
  const unsafe = init.method && !['GET', 'HEAD', 'OPTIONS'].includes(init.method);
  try {
    if (unsafe) headers.set('X-CSRFToken', await csrf());
    const response = await fetch(ROOT + path, { ...init, headers, credentials: 'same-origin', cache: 'no-store', signal: controller.signal });
    const body = await (responseLimit ? boundedJson(response, responseLimit) : response.json()).catch(() => null) as Record<string, unknown> | null;
    const code = typeof body?.code === 'string' ? body.code : 'REQUEST_FAILED';
    const csrfFailure = code.toLowerCase().includes('csrf');
    // Authorization denials clear private views even when a proxy returns HTML.
    if (!response.ok && (response.status === 401 || response.status === 403 && !csrfFailure) && path !== '/auth/login/' && path !== '/me/' && path !== '/auth/csrf/' && path !== '/auth/logout/') {
      window.dispatchEvent(new Event('kapit-session-expired'));
    }
    // A static preview or stopped proxy can return an HTML page even with HTTP 200.
    // Never treat that page as an authentication response or display its contents.
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw unavailableResponse(response.ok ? 0 : response.status);
    if (!response.ok) {
      const fields: Record<string, string> = {};
      if (body?.errors && typeof body.errors === 'object') {
        for (const [name, value] of Object.entries(body.errors)) {
          if (typeof value === 'string') fields[name] = value;
          else if (Array.isArray(value) && typeof value[0] === 'string') fields[name] = value[0];
        }
      }
      if (csrfFailure) csrfToken = '';
      throw new ApiError(response.status, code, typeof body?.message === 'string' ? body.message : 'This request is unavailable. Refresh and try again.', fields);
    }
    return body as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(0, 'CONNECTION_LOST', 'The server could not be reached. Check your connection and try again.');
  } finally { window.clearTimeout(timeout); }
}
const post = <T>(path: string, body: unknown, key?: string) => request<T>(path, { method: 'POST', body: JSON.stringify(body), headers: key ? { 'Idempotency-Key': key } : {} });
const query = (values: Record<string, string | number>) => {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) if (value !== '' && !(key === 'role' && value === 'ALL')) params.set(key, String(value));
  return params.size ? '?' + params.toString() : '';
};
function confirmedUser(response: { user: User }): { user: User } {
  if (!response.user || typeof response.user !== 'object' || typeof response.user.id !== 'string' || typeof response.user.role !== 'string' || typeof response.user.display_name !== 'string') throw unavailableResponse();
  return response;
}
const deviceId = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
const exactFields = (value: unknown, fields: string[]): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
function deviceDate(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value)) return false;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.getUTCFullYear() > 0 && date.toISOString().slice(0, 19) === value.slice(0, 19);
}
function invalidDevices(): ApiError { return new ApiError(0, 'INVALID_DEVICE_RESPONSE', 'The device response could not be confirmed.'); }
function confirmedDevices(value: unknown): EnrolledDevices {
  if (!exactFields(value, ['results', 'count']) || !Array.isArray(value.results) || !Number.isInteger(value.count) || value.count !== value.results.length || value.results.length > 100) throw invalidDevices();
  const ids = new Set<string>();
  const results = value.results.map((row: unknown): EnrolledDevice => {
    if (!exactFields(row, ['id', 'label', 'created_at', 'last_authenticated_at', 'revoked_at']) || !deviceId(row.id) || ids.has(row.id) || typeof row.label !== 'string' || !row.label.trim() || [...row.label].length > 80 || /[\p{Cc}\p{Cf}\p{Cs}]/u.test(row.label) || !deviceDate(row.created_at) || !deviceDate(row.last_authenticated_at) || row.revoked_at !== null && !deviceDate(row.revoked_at)) throw invalidDevices();
    ids.add(row.id);
    return { id: row.id, label: row.label, created_at: row.created_at, last_authenticated_at: row.last_authenticated_at, revoked_at: row.revoked_at };
  });
  return { results, count: results.length };
}
export const api = {
  policyState: () => request<import('./types').PolicyState>('/administration/policy/'),
  integrationState: (page = 1) => request<import('./types').IntegrationState>(`/administration/integration-clients/?page=${page}&page_size=25`),
  governanceWrite: (path: string, body: Record<string, unknown>, operationId?: string) => {
    if (!/^\/administration\/(?:policy\/proposals\/(?:[a-f0-9-]{36}\/apply\/)?|integration-clients\/(?:requests\/[a-f0-9-]{36}\/(?:approve|collect)\/|[a-f0-9-]{36}\/revoke\/)?)$/.test(path)) throw new ApiError(0, 'INVALID_REQUEST', 'Reload this administration panel.');
    return post<Record<string, unknown>>(path, body, operationId);
  },
  me: async () => confirmedUser(await request<{ user: User }>('/me/')),
  checkConnection: async () => { clearApiMemory(); await csrf(); },
  login: async (username: string, password: string) => {
    const response = confirmedUser(await post<{ user: User }>('/auth/login/', { username, password }));
    csrfToken = ''; // Django rotates its CSRF secret on login.
    return response;
  },
  logout: () => post<Record<string, unknown>>('/auth/logout/', {}),
  changePassword: async (body: { current_password: string; new_password: string }) => {
    try {
      const response = await post<{ changed: true; reauthenticate: true }>('/auth/password/', body);
      if (response.changed !== true || response.reauthenticate !== true) throw new ApiError(0, 'UNCONFIRMED_CHANGE', 'The password change could not be confirmed.');
      clearApiMemory(); return response;
    } catch (failure) { if (failure instanceof ApiError && failure.uncertain) clearApiMemory(); throw failure; }
  },
  devices: async () => confirmedDevices(await request<unknown>('/account/devices/', {}, 128 * 1024)),
  revokeDevice: async (id: string): Promise<DeviceRevocation> => {
    if (!deviceId(id)) throw invalidDevices();
    const value = await request<unknown>(`/account/devices/${encodeURIComponent(id)}/revoke/`, { method: 'POST', body: '{}' }, 4096);
    if (!exactFields(value, ['id', 'revoked', 'revoked_at']) || value.id !== id || value.revoked !== true || !deviceDate(value.revoked_at)) throw invalidDevices();
    return { id, revoked: true, revoked_at: value.revoked_at };
  },
  reports: (filters?: ReportFilters) => request<PageResult<SourceSummary>>('/reports/' + (filters ? query({ ...filters }) : '')),
  source: (id: string, revision = 1) => request<SourceDetail>(`/reports/${encodeURIComponent(id)}/revisions/${revision}/`),
  submit: (operation: Operation) => post<Receipt>('/sync/operations/', operation, operation.operation_id),
  receipt: (id: string) => request<Receipt>(`/sync/receipts/${encodeURIComponent(id)}/`),
  queue: (filters?: ReportFilters) => request<PageResult<SourceSummary>>('/review/queue/' + (filters ? query({ ...filters }) : '')),
  review: (id: string) => request<ReviewDetail>(`/variants/${encodeURIComponent(id)}/review/`),
  decide: (id: string, operation: DecisionOperation) => post<DecisionResult>(`/variants/${encodeURIComponent(id)}/decisions/`, operation, operation.operation_id),
  candidateSet: (id: string) => request<BatchReviewDetail>(`/revisions/${encodeURIComponent(id)}/candidates/`),
  decideBatch: async (id: string, operation: BatchDecisionOperation) => {
    const value = await post<BatchDecisionResult>(`/revisions/${encodeURIComponent(id)}/decisions/`, operation, operation.operation_id);
    const strings = (rows: unknown): rows is string[] => Array.isArray(rows) && rows.every(row => typeof row === 'string');
    if (typeof value.batch_id !== 'string' || !value.batch_id || value.action !== operation.action || value.report_status !== ({ APPROVE: 'APPROVED', RETURN: 'RETURNED', REJECT: 'REJECTED' } as const)[operation.action] || !strings(value.approved_profiles) || !strings(value.withheld_profiles) || !strings(value.withheld_variant_ids) || !strings(value.publication_ids) || JSON.stringify([...value.approved_profiles].sort()) !== JSON.stringify([...operation.approve_profiles].sort())) throw new ApiError(0, 'UNCONFIRMED_DECISION', 'The decision result could not be confirmed. Retry the same operation.');
    return value;
  },
  withdraw: async (id: string, operation: WithdrawalOperation) => {
    const value = await post<WithdrawalResult>(`/reports/${encodeURIComponent(id)}/withdrawal/`, operation, operation.operation_id);
    if (typeof value.withdrawal_id !== 'string' || !value.withdrawal_id || value.report_status !== 'WITHDRAWN' || !Array.isArray(value.publication_ids) || !value.publication_ids.every(row => typeof row === 'string')) throw new ApiError(0, 'UNCONFIRMED_WITHDRAWAL', 'The withdrawal result could not be confirmed. Retry the same operation.');
    return value;
  },
  feed: (id: string, filters?: FeedFilters) => request<Feed>(`/channels/${encodeURIComponent(id)}/feed/` + (filters ? query({ ...filters, ...(filters.area === 'ALL' ? { area: '' } : {}) }) : '')),
  map: (id: string, filters: FeedFilters) => request<MapCounts>(`/channels/${encodeURIComponent(id)}/map/` + query({ q: filters.q, category: filters.category, urgency: filters.urgency, ...(filters.profile ? { profile: filters.profile } : {}), ...(filters.area && filters.area !== 'ALL' ? { area: filters.area } : {}) })),
  removed: (id: string) => request<{ results: RemovedPublication[] }>(`/channels/${encodeURIComponent(id)}/removed/`),
  publication: (id: string) => request<Publication>(`/publications/${encodeURIComponent(id)}/`),
  operationsHealth: () => request<unknown>('/administration/health/'),
  administrationContext: () => request<AdminContext>('/administration/context/'),
  users: (filters: AdminFilters) => request<PageResult<AdminUser>>('/administration/users/' + query({ ...filters })),
  createUser: (body: AccountFields & { username: string; password: string }) => post<AdminUser>('/administration/users/', body),
  updateUser: (id: string, body: AccountFields & { expected_permission_version: number }) => request<AdminUser>(`/administration/users/${encodeURIComponent(id)}/`, { method: 'PATCH', body: JSON.stringify(body) }),
  resetUserPassword: (id: string, body: { password: string; expected_permission_version: number }) => post<AdminUser>(`/administration/users/${encodeURIComponent(id)}/password/`, body),
};
