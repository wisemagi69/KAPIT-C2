/** Private original-source evidence only. No persisted references or public URL. */
import { ApiError } from './api';

export const EVIDENCE_LIMIT = 5 * 1024 * 1024;
const ROOT = '/api/v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SIGNATURE = [137, 80, 78, 71, 13, 10, 26, 10];
const QUARANTINE = new Set(['DECODER_REQUIRED', 'DEPENDENCY_UNAVAILABLE', 'PROVENANCE_UNAVAILABLE', 'ISOLATION_UNAVAILABLE',
  'SCANNER_UNAVAILABLE', 'SIGNATURES_STALE', 'SCAN_NOT_CLEAN', 'RESOURCE_LIMIT', 'DECODE_UNAVAILABLE',
  'DERIVATIVE_LIMIT', 'VALIDATION_STALE', 'SCRATCH_CLEANUP_REQUIRED']);
const REJECTED = new Set(['INVALID_IMAGE', 'TYPE_MISMATCH', 'PIXEL_LIMIT', 'MULTIFRAME_UNSUPPORTED', 'METADATA_INVALID']);

export interface EvidenceReference {
  id: string; operation_id: string; state: 'QUARANTINED'; validation_code: 'DECODER_REQUIRED'; created_at: string;
}
export interface EvidenceStatus {
  evidence_id: string; state: 'QUARANTINED' | 'REJECTED_PRIVATE' | 'VALIDATED_PRIVATE';
  validation_code: string; can_download: boolean;
}
export type FrozenEvidenceUpload = Readonly<{
  revisionId: string; operationId: string; mediaType: 'image/png' | 'image/jpeg'; filename: 'evidence.png' | 'evidence.jpg'; body: Blob;
}>;

const invalid = () => new ApiError(0, 'INVALID_EVIDENCE_RESPONSE', 'The private evidence response could not be confirmed.');
const failed = (status: number, code: string) => new ApiError(status, code,
  code === 'CSRF_FAILED' ? 'Refresh the security check and retry the same file.' :
  [401, 403, 404].includes(status) ? 'Private evidence is unavailable in this source view. Refresh the source to continue.' :
  status === 409 ? 'The server could not accept this evidence operation. Refresh the source after resolving any uncertain upload.' :
  status === 413 ? 'Choose a JPEG or PNG file no larger than 5 MiB.' :
  status >= 500 ? 'The upload result could not be confirmed. Retry the same private file.' :
  'This private evidence request could not be completed.');
function exact(value: unknown, keys: string[]): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function identifier(value: unknown): value is string { return typeof value === 'string' && UUID.test(value); }
function date(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value)) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 19) === value.slice(0, 19);
}
function active(signal: AbortSignal) { if (signal.aborted) throw new DOMException('Aborted', 'AbortError'); }
async function bounded(response: Response, maximum: number, signal: AbortSignal): Promise<Uint8Array<ArrayBuffer>> {
  active(signal);
  const declared = response.headers.get('Content-Length');
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > maximum)) {
    await response.body?.cancel(); throw invalid();
  }
  const reader = response.body?.getReader();
  if (!reader) throw invalid();
  const parts: Uint8Array[] = []; let size = 0;
  try {
    while (true) {
      active(signal);
      const { value, done } = await reader.read();
      active(signal);
      if (done) break;
      if (!value || size + value.byteLength > maximum) { await reader.cancel(); throw invalid(); }
      size += value.byteLength; parts.push(value);
    }
    if (declared !== null && Number(declared) !== size) throw invalid();
    const bytes = new Uint8Array(size); let offset = 0;
    for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
    return bytes;
  } finally { reader.releaseLock(); }
}
async function json(response: Response, signal: AbortSignal, maximum = 8192): Promise<unknown> {
  active(signal);
  if (response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/json') {
    await response.body?.cancel(); return null;
  }
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await bounded(response, maximum, signal)));
    active(signal); return value;
  } catch { active(signal); return null; }
}
async function failure(response: Response, signal: AbortSignal): Promise<never> {
  const body = await json(response, signal);
  active(signal);
  const code = exact(body, ['code', 'message']) && typeof body.code === 'string' && body.code === 'CSRF_FAILED' ? 'CSRF_FAILED' : 'EVIDENCE_REQUEST_FAILED';
  if ([401, 403].includes(response.status) && code !== 'CSRF_FAILED') {
    active(signal); window.dispatchEvent(new Event('kapit-session-expired'));
  }
  throw failed(response.status, code);
}
async function request<T>(path: string, action: (response: Response, signal: AbortSignal) => Promise<T>,
  init: RequestInit = {}, signal?: AbortSignal): Promise<T> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener('abort', abort, { once: true });
  if (signal?.aborted) controller.abort();
  const timer = window.setTimeout(abort, 15_000);
  try {
    const response = await fetch(ROOT + path, { ...init, credentials: 'same-origin', cache: 'no-store',
      redirect: 'error', signal: controller.signal });
    active(controller.signal);
    if (!response.ok) return await failure(response, controller.signal);
    const result = await action(response, controller.signal);
    active(controller.signal); return result;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(0, 'EVIDENCE_CONNECTION_LOST', 'The private evidence request could not be confirmed. Retry the same file if an upload is pending.');
  } finally {
    window.clearTimeout(timer); signal?.removeEventListener('abort', abort);
  }
}
export async function freezeEvidenceUpload(file: File, revisionId: string): Promise<FrozenEvidenceUpload> {
  if (!identifier(revisionId) || !file || !Number.isInteger(file.size) || file.size < 1 || file.size > EVIDENCE_LIMIT ||
    !['image/png', 'image/jpeg'].includes(file.type)) throw failed(413, 'INVALID_FILE');
  const buffer = await file.arrayBuffer();
  if (buffer.byteLength !== file.size || buffer.byteLength > EVIDENCE_LIMIT) throw failed(413, 'INVALID_FILE');
  const bytes = new Uint8Array(buffer);
  if (file.type === 'image/png' ? !SIGNATURE.every((value, index) => bytes[index] === value) :
    bytes.length < 4 || bytes[0] !== 255 || bytes[1] !== 216 || bytes.at(-2) !== 255 || bytes.at(-1) !== 217) {
    throw new ApiError(422, 'INVALID_EVIDENCE_IMAGE', 'Choose a JPEG or PNG file with matching contents.');
  }
  return Object.freeze({ revisionId, operationId: crypto.randomUUID(), mediaType: file.type as 'image/png' | 'image/jpeg',
    filename: file.type === 'image/png' ? 'evidence.png' : 'evidence.jpg', body: new Blob([buffer], { type: file.type }) });
}
export async function uploadEvidence(pending: FrozenEvidenceUpload, signal?: AbortSignal): Promise<EvidenceReference> {
  // Fresh CSRF check for each retry; no token survives an account/context change.
  const token = await request('/auth/csrf/', async (response, signal) => {
    const value = await json(response, signal, 2048);
    if (!exact(value, ['csrf_token']) || typeof value.csrf_token !== 'string' ||
      !/^[a-zA-Z0-9]{32,128}$/.test(value.csrf_token)) throw invalid();
    return value.csrf_token;
  }, {}, signal);
  return request(`/revisions/${pending.revisionId}/evidence/`, async (response, signal) => {
    const value = await json(response, signal);
    if (![200, 201].includes(response.status) || !exact(value, ['id', 'operation_id', 'state', 'validation_code', 'created_at']) ||
      !identifier(value.id) || value.operation_id !== pending.operationId || value.state !== 'QUARANTINED' ||
      value.validation_code !== 'DECODER_REQUIRED' || !date(value.created_at)) throw invalid();
    return { id: value.id, operation_id: pending.operationId, state: 'QUARANTINED', validation_code: 'DECODER_REQUIRED', created_at: value.created_at };
  }, { method: 'POST', body: pending.body, headers: { Accept: 'application/json', 'Content-Type': pending.mediaType,
    'X-Evidence-Filename': pending.filename, 'Idempotency-Key': pending.operationId, 'X-CSRFToken': token } }, signal);
}
export async function evidenceStatus(evidenceId: string, signal?: AbortSignal): Promise<EvidenceStatus> {
  if (!identifier(evidenceId)) throw invalid();
  return request(`/evidence/${evidenceId}/validation/`, async (response, signal) => {
    const value = await json(response, signal);
    if (!exact(value, ['evidence_id', 'state', 'validation_code', 'can_download']) || value.evidence_id !== evidenceId ||
      typeof value.can_download !== 'boolean' || typeof value.validation_code !== 'string') throw invalid();
    if (value.state === 'VALIDATED_PRIVATE' ? value.validation_code !== 'VALIDATION_COMPLETE' || value.can_download !== true :
      value.state === 'QUARANTINED' ? !QUARANTINE.has(value.validation_code) || value.can_download !== false :
      value.state === 'REJECTED_PRIVATE' ? !REJECTED.has(value.validation_code) || value.can_download !== false : true) throw invalid();
    return { evidence_id: evidenceId, state: value.state as EvidenceStatus['state'], validation_code: value.validation_code, can_download: value.can_download };
  }, {}, signal);
}
export async function downloadEvidence(evidenceId: string, signal?: AbortSignal): Promise<Blob> {
  if (!identifier(evidenceId)) throw invalid();
  return request(`/evidence/${evidenceId}/download/`, async (response, signal) => {
    if (response.status !== 200 || response.headers.get('Content-Type')?.trim().toLowerCase() !== 'image/png' ||
      response.headers.get('Content-Disposition') !== 'attachment; filename="evidence.png"' ||
      response.headers.get('X-Content-Type-Options')?.toLowerCase() !== 'nosniff' ||
      !response.headers.get('Cache-Control')?.split(',').some(value => value.trim().toLowerCase() === 'no-store') ||
      response.headers.has('Content-Range') || response.headers.has('ETag') || response.headers.has('Last-Modified')) {
      await response.body?.cancel(); throw invalid();
    }
    const bytes = await bounded(response, EVIDENCE_LIMIT + 1, signal);
    if (!bytes.length || bytes.length > EVIDENCE_LIMIT || !SIGNATURE.every((value, index) => bytes[index] === value)) throw invalid();
    return new Blob([bytes], { type: 'image/png' });
  }, { headers: { Accept: 'image/png' } }, signal);
}
