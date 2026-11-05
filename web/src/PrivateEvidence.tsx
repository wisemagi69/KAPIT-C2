import { useEffect, useRef, useState } from 'react';
import { ApiError, errorMessage } from './api';
import { Notice } from './components';
import { Icon } from './icons';
import { downloadEvidence, evidenceStatus, freezeEvidenceUpload, uploadEvidence } from './evidenceApi';
import type { EvidenceReference, EvidenceStatus, FrozenEvidenceUpload } from './evidenceApi';

type Reference = { receipt: EvidenceReference; status: EvidenceStatus | null };
export default function PrivateEvidence({ revisionId, canUpload, onLockChange }: {
  revisionId: string; canUpload: boolean; onLockChange?: (locked: boolean) => void;
}) {
  const [selected, setSelected] = useState<File | null>(null);
  const [references, setReferences] = useState<Reference[]>([]);
  const [busy, setBusy] = useState(false), [uncertain, setUncertain] = useState(false);
  const [blocked, setBlocked] = useState(false), [error, setError] = useState(''), [notice, setNotice] = useState('');
  const pending = useRef<FrozenEvidenceUpload | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const requests = useRef(new Set<AbortController>()), urls = useRef(new Set<string>());
  const generation = useRef(0), alive = useRef(false), sending = useRef(false);
  const errorBox = useRef<HTMLDivElement>(null);
  const locked = busy || uncertain;

  useEffect(() => {
    alive.current = true; generation.current++;
    return () => {
      alive.current = false; generation.current++;
      for (const controller of requests.current) controller.abort();
      requests.current.clear();
      for (const url of urls.current) URL.revokeObjectURL(url);
      urls.current.clear(); pending.current = null;
      if (input.current) input.current.value = '';
    };
  }, []);
  useEffect(() => { onLockChange?.(locked); return () => onLockChange?.(false); }, [locked, onLockChange]);
  useEffect(() => { if (error) errorBox.current?.focus(); }, [error]);

  const deny = () => {
    generation.current++;
    for (const controller of requests.current) controller.abort();
    requests.current.clear();
    for (const url of urls.current) URL.revokeObjectURL(url);
    urls.current.clear(); pending.current = null;
    if (input.current) input.current.value = '';
    setSelected(null); setReferences([]); setUncertain(false); setBusy(false); setNotice(''); setBlocked(true);
    onLockChange?.(false);
    setError('Private evidence is unavailable in this source view. Refresh the source to continue.');
  };
  useEffect(() => {
    const expired = () => { if (alive.current) deny(); };
    window.addEventListener('kapit-session-expired', expired);
    return () => window.removeEventListener('kapit-session-expired', expired);
  }, []);
  const denied = (failure: unknown) => failure instanceof ApiError &&
    [401, 403, 404].includes(failure.status) && failure.code !== 'CSRF_FAILED';
  const current = (token: number) => alive.current && token === generation.current;
  const begin = () => { const controller = new AbortController(); requests.current.add(controller); return controller; };

  const send = async () => {
    if (!canUpload || sending.current || blocked || !selected && !pending.current) return;
    const token = generation.current, recovering = uncertain, controller = begin();
    sending.current = true; onLockChange?.(true); setBusy(true); setError(''); setNotice('');
    try {
      const frozen = pending.current ?? await freezeEvidenceUpload(selected!, revisionId);
      if (!current(token)) return;
      pending.current = frozen;
      const receipt = await uploadEvidence(frozen, controller.signal);
      if (!current(token)) return;
      if (references.some(row => row.receipt.id === receipt.id && row.receipt.operation_id !== receipt.operation_id)) {
        throw new ApiError(0, 'INVALID_EVIDENCE_RESPONSE', 'The private evidence response could not be confirmed.');
      }
      setReferences(rows => rows.some(row => row.receipt.id === receipt.id) ? rows : [...rows, { receipt, status: null }].slice(0, 2));
      pending.current = null; setSelected(null); setUncertain(false);
      if (input.current) input.current.value = '';
      setNotice('Private upload received in quarantine. Your text receipt is unchanged. Validation and download have not been confirmed.');
    } catch (failure) {
      if (!current(token)) return;
      if (denied(failure)) { deny(); return; }
      const unresolved = pending.current !== null && (recovering || failure instanceof ApiError && failure.uncertain);
      setUncertain(unresolved); setError(errorMessage(failure));
      if (!unresolved) { pending.current = null; setSelected(null); if (input.current) input.current.value = ''; }
    } finally {
      requests.current.delete(controller); sending.current = false;
      if (current(token)) { setBusy(false); onLockChange?.(pending.current !== null); }
    }
  };

  const refresh = async (id: string) => {
    if (sending.current || blocked) return;
    const token = generation.current, controller = begin();
    sending.current = true; onLockChange?.(true); setBusy(true); setError(''); setNotice('');
    setReferences(rows => rows.map(row => row.receipt.id === id ? { ...row, status: null } : row));
    try {
      const status = await evidenceStatus(id, controller.signal);
      if (current(token)) setReferences(rows => rows.map(row => row.receipt.id === id ? { ...row, status } : row));
    } catch (failure) {
      if (current(token)) { if (denied(failure)) deny(); else setError(errorMessage(failure)); }
    } finally {
      requests.current.delete(controller); sending.current = false;
      if (current(token)) { setBusy(false); onLockChange?.(pending.current !== null); }
    }
  };

  const download = async (id: string) => {
    if (sending.current || blocked || !references.some(row => row.receipt.id === id && row.status?.can_download === true)) return;
    const token = generation.current, controller = begin();
    sending.current = true; onLockChange?.(true); setBusy(true); setError(''); setNotice('');
    setReferences(rows => rows.map(row => row.receipt.id === id ? { ...row, status: null } : row));
    try {
      const blob = await downloadEvidence(id, controller.signal);
      if (!current(token)) return;
      const url = URL.createObjectURL(blob); urls.current.add(url);
      const anchor = document.createElement('a');
      try {
        anchor.href = url; anchor.download = 'evidence.png'; document.body.append(anchor); anchor.click();
      } finally { anchor.remove(); URL.revokeObjectURL(url); urls.current.delete(url); }
      setNotice('Normalized private copy downloaded. Previously downloaded copies cannot be recalled.');
    } catch (failure) {
      if (current(token)) {
        if (denied(failure) || failure instanceof ApiError && failure.code === 'INVALID_EVIDENCE_RESPONSE') deny();
        else setError(errorMessage(failure));
      }
    } finally {
      requests.current.delete(controller); sending.current = false;
      if (current(token)) { setBusy(false); onLockChange?.(pending.current !== null); }
    }
  };

  return <section className="card evidence-card" aria-label="Private source evidence">
    <div className="card-heading"><span className="card-icon"><Icon name="lock" /></span><div><h3>Private evidence</h3><p>Optional JPEG or PNG, up to 5 MiB each. The server permits two objects per immutable revision.</p></div></div>
    <div className="card-body">
      <p className="card-note">Text delivery is separate. Images remain private and are never included in recipient feeds or maps. Uploading does not queue or confirm validation.</p>
      <p className="card-note">Only references received during this source view appear here. Earlier uploads are not listed.</p>
      {error && <div tabIndex={-1} ref={errorBox}><Notice tone={uncertain ? 'warning' : 'error'}>{error}</Notice></div>}
      {notice && <Notice>{notice}</Notice>}
      {uncertain && <Notice tone="warning"><strong>Upload result not yet confirmed.</strong><p>The same captured file bytes and operation reference are retained in memory. Retry without selecting another file.</p></Notice>}
      {canUpload && !blocked ? <div className="evidence-upload">
        <label className="field"><span>Private evidence image</span><input ref={input} type="file" accept="image/jpeg,image/png" aria-label="Private evidence image"
          disabled={locked || references.length >= 2} onChange={event => { if (!locked && !pending.current) { setSelected(event.target.files?.[0] ?? null); setError(''); setNotice(''); } }} /></label>
        <button className="button secondary" disabled={busy || !uncertain && !selected || references.length >= 2} onClick={() => void send()}>
          {busy ? 'Checking private evidence…' : uncertain ? 'Retry same private upload' : 'Upload private image'}
        </button>
      </div> : !blocked && <p className="card-note">New evidence can only be uploaded by the author to the current source revision. No evidence references are requested automatically.</p>}
      {references.map((row, index) => <section className="evidence-item" key={row.receipt.id} aria-label={`Private image ${index + 1}`}>
        <div><h4>Private image {index + 1}</h4>
          <p>{row.status?.can_download ? 'Current validation permits a normalized private copy.' :
            row.status?.state === 'REJECTED_PRIVATE' ? 'Validation did not accept this private image. No download is available.' :
            'Quarantined or validation not confirmed. No download is available.'}</p></div>
        <div className="button-row"><button className="button secondary small" disabled={locked || blocked} onClick={() => void refresh(row.receipt.id)}>Refresh private image {index + 1} status</button>
          {row.status?.can_download && <button className="button secondary small" disabled={locked || blocked} onClick={() => void download(row.receipt.id)}>Download normalized private image {index + 1}</button>}</div>
      </section>)}
    </div>
  </section>;
}
