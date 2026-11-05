import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError } from '../api';
import { EmptyState, Loading, Modal, Notice } from '../components';
import { dateLabel } from '../domain';
import { Icon } from '../icons';
import type { EnrolledDevice, EnrolledDevices as DeviceList } from '../types';

// The workspace remounts on account/session changes. A local request generation
// additionally fences replies after navigation, reload, or a newer operation.
export default function EnrolledDevices({ disabled, onLockChange }: { disabled: boolean; onLockChange: (locked: boolean) => void }) {
  const [devices, setDevices] = useState<DeviceList | null>(null);
  const [loading, setLoading] = useState(true);
  const [revoking, setRevoking] = useState(false);
  const [selected, setSelected] = useState<EnrolledDevice | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState<{ text: string; confirmed: boolean } | null>(null);
  const alive = useRef(false);
  const generation = useRef(0);
  const writing = useRef(false);
  const uncertainId = useRef<string | null>(null);
  const feedback = useRef<HTMLDivElement>(null);
  const lastFeedback = useRef({ error, notice });
  const confirmationTrigger = useRef<HTMLButtonElement | null>(null);
  const restoreConfirmationFocus = useRef(false);
  useEffect(() => { onLockChange(selected !== null || revoking); return () => onLockChange(false); }, [selected, revoking, onLockChange]);
  useEffect(() => {
    const changed = lastFeedback.current.error !== error || lastFeedback.current.notice !== notice;
    lastFeedback.current = { error, notice };
    // Either confirmation owns focus while open. Consume a background update
    // without replaying its focus change when the modal restores its trigger.
    if (changed && !disabled && selected === null && !revoking && (error || notice)) feedback.current?.focus();
  }, [error, notice, disabled, selected, revoking]);
  useEffect(() => {
    // The selected state disables its own trigger before Modal's mount effect.
    // Cancellation restores the captured button after the enabled DOM commits.
    if (restoreConfirmationFocus.current && selected === null && !revoking && !disabled) {
      restoreConfirmationFocus.current = false;
      const target = confirmationTrigger.current; confirmationTrigger.current = null;
      if (target?.isConnected && !target.disabled) target.focus();
    }
  }, [selected, revoking, disabled]);

  const reload = useCallback(async () => {
    if (!alive.current || writing.current) return;
    const ticket = ++generation.current;
    setDevices(null); setSelected(null); setError(''); setLoading(true);
    try {
      const result = await api.devices();
      if (!alive.current || ticket !== generation.current) return;
      if (uncertainId.current) {
        const reconciled = result.results.find(device => device.id === uncertainId.current);
        if (reconciled?.revoked_at) {
          uncertainId.current = null;
          setNotice({ text: 'The refreshed server list confirms this enrollment is revoked.', confirmed: true });
        } else if (reconciled) {
          uncertainId.current = null;
          setNotice({ text: 'The server currently lists this enrollment as not revoked. To send a new revocation request, review and confirm it again.', confirmed: false });
        } else {
          setNotice({ text: 'The revocation result is still unconfirmed. This enrollment was absent from the refreshed list. Refresh again to check its status.', confirmed: false });
        }
      }
      setDevices(result);
    } catch {
      if (alive.current && ticket === generation.current) {
        // Do not echo server errors or retain an earlier owner's device list.
        setDevices(null);
        setError('The device list is unavailable or could not be verified. Refresh devices to check again.');
      }
    } finally { if (alive.current && ticket === generation.current) setLoading(false); }
  }, []);

  useEffect(() => {
    alive.current = true; void reload();
    return () => { alive.current = false; generation.current++; uncertainId.current = null; };
  }, [reload]);

  const cancel = useCallback(() => {
    if (!writing.current) { restoreConfirmationFocus.current = true; setSelected(null); }
  }, []);
  const revoke = async () => {
    if (!selected || selected.revoked_at || writing.current || disabled || uncertainId.current) return;
    confirmationTrigger.current = null; restoreConfirmationFocus.current = false;
    const targetId = selected.id;
    const ticket = ++generation.current;
    writing.current = true; setRevoking(true); setDevices(null); setError(''); setNotice(null);
    let confirmed = false;
    try {
      await api.revokeDevice(targetId);
      if (!alive.current || ticket !== generation.current) return;
      confirmed = true;
      setNotice({ text: 'Revocation confirmed. This enrollment can no longer connect to the server. Other enrollments and this browser session are unchanged.', confirmed: true });
    } catch (failure) {
      if (!alive.current || ticket !== generation.current) return;
      if (!(failure instanceof ApiError) || failure.uncertain) {
        uncertainId.current = targetId;
        setNotice({ text: 'The revocation result is unconfirmed. No request will be repeated automatically. Refresh devices to check the server state before trying again.', confirmed: false });
      } else {
        setError('The revocation request was not accepted. Refresh devices to check your current access and device status.');
      }
    } finally {
      writing.current = false;
      if (alive.current && ticket === generation.current) { setRevoking(false); setSelected(null); }
    }
    // Only a confirmed mutation triggers a safe list refresh. Uncertain writes
    // require an explicit read; neither branch automatically repeats the POST.
    if (confirmed && alive.current && ticket === generation.current) await reload();
  };

  return <section className="card" aria-labelledby="enrolled-devices-title">
    <div className="card-heading"><span className="card-icon"><Icon name="shield" /></span><div><h3 id="enrolled-devices-title">Your mobile devices</h3><p>Enrollments belonging to your current account.</p></div></div>
    <div className="card-body">
      <p className="card-note">Revoke a lost or unused phone without having it with you. Revocation blocks future server access for that enrollment. It does not erase the phone or immediately lock data while it is offline.</p>
      <p className="field-hint">Labels are supplied during enrollment and do not verify a physical phone. “Not revoked” does not guarantee current sign-in or report permissions.</p>
      <div className="button-row"><button className="button secondary" onClick={() => void reload()} disabled={disabled || revoking || loading || selected !== null}><Icon name="refresh" size={16} />Refresh devices</button></div>
    </div>
    {(error || notice) && <div ref={feedback} tabIndex={-1}>{error && <Notice tone="error">{error}</Notice>}{notice && <Notice tone={notice.confirmed ? 'success' : 'warning'}>{notice.text}</Notice>}</div>}
    {loading && <Loading text="Checking your mobile enrollments…" />}
    {!loading && devices?.count === 0 && <EmptyState title="No mobile enrollments" text="No mobile device is enrolled to this account." icon="lock" />}
    {!loading && devices && devices.count > 0 && <>
      <p className="security-scope-note">{devices.count} {devices.count === 1 ? 'enrollment' : 'enrollments'}, including revoked history.</p>
      {devices.results.map(device => <article className="device-item" key={device.id} aria-label={`Mobile enrollment ${device.label}`}>
        <dl className="detail-fields">
          <div className="full"><dt>Device label</dt><dd>{device.label}</dd></div>
          <div className="full"><dt>Enrollment reference</dt><dd className="mono">{device.id}</dd></div>
          <div><dt>Enrolled</dt><dd>{dateLabel(device.created_at, true)}</dd></div>
          <div><dt>Last authenticated</dt><dd>{dateLabel(device.last_authenticated_at, true)}</dd></div>
          <div><dt>Status</dt><dd><span className={'status-badge ' + (device.revoked_at ? 'status-rejected' : 'status-approved')}><span className="status-dot" />{device.revoked_at ? 'Revoked' : 'Not revoked'}</span></dd></div>
          {device.revoked_at && <div><dt>Revoked at</dt><dd>{dateLabel(device.revoked_at, true)}</dd></div>}
          {!device.revoked_at && <div className="full"><dt className="sr-only">Action</dt><dd><button className="button secondary" onClick={event => { confirmationTrigger.current = event.currentTarget; restoreConfirmationFocus.current = false; setSelected(device); }} disabled={disabled || revoking || selected !== null || uncertainId.current !== null} aria-label={`Review revocation for ${device.label}`}>Review revocation</button></dd></div>}
        </dl>
      </article>)}
    </>}
    {selected && <Modal title="Revoke mobile enrollment?" onClose={cancel} locked={revoking}>
      <p>Revoke <strong>{selected.label}</strong> for your account?</p>
      <dl className="detail-fields"><div className="full"><dt>Enrollment reference</dt><dd>{selected.id}</dd></div></dl>
      <p>This enrollment cannot be reactivated. Its server sessions will end; other enrollments and this browser session stay unchanged. Existing report history is retained.</p>
      <p>This does not erase a disconnected phone. Its protected offline access remains subject to the app’s existing lock and lease limits.</p>
      <div className="button-row modal-actions"><button className="button secondary" onClick={cancel} disabled={revoking}>Cancel</button><button className="button primary" onClick={() => void revoke()} disabled={revoking}>{revoking ? 'Revoking enrollment…' : 'Revoke enrollment'}</button></div>
    </Modal>}
  </section>;
}
