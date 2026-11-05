import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError } from '../api';
import { Modal, Notice, SectionHeading } from '../components';
import { profileLabel, roleLabel, validatePasswordChange } from '../domain';
import { Icon } from '../icons';
import type { User } from '../types';
import EnrolledDevices from './EnrolledDevices';

export default function AccountSecurity({ user, onReauthenticate }: { user: User; onReauthenticate: (message: string) => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState('');
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [deviceAction, setDeviceAction] = useState(false);
  const inFlight = useRef(false);
  const alive = useRef(true);
  const message = useRef<HTMLDivElement>(null);
  const confirmationTrigger = useRef<HTMLElement | null>(null);
  const restoreConfirmationFocus = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => { if (error || Object.keys(errors).length) message.current?.focus(); }, [error, errors]);
  useEffect(() => {
    // Opening disables the fieldset before Modal's effect can capture its trigger.
    // Restore the earlier element only after cancellation has enabled it again.
    if (restoreConfirmationFocus.current && !confirming && !busy && !deviceAction) {
      restoreConfirmationFocus.current = false;
      const target = confirmationTrigger.current; confirmationTrigger.current = null;
      if (target?.isConnected && !target.matches(':disabled')) target.focus();
    }
  }, [confirming, busy, deviceAction]);
  const cancel = useCallback(() => {
    if (!inFlight.current) { restoreConfirmationFocus.current = true; setConfirming(false); }
  }, []);
  const change = async () => {
    if (inFlight.current) return;
    confirmationTrigger.current = null; restoreConfirmationFocus.current = false;
    inFlight.current = true; setBusy(true); setError(''); setErrors({});
    const body = { current_password: current, new_password: next };
    // The frozen request exists only for this attempt; no retry copy is retained.
    setCurrent(''); setNext(''); setConfirmation('');
    try {
      await api.changePassword(body);
      onReauthenticate('Your password changed. All existing sessions have ended. Sign in with your new password.');
    } catch (failure) {
      if (!(failure instanceof ApiError) || failure.uncertain) {
        onReauthenticate('The password change could not be confirmed. The private workspace was cleared. Sign in to reconcile your account; try the new password first.');
      } else if (alive.current) {
        // Deliberately do not echo server field values or retain attempted credentials.
        setError(failure.status === 400 ? 'The password change was not accepted. Check your current password and choose a suitable different password, then enter the fields again.' : 'The password change was not accepted. Refresh your session and enter the fields again.');
      }
    } finally {
      body.current_password = ''; body.new_password = '';
      inFlight.current = false;
      if (alive.current) { setBusy(false); setConfirming(false); }
    }
  };
  return <>
    <SectionHeading eyebrow="YOUR ACCOUNT" title="Account security" text="Manage your password and the mobile enrollments for your issued account." />
    <div className="security-layout">
      <section className="card account-context"><div className="card-heading"><span className="card-icon"><Icon name="shield" /></span><div><h3>Issued account</h3><p>Current account and permissions</p></div></div><dl className="detail-fields"><div><dt>Username</dt><dd>{user.username}</dd></div><div><dt>Display name</dt><dd>{user.display_name}</dd></div><div className="full"><dt>Role</dt><dd>{roleLabel(user.role)}</dd></div><div className="full"><dt>Source unit</dt><dd>{user.unit ? `${user.unit.code} · ${user.unit.name}` : 'No source-unit assignment'}</dd></div><div className="full"><dt>Channel</dt><dd>{user.channel ? `${user.channel.code} · ${user.channel.name}` : 'No channel assignment'}</dd></div>{user.role !== 'administrator' && <div className="full"><dt>Disclosure profile</dt><dd>{profileLabel(user.profile)}</dd></div>}</dl><p className="security-scope-note">Account and assignment changes are managed separately by an account administrator.</p></section>
      <section className="card security-form-card"><div className="card-heading"><span className="card-icon"><Icon name="lock" /></span><div><h3>Change your password</h3><p>Use a different password of 12–128 characters.</p></div></div>
        <Notice>Changing your password ends every existing session, including this one. You will need to sign in again.</Notice>
        <form noValidate onSubmit={event => { event.preventDefault(); if (inFlight.current || deviceAction) return; setError(''); const issues = validatePasswordChange(current, next, confirmation); setErrors(issues); if (!Object.keys(issues).length) { confirmationTrigger.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; restoreConfirmationFocus.current = false; setConfirming(true); } }}>
          {(error || Object.keys(errors).length > 0) && <div ref={message} tabIndex={-1}><Notice tone="error">{error || 'Check the password fields below.'}</Notice></div>}
          <fieldset disabled={busy || confirming || deviceAction}><legend className="sr-only">Your password change</legend>
            <label className="field" htmlFor="security-current-password"><span>Current password</span><input id="security-current-password" type="password" autoComplete="current-password" value={current} onChange={event => setCurrent(event.target.value)} maxLength={128} aria-invalid={!!errors.current_password} aria-describedby={errors.current_password ? 'security-current-error' : undefined} /></label>{errors.current_password && <p id="security-current-error" className="field-error">{errors.current_password}</p>}
            <label className="field" htmlFor="security-new-password"><span>New password</span><input id="security-new-password" type="password" autoComplete="new-password" value={next} onChange={event => setNext(event.target.value)} maxLength={128} aria-invalid={!!errors.new_password} aria-describedby={errors.new_password ? 'security-new-error' : 'security-password-hint'} /></label><p id="security-password-hint" className="field-hint">Avoid common passwords and your account details. Spaces are preserved.</p>{errors.new_password && <p id="security-new-error" className="field-error">{errors.new_password}</p>}
            <label className="field" htmlFor="security-confirm-password"><span>Confirm new password</span><input id="security-confirm-password" type="password" autoComplete="new-password" value={confirmation} onChange={event => setConfirmation(event.target.value)} maxLength={128} aria-invalid={!!errors.confirmation} aria-describedby={errors.confirmation ? 'security-confirm-error' : undefined} /></label>{errors.confirmation && <p id="security-confirm-error" className="field-error">{errors.confirmation}</p>}
            <button className="button primary" type="submit">Review password change<Icon name="arrow" size={18} /></button>
          </fieldset>
        </form>
      </section>
    </div>
    <EnrolledDevices key={user.id} disabled={busy || confirming} onLockChange={setDeviceAction} />
    {confirming && <Modal title="Confirm password change" onClose={cancel} locked={busy}><p>Change the password for <strong>{user.username}</strong>? All existing sessions will end and this workspace will be cleared.</p><p>After confirmation, enter your new password on the sign-in screen.</p><div className="button-row modal-actions"><button className="button secondary" onClick={cancel} disabled={busy}>Cancel</button><button className="button primary" onClick={() => void change()} disabled={busy}>{busy ? 'Changing password…' : 'Change password'}</button></div></Modal>}
  </>;
}
