import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { api, ApiError, errorMessage } from '../api';
import { BackButton, EmptyState, Loading, MetricCard, Modal, Notice, Pagination, SectionHeading } from '../components';
import { eligibleChannels, roleLabel, validateAccount } from '../domain';
import { Icon } from '../icons';
import Governance from '../Governance';
import OperationsHealth from '../OperationsHealth';
import type { AccountFields, AdminContext, AdminFilters, AdminUser, PageResult, Role, User } from '../types';

const ROLES: Role[] = ['submitter', 'reviewer', 'recipient', 'administrator'];
const emptyFields = (): AccountFields => ({ display_name: '', role: 'submitter', is_active: true, unit_id: null, channel_id: null });
const emptyPage: PageResult<AdminUser> = { results: [], count: 0, page: 1, page_size: 10, total_pages: 1 };
type Editor = { mode: 'create' } | { mode: 'edit' | 'password'; target: AdminUser };

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] ?? '?') + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase();
}

function permissionText(role: Role): string {
  switch (role) {
    case 'submitter': return 'Submit private reports and correct returned reports in the assigned source unit.';
    case 'reviewer': return 'Read and review other authors’ reports in the assigned unit; explicitly approve sharing to its eligible channel.';
    case 'recipient': return 'Read approved reduced publications in the assigned channel.';
    case 'administrator': return 'Manage accounts and permissions in this organization. This role does not grant report or publication access.';
  }
}

export default function Administration({ user, active: panelActive = true, onWriteLockChange }: { user: User; active?: boolean; onWriteLockChange: (locked: boolean) => void }) {
  const [filters, setFilters] = useState<AdminFilters>({ q: '', role: 'ALL', active: 'ALL', page: 1, page_size: 10 });
  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState<AdminFilters['role']>('ALL');
  const [activeFilter, setActiveFilter] = useState<AdminFilters['active']>('ALL');
  const [data, setData] = useState<PageResult<AdminUser>>(emptyPage);
  const [context, setContext] = useState<AdminContext | null>(null);
  const [governanceLocked, setGovernanceLocked] = useState(false);
  const governanceLock = useCallback((locked: boolean) => { setGovernanceLocked(locked); onWriteLockChange(locked); }, [onWriteLockChange]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [editor, setEditor] = useState<Editor | null>(null);
  const [fields, setFields] = useState<AccountFields>(emptyFields);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState('');
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [reconcile, setReconcile] = useState(false);
  const sequence = useRef(0);
  const alive = useRef(true);
  const inFlight = useRef(false);
  const formHeading = useRef<HTMLDivElement>(null);
  const errorSummary = useRef<HTMLDivElement>(null);

  const refresh = useCallback(async () => {
    const current = ++sequence.current;
    setLoading(true); setError('');
    try {
      const [accounts, scopes] = await Promise.all([api.users(filters), api.administrationContext()]);
      if (current !== sequence.current) return;
      setData(accounts); setContext(scopes);
    } catch (failure) {
      if (current !== sequence.current) return;
      setData(emptyPage); setContext(null); setError(errorMessage(failure));
    } finally { if (current === sequence.current) setLoading(false); }
  }, [filters]);
  useEffect(() => { alive.current = true; return () => { alive.current = false; sequence.current++; }; }, []);
  useEffect(() => { void refresh(); return () => { sequence.current++; }; }, [refresh]);
  useEffect(() => { if (formError || Object.keys(fieldErrors).length) errorSummary.current?.focus(); }, [formError, fieldErrors]);
  useEffect(() => { if (editor) formHeading.current?.focus(); }, [editor]);

  const clearSecret = () => { setPassword(''); setConfirmPassword(''); };
  const begin = (next: Editor) => {
    if (inFlight.current || reconcile || next.mode !== 'create' && next.target.id === user.id) return;
    setEditor(next); setUsername(next.mode === 'create' ? '' : next.target.username);
    setFields(next.mode === 'create' ? emptyFields() : { display_name: next.target.display_name, role: next.target.role, is_active: next.target.is_active, unit_id: next.target.unit_id, channel_id: next.target.channel_id });
    clearSecret(); setFieldErrors({}); setFormError(''); setMessage(''); setConfirming(false);
  };
  const closeEditor = () => { if (inFlight.current || reconcile) return; clearSecret(); setEditor(null); setFieldErrors({}); setFormError(''); };
  const changeRole = (role: Role) => setFields(current => ({ ...current, role, unit_id: null, channel_id: null }));
  const changeUnit = (unit_id: string) => {
    const channels = context ? eligibleChannels(context, unit_id) : [];
    setFields(current => ({ ...current, unit_id: unit_id || null, channel_id: channels.length === 1 ? channels[0].id : null }));
  };
  const requestConfirmation = (event: FormEvent) => {
    event.preventDefault();
    if (!editor || !context || inFlight.current || reconcile) return;
    const errors = editor.mode === 'password' ? {} : validateAccount(fields, context);
    if (editor.mode === 'create' && !username.trim()) errors.username = 'Enter an issued username.';
    if (editor.mode !== 'edit') {
      if (password.length < 12) errors.password = 'Use at least 12 characters.';
      if (password !== confirmPassword) errors.confirm_password = 'The passwords must match.';
    }
    setFieldErrors(errors); setFormError('');
    if (!Object.keys(errors).length) setConfirming(true);
  };
  const closeConfirmation = useCallback(() => { if (!inFlight.current) setConfirming(false); }, []);
  const commit = async () => {
    if (!editor || !context || inFlight.current || reconcile) return;
    inFlight.current = true; setBusy(true); setFormError('');
    try {
      const nextFields = { ...fields, display_name: fields.display_name.trim() };
      const result = editor.mode === 'create'
        ? await api.createUser({ ...nextFields, username: username.trim(), password })
        : editor.mode === 'password'
          ? await api.resetUserPassword(editor.target.id, { password, expected_permission_version: editor.target.permission_version })
          : await api.updateUser(editor.target.id, { ...nextFields, expected_permission_version: editor.target.permission_version });
      if (!alive.current) return;
      setMessage(editor.mode === 'create' ? `Account ${result.username} created. Share its credentials through your approved private process.` : editor.mode === 'password' ? `Password reset for ${result.username}. Existing sessions have been invalidated.` : `Access updated for ${result.username}. Existing sessions have been invalidated.`);
      setEditor(null); setReconcile(false); void refresh();
    } catch (failure) {
      if (!alive.current) return;
      const unconfirmed = failure instanceof ApiError && failure.uncertain;
      const stale = failure instanceof ApiError && failure.status === 409;
      setReconcile(unconfirmed || stale);
      setFormError(unconfirmed ? 'The server result could not be confirmed. Reload accounts and check the current record before making another change. Do not create a replacement account to retry this request.' : stale ? 'This account changed after you opened it. Reload accounts and review its current permissions before making another change.' : errorMessage(failure));
      if (failure instanceof ApiError && !unconfirmed && !stale) setFieldErrors(failure.fields);
    } finally {
      inFlight.current = false;
      if (alive.current) { clearSecret(); setBusy(false); setConfirming(false); }
    }
  };
  const reloadForReconciliation = () => {
    if (inFlight.current) return;
    const lookup = username.trim();
    clearSecret(); setReconcile(false); setEditor(null); setFormError(''); setSearch(lookup); setRoleFilter('ALL'); setActiveFilter('ALL');
    setMessage('Accounts reloaded for reconciliation. Check the account and its permission version before another change. A password is never returned by the server.');
    setFilters({ ...filters, q: lookup, role: 'ALL', active: 'ALL', page: 1 });
  };
  const scopeLabel = (account: Pick<AdminUser, 'unit_id' | 'channel_id' | 'role'>) => {
    if (!context) return 'Unavailable';
    if (account.role === 'administrator') return 'Organization accounts';
    return [context.units.find(unit => unit.id === account.unit_id)?.code, context.channels.find(channel => channel.id === account.channel_id)?.code].filter(Boolean).join(' · ') || 'No current assignment';
  };
  const shown = data.results.length;
  const active = data.results.filter(account => account.is_active).length;
  const fieldError = (name: string) => fieldErrors[name] ? <span className="field-error" id={`account-${name}-error`}>{fieldErrors[name]}</span> : null;
  const invalid = (name: string) => ({ 'aria-invalid': !!fieldErrors[name], 'aria-describedby': fieldErrors[name] ? `account-${name}-error` : undefined });

  return <>
    {panelActive && !editor && context && Array.isArray(context.authorities) && context.authorities.some(value => value === 'POLICY' || value === 'INTEGRATION') && <Governance user={user} context={context} onWriteLockChange={governanceLock} />}
    <div className="admin-stack" inert={confirming || governanceLocked} aria-hidden={confirming || governanceLocked ? true : undefined}>
      {editor ? <>
        <BackButton onClick={closeEditor}>Back to accounts</BackButton>
        <div ref={formHeading} tabIndex={-1}><SectionHeading eyebrow="ACCOUNT ADMINISTRATION" title={editor.mode === 'create' ? 'Create account' : editor.mode === 'password' ? `Reset password for ${username}` : `Manage ${username}`} text={editor.mode === 'password' ? 'Set a new password and invalidate this account’s existing sessions.' : 'Choose the exact role and assignment this account needs.'} /></div>
        <div className="admin-editor-layout"><form className="card account-form" onSubmit={requestConfirmation} noValidate>
          <div className="card-heading"><span className="card-icon"><Icon name="lock" /></span><div><h3>{editor.mode === 'password' ? 'New credentials' : 'Account details'}</h3><p>{editor.mode === 'create' ? 'Create an account in your organization' : `Current permission version ${editor.target.permission_version}`}</p></div></div>
          {(formError || Object.keys(fieldErrors).length > 0) && <div tabIndex={-1} ref={errorSummary} className="account-errors"><Notice tone={reconcile ? 'warning' : 'error'}>{formError || 'Check the highlighted account fields.'}</Notice>{reconcile && <button type="button" className="button secondary" onClick={reloadForReconciliation}><Icon name="refresh" />Reload accounts</button>}</div>}
          <fieldset disabled={busy || reconcile}><legend className="sr-only">Account settings</legend><div className="form-grid">
            {editor.mode !== 'password' && <>
              <label className="field"><span>Username</span><input value={username} onChange={event => setUsername(event.target.value)} readOnly={editor.mode !== 'create'} autoComplete="off" autoCapitalize="none" spellCheck={false} maxLength={150} {...invalid('username')} /><span className="field-hint">Usernames stay fixed after account creation.</span>{fieldError('username')}</label>
              <label className="field"><span>Display name</span><input value={fields.display_name} onChange={event => setFields({ ...fields, display_name: event.target.value })} maxLength={120} autoComplete="off" {...invalid('display_name')} />{fieldError('display_name')}</label>
              <label className="field full"><span>Role</span><select value={fields.role} onChange={event => changeRole(event.target.value as Role)} {...invalid('role')}>{ROLES.map(role => <option key={role} value={role}>{roleLabel(role)}</option>)}</select>{fieldError('role')}</label>
              {(fields.role === 'submitter' || fields.role === 'reviewer') && <><label className="field"><span>Source unit</span><select value={fields.unit_id ?? ''} onChange={event => changeUnit(event.target.value)} {...invalid('unit_id')}><option value="">Choose a source unit</option>{context?.units.filter(unit => unit.active).map(unit => <option value={unit.id} key={unit.id}>{unit.code} · {unit.name}</option>)}</select>{fieldError('unit_id')}</label><div className="field"><span>Eligible sharing channel</span><div className="assignment-display">{context?.channels.find(channel => channel.id === fields.channel_id)?.code ?? 'Choose an eligible source unit'}</div>{fieldError('channel_id')}<span className="field-hint">The unit must have one eligible active channel.</span></div></>}
              {fields.role === 'recipient' && <label className="field full"><span>Recipient channel</span><select value={fields.channel_id ?? ''} onChange={event => setFields({ ...fields, channel_id: event.target.value || null, unit_id: null })} {...invalid('channel_id')}><option value="">Choose a recipient channel</option>{context?.channels.filter(channel => channel.active).map(channel => <option value={channel.id} key={channel.id}>{channel.code} · {channel.name}</option>)}</select>{fieldError('channel_id')}</label>}
              <label className="checkbox-field full"><input type="checkbox" checked={fields.is_active} onChange={event => setFields({ ...fields, is_active: event.target.checked })} /><span><strong>Account active</strong><span className="field-hint">Inactive accounts cannot sign in.</span></span></label>
            </>}
            {editor.mode !== 'edit' && <><label className="field"><span>Password</span><input type="password" value={password} onChange={event => setPassword(event.target.value)} autoComplete="new-password" minLength={12} maxLength={128} {...invalid('password')} /><span className="field-hint">At least 12 characters. The server checks password suitability.</span>{fieldError('password')}</label><label className="field"><span>Confirm password</span><input type="password" value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} autoComplete="new-password" maxLength={128} {...invalid('confirm_password')} />{fieldError('confirm_password')}</label></>}
          </div></fieldset>
          <div className="form-footer"><p><Icon name="shield" size={16} />{editor.mode === 'create' ? 'Review the account and permissions before creation.' : 'Saving invalidates this account’s existing sessions.'}</p><div className="button-row"><button type="button" className="button secondary" disabled={busy || reconcile} onClick={closeEditor}>Cancel</button><button className="button primary" disabled={busy || reconcile || !context}>{editor.mode === 'create' ? 'Create account' : editor.mode === 'password' ? 'Review password reset' : 'Review changes'}<Icon name="arrow" /></button></div></div>
        </form><aside className="card permissions-card"><span className="card-icon"><Icon name="shield" /></span><h3>{editor.mode === 'password' ? 'Password reset' : 'Selected permissions'}</h3><strong>{roleLabel(fields.role)}</strong><p>{permissionText(fields.role)}</p>{editor.mode !== 'password' && <dl><dt>Assignment</dt><dd>{scopeLabel(fields)}</dd><dt>Sign-in access</dt><dd>{fields.is_active ? 'Active' : 'Inactive'}</dd></dl>}<div className="permission-note"><Icon name="lock" size={17} /><p>{editor.mode === 'password' ? 'The new password is sent only when you confirm. It is never displayed in account lists.' : 'Changing the role replaces current assignments. Prior membership history remains intact.'}</p></div></aside></div>
      </> : <>
        <SectionHeading hero eyebrow="ORGANIZATION WORKSPACE" title="Administration" text="Issue accounts and keep each person’s role and scope clear. Report submission, human review and approved publications remain separate roles." meta={<><span><Icon name="users" size={14} />Accounts &amp; permissions</span><span>Separate from report review</span></>} action={<button className="button primary" disabled={loading || !context} onClick={() => begin({ mode: 'create' })}><Icon name="plus" />Create account</button>} />
        <div className="metrics-grid"><MetricCard label="Accounts" value={data.count} detail="Matching the current filters" icon="users" /><MetricCard label="Active" value={active} detail={`Of ${shown} shown on this page`} icon="check" share={{ value: active, of: shown, label: `${active} of ${shown} accounts on this page are active` }} /><MetricCard label="Inactive" value={shown - active} detail={`Of ${shown} shown on this page`} icon="lock" tone="amber" share={{ value: shown - active, of: shown, label: `${shown - active} of ${shown} accounts on this page are inactive` }} /><div className="metric-card tone-blue"><div className="metric-top"><span>Roles on this page</span><span className="metric-icon blue"><Icon name="shield" /></span></div><div className="role-breakdown">{ROLES.map(role => <span key={role} className={'role-chip role-' + role}>{role[0].toUpperCase() + role.slice(1)} · {data.results.filter(account => account.role === role).length}</span>)}</div></div></div>
        {message && <Notice tone="info">{message}</Notice>}
        {panelActive && <OperationsHealth />}
        <section className="card accounts-card"><div className="card-heading"><div><h3>Accounts & permissions</h3><p>{data.count} matching accounts in your organization</p></div><button className="button secondary small" onClick={() => void refresh()} disabled={loading}><Icon name="refresh" size={16} />Refresh</button></div>
          <form className="account-filters" onSubmit={event => { event.preventDefault(); setFilters({ ...filters, q: search.trim(), role: roleFilter, active: activeFilter, page: 1 }); }}><div className="filter-controls"><label className="field account-search"><span>Search accounts</span><input type="search" placeholder="Username or display name" value={search} maxLength={150} onChange={event => setSearch(event.target.value)} /></label><label className="field"><span>Account role</span><select value={roleFilter} onChange={event => setRoleFilter(event.target.value as AdminFilters['role'])}><option value="ALL">All roles</option>{ROLES.map(role => <option key={role} value={role}>{roleLabel(role)}</option>)}</select></label><label className="field"><span>Account status</span><select value={activeFilter} onChange={event => setActiveFilter(event.target.value as AdminFilters['active'])}><option value="ALL">All accounts</option><option value="true">Active</option><option value="false">Inactive</option></select></label><button className="button secondary" disabled={loading}>Apply filters</button></div></form>
          {error && <Notice tone="error">{error}</Notice>}{loading ? <Loading rows={5} text="Loading authorized accounts…" /> : !error && (data.results.length ? <div className="table-scroll"><table className="report-table account-table"><thead><tr><th>Account</th><th>Role & scope</th><th>Status</th><th>Permissions</th><th>Actions</th></tr></thead><tbody>{data.results.map(account => <tr key={account.id}><td><div className="account-cell"><span className="account-avatar" aria-hidden="true">{initials(account.display_name)}</span><div><strong>{account.display_name}</strong><span className="cell-sub">{account.username}{account.id === user.id ? ' · You' : ''}</span></div></div></td><td><span className={'role-chip role-' + account.role}>{roleLabel(account.role)}</span><span className="cell-sub">{scopeLabel(account)}</span></td><td><span className={'status-badge ' + (account.is_active ? 'status-approved' : 'status-rejected')}><span className="status-dot" />{account.is_active ? 'Active' : 'Inactive'}</span></td><td className="muted">Version {account.permission_version}</td><td><div className="account-actions"><button className="button secondary small" aria-label={`Manage ${account.username}`} disabled={account.id === user.id} onClick={() => begin({ mode: 'edit', target: account })}>Manage</button><button className="button secondary small" aria-label={`Reset password for ${account.username}`} disabled={account.id === user.id} onClick={() => begin({ mode: 'password', target: account })}>Reset password</button></div>{account.id === user.id && <span className="cell-sub">Another administrator manages your account.</span>}</td></tr>)}</tbody></table></div> : <EmptyState icon="lock" title="No matching accounts" text="Try a different name, role or account status." />)}
          {!error && <Pagination data={data} busy={loading} onPage={page => setFilters({ ...filters, page })} onPageSize={page_size => setFilters({ ...filters, page_size, page: 1 })} />}
        </section>
      </>}
    </div>
    {confirming && editor && <Modal title={editor.mode === 'create' ? 'Confirm account creation' : editor.mode === 'password' ? 'Confirm password reset' : 'Confirm account changes'} onClose={closeConfirmation} locked={busy}>
      <p className="modal-intro">{editor.mode === 'create' ? 'Create this account with the permissions shown below.' : editor.mode === 'password' ? 'Replace the password and sign this account out of every existing session.' : 'Apply these permissions and sign this account out of every existing session.'}</p>
      <dl className="confirmation-account"><div><dt>Account</dt><dd>{username}</dd></div>{editor.mode === 'edit' && <div><dt>Current access</dt><dd>{roleLabel(editor.target.role)} · {scopeLabel(editor.target)} · {editor.target.is_active ? 'Active' : 'Inactive'}</dd></div>}{editor.mode !== 'password' && <><div><dt>{editor.mode === 'create' ? 'Role' : 'New role'}</dt><dd>{roleLabel(fields.role)}</dd></div><div><dt>Assignment</dt><dd>{scopeLabel(fields)}</dd></div><div><dt>Account status</dt><dd>{fields.is_active ? 'Active' : 'Inactive'}</dd></div></>}</dl>
      <Notice tone={editor.mode === 'password' || !fields.is_active ? 'warning' : 'info'}>{editor.mode === 'password' ? 'The account must use its new password to sign in again.' : permissionText(fields.role)}</Notice>
      <div className="modal-footer"><button className="button secondary" disabled={busy} onClick={closeConfirmation}>Cancel</button><button className="button primary" disabled={busy} onClick={() => void commit()}>{busy ? 'Saving…' : editor.mode === 'create' ? 'Confirm account creation' : editor.mode === 'password' ? 'Reset password' : 'Save account changes'}<Icon name="check" /></button></div>
    </Modal>}
  </>;
}
