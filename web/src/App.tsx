import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { api, ApiError, clearApiMemory, errorMessage, isBackendUnavailable } from './api';
import { Loading, Notice } from './components';
import { accessSignature, profileLabel, roleLabel } from './domain';
import { Icon } from './icons';
import type { IconName } from './icons';
import type { User } from './types';
import Submitter from './views/Submitter';
import Reviewer from './views/Reviewer';
import Recipient from './views/Recipient';
import Administration from './views/Administration';
import AccountSecurity from './views/AccountSecurity';
import heroImage from './assets/field-command-hero.webp';
import './auth.css';

// `short` labels the mobile tab bar, where each destination has a quarter of a phone's width.
interface NavigationItem { id: string; label: string; short: string; icon: IconName }
const navigation: Record<string, NavigationItem[]> = {
  submitter: [{ id: 'overview', label: 'Overview', short: 'Home', icon: 'overview' }, { id: 'new', label: 'New report', short: 'New', icon: 'plus' }, { id: 'reports', label: 'Your reports', short: 'Reports', icon: 'report' }],
  reviewer: [{ id: 'overview', label: 'Overview', short: 'Home', icon: 'overview' }, { id: 'review', label: 'Review queue', short: 'Queue', icon: 'review' }],
  recipient: [{ id: 'overview', label: 'Overview', short: 'Home', icon: 'overview' }, { id: 'publications', label: 'Publications', short: 'Feed', icon: 'feed' }],
  administrator: [{ id: 'overview', label: 'Administration', short: 'Admin', icon: 'shield' }],
};

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(true);
  const [page, setPage] = useState('overview');
  const [generation, setGeneration] = useState(0);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [mobileNavigation, setMobileNavigation] = useState(() => window.matchMedia('(max-width: 780px)').matches);
  const [authMessage, setAuthMessage] = useState('');
  const [signoutUnconfirmed, setSignoutUnconfirmed] = useState(false);
  const [backendUnavailable, setBackendUnavailable] = useState(false);
  const writeLock = useRef(false);
  const [writeLocked, setWriteLocked] = useState(false);
  const onWriteLockChange = useCallback((locked: boolean) => { writeLock.current = locked; setWriteLocked(locked); }, []);
  const epoch = useRef(0);
  const businessPage = useRef('overview');
  const pageHeading = useRef<HTMLDivElement>(null);
  const sidebar = useRef<HTMLElement>(null);
  const sidebarTrigger = useRef<HTMLButtonElement>(null);
  const closeWorkspace = useCallback((message = '') => {
    onWriteLockChange(false); epoch.current++; businessPage.current = 'overview'; clearApiMemory(); setUser(null); setPage('overview'); setGeneration(value => value + 1); setSidebarOpen(false); setAuthMessage(message); setChecking(false);
  }, [onWriteLockChange]);
  useEffect(() => {
    const media = window.matchMedia('(max-width: 780px)');
    const changed = () => { setMobileNavigation(media.matches); if (!media.matches) setSidebarOpen(false); };
    changed(); media.addEventListener('change', changed);
    return () => media.removeEventListener('change', changed);
  }, []);
  useEffect(() => {
    if (!mobileNavigation || !sidebarOpen || !user) return;
    const previous = document.activeElement as HTMLElement | null;
    const controls = () => [...(sidebar.current?.querySelectorAll<HTMLElement>('button:not([disabled]), a[href], [tabindex="0"]') ?? [])].filter(element => element.getClientRects().length > 0);
    controls()[0]?.focus();
    document.body.classList.add('drawer-open');
    const keyboard = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); setSidebarOpen(false); return; }
      if (event.key !== 'Tab') return;
      const items = controls(); if (!items.length) { event.preventDefault(); return; }
      const first = items[0], last = items[items.length - 1];
      if (!sidebar.current?.contains(document.activeElement)) { event.preventDefault(); first.focus(); }
      else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', keyboard);
    return () => {
      document.body.classList.remove('drawer-open'); document.removeEventListener('keydown', keyboard);
      if (previous?.isConnected) previous.focus(); else sidebarTrigger.current?.focus();
    };
  }, [mobileNavigation, sidebarOpen, user]);
  useEffect(() => {
    const sequence = ++epoch.current;
    api.me().then(response => {
      if (sequence === epoch.current) {
        if (!navigation[response.user.role]) { closeWorkspace('Your issued account does not have a website role.'); return; }
        setBackendUnavailable(false); setUser(response.user); setChecking(false);
      }
    }).catch(failure => {
      if (sequence !== epoch.current) return;
      setChecking(false);
      if (isBackendUnavailable(failure) || !(failure instanceof ApiError && [401, 403].includes(failure.status))) setBackendUnavailable(true);
    });
    const expired = () => closeWorkspace('Your session or access has changed. Sign in to check your current permissions.');
    window.addEventListener('kapit-session-expired', expired);
    return () => { epoch.current++; window.removeEventListener('kapit-session-expired', expired); };
  }, [closeWorkspace]);
  useEffect(() => {
    if (!user) return;
    const checkCurrent = async () => {
      const sequence = epoch.current;
      try {
        const response = await api.me();
        if (sequence !== epoch.current) return;
        const next = response.user;
        if (accessSignature(next) !== accessSignature(user)) {
          closeWorkspace('Your account context changed. Sign in again to reload current permissions.');
        }
      } catch (failure) { if (sequence === epoch.current && failure instanceof ApiError && [401, 403].includes(failure.status)) closeWorkspace('Your session or access ended. Sign in to continue.'); }
    };
    const focus = () => { if (document.visibilityState === 'visible') void checkCurrent(); };
    const interval = window.setInterval(focus, 30_000);
    window.addEventListener('focus', focus); document.addEventListener('visibilitychange', focus);
    return () => { window.clearInterval(interval); window.removeEventListener('focus', focus); document.removeEventListener('visibilitychange', focus); };
  }, [user, closeWorkspace]);
  const authenticated = (next: User) => {
    onWriteLockChange(false); epoch.current++; businessPage.current = 'overview'; setGeneration(value => value + 1); setPage('overview'); setUser(next); setChecking(false); setAuthMessage(''); setSignoutUnconfirmed(false); setBackendUnavailable(false);
  };
  const signOut = async () => {
    // Unmount and clear private views immediately; keep the CSRF secret until the server logout request has used it.
    onWriteLockChange(false); epoch.current++; businessPage.current = 'overview'; setUser(null); setPage('overview'); setGeneration(value => value + 1); setSidebarOpen(false); setChecking(true);
    try { await api.logout(); setAuthMessage('You have signed out. The private workspace has been cleared.'); setSignoutUnconfirmed(false); setBackendUnavailable(false); }
    catch (failure) { setAuthMessage('The private workspace was cleared, but server sign-out could not be confirmed. Reconnect and complete sign-out before leaving this device.'); setSignoutUnconfirmed(true); if (isBackendUnavailable(failure)) setBackendUnavailable(true); }
    finally { clearApiMemory(); setChecking(false); }
  };
  const navigate = (next: string) => { if (writeLock.current) return; if (next !== 'security') businessPage.current = next; setPage(next); setSidebarOpen(false); window.scrollTo({ top: 0, behavior: 'instant' }); window.setTimeout(() => pageHeading.current?.focus(), 0); };

  if (checking) return <div className="auth-loading"><AuthWordmark /><Loading text="Checking your session and current access…" /><span className="auth-chip"><span />Training &amp; evaluation</span></div>;
  if (!user) return <Login onAuthenticated={authenticated} message={authMessage} signoutUnconfirmed={signoutUnconfirmed} onCompleteSignout={() => void signOut()} backendUnavailable={backendUnavailable} onAvailabilityChange={setBackendUnavailable} />;
  const items: NavigationItem[] = [...navigation[user.role], { id: 'security', label: 'Account security', short: 'Account', icon: 'lock' }];
  const workspaceEpoch = epoch.current;
  return <div className="app-shell">
    <a className="skip-link" href="#workspace" inert={mobileNavigation && sidebarOpen}>Skip to workspace</a>
    {mobileNavigation && sidebarOpen && <button className="sidebar-scrim" onClick={() => setSidebarOpen(false)} tabIndex={-1} aria-hidden="true" />}
    <aside className={'sidebar ' + (sidebarOpen ? 'open' : '')} ref={sidebar} inert={mobileNavigation && !sidebarOpen} aria-hidden={mobileNavigation && !sidebarOpen ? true : undefined} role={mobileNavigation && sidebarOpen ? 'dialog' : undefined} aria-modal={mobileNavigation && sidebarOpen ? true : undefined} aria-label={mobileNavigation && sidebarOpen ? 'Workspace menu' : undefined}>
      <div className="sidebar-brand"><Brand /><button className="icon-button sidebar-close" aria-label="Close navigation" onClick={() => setSidebarOpen(false)}><Icon name="close" /></button></div>
      <div className="workspace-label"><span className="workspace-mark" aria-hidden="true">{user.role.slice(0, 1).toUpperCase()}</span><div><strong>{roleLabel(user.role)}</strong><span>{user.role === 'administrator' ? 'Organization accounts' : user.role === 'recipient' ? user.channel?.code ?? 'No current channel' : user.unit?.code ?? 'Assigned source unit'}</span></div></div>
      <p className="nav-section-label">WORKSPACE</p>
      <nav aria-label="Workspace navigation">{items.map(item => <button key={item.id} disabled={writeLocked} className={'nav-item ' + (page === item.id ? 'active' : '')} aria-current={page === item.id ? 'page' : undefined} onClick={() => navigate(item.id)}><Icon name={item.icon} />{item.label}{page === item.id && <span className="nav-active-dot" />}</button>)}</nav>
      <div className="sidebar-bottom"><div className="scope-note"><Icon name="shield" size={20} /><strong>Purposeful sharing.</strong><p>Private originals.<br />Independent review.<br />Approved information.</p></div><div className="sidebar-context"><span className="context-live-dot" />Training use only<span>Local deployment</span></div></div>
    </aside>
    <div className="main-shell" inert={mobileNavigation && sidebarOpen} aria-hidden={mobileNavigation && sidebarOpen ? true : undefined}><header className="topbar"><div className="topbar-left"><button className="icon-button mobile-menu" ref={sidebarTrigger} onClick={() => setSidebarOpen(true)} aria-label="Open navigation" aria-expanded={sidebarOpen}><Icon name="menu" /></button><span className="topbar-breadcrumb">Workspace<Icon name="chevron" size={13} /><strong>{items.find(item => item.id === page)?.label ?? 'Overview'}</strong></span></div><div className="topbar-right"><span className="synthetic-badge"><span />Training &amp; evaluation</span><div className="user-menu"><span className="avatar">{user.display_name.slice(0, 1).toUpperCase()}</span><div><strong>{user.display_name}</strong><span>{roleLabel(user.role)}</span></div></div><button className="icon-button signout-button" onClick={() => void signOut()} aria-label="Sign out" title="Sign out"><Icon name="logout" /></button></div></header>
      <div className="context-bar"><div><Icon name={user.role === 'recipient' ? 'feed' : 'shield'} size={15} /><span>{user.role === 'administrator' ? 'Organization account administration' : user.role === 'recipient' ? user.channel?.code ?? 'No current channel' : user.unit?.code ?? 'Assigned source unit'}</span><span className="context-divider" />{user.role === 'administrator' ? 'Accounts & permissions' : user.profile ? profileLabel(user.profile) + ' disclosure' : 'No disclosure profile'}</div><span>Training and evaluation · online workflow</span></div>
      <main id="workspace" className="workspace" ref={pageHeading} tabIndex={-1} key={`${user.id}-${generation}`}>
        <div hidden={page === 'security'} inert={page === 'security'} aria-hidden={page === 'security' ? true : undefined}>
          {user.role === 'submitter' ? <Submitter user={user} page={businessPage.current} onNavigate={navigate} onWriteLockChange={onWriteLockChange} /> : user.role === 'reviewer' ? <Reviewer onSignOut={() => void signOut()} onWriteLockChange={onWriteLockChange} user={user} page={businessPage.current} onNavigate={navigate} /> : user.role === 'administrator' ? <Administration user={user} active={page !== 'security'} onWriteLockChange={onWriteLockChange} /> : <Recipient user={user} page={businessPage.current} />}
        </div>
        {page === 'security' && <AccountSecurity user={user} onReauthenticate={message => { if (epoch.current === workspaceEpoch) closeWorkspace(message); }} />}
      </main><footer className="app-footer"><span>KAPIT-C2 <span>·</span> Training and evaluation system</span><span>Human review before sharing</span></footer>
      {mobileNavigation && <nav className="bottom-nav" aria-label="Quick navigation">{items.map(item => <button key={item.id} disabled={writeLocked} className={'bottom-nav-item' + (page === item.id ? ' active' : '')} aria-current={page === item.id ? 'page' : undefined} onClick={() => navigate(item.id)}><Icon name={item.icon} size={21} /><span>{item.short}</span></button>)}</nav>}
    </div>
  </div>;
}

function AuthWordmark() { return <span className="auth-wordmark"><svg viewBox="0 0 32 32" aria-hidden="true"><path d="M6 5v22M14 5v22M26 5 15 16l11 11" /></svg><span>KAPIT<span className="auth-wordmark-c2">C2</span></span></span>; }
function Brand() { return <div className="brand"><span className="brand-symbol"><svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><path d="M7 6v20M15 6v20M25 6l-10 10 10 10" stroke="currentColor" strokeWidth="3.3" strokeLinecap="round" strokeLinejoin="round" /></svg></span><span>KAPIT<span className="brand-c2">C2</span></span></div>; }
function Login({ onAuthenticated, message, signoutUnconfirmed, onCompleteSignout, backendUnavailable, onAvailabilityChange }: { onAuthenticated: (user: User) => void; message: string; signoutUnconfirmed: boolean; onCompleteSignout: () => void; backendUnavailable: boolean; onAvailabilityChange: (unavailable: boolean) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [connectionChecking, setConnectionChecking] = useState(false);
  const [connectionNotice, setConnectionNotice] = useState('');
  const errorRef = useRef<HTMLDivElement>(null);
  const usernameRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const pending = useRef(false);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { if (error) errorRef.current?.focus(); }, [error]);
  const checkConnection = async () => {
    if (pending.current) return;
    pending.current = true; setConnectionChecking(true); setConnectionNotice(''); setError(''); setPassword('');
    try {
      await api.checkConnection();
      if (!mounted.current) return;
      onAvailabilityChange(false); setConnectionNotice(signoutUnconfirmed ? 'Connection restored. Complete server sign-out before signing in.' : 'Connection restored. You can sign in with your issued account.');
      if (!signoutUnconfirmed) window.setTimeout(() => usernameRef.current?.focus(), 0);
    } catch {
      if (mounted.current) { onAvailabilityChange(true); setConnectionNotice('Still unavailable. Complete local setup and keep its terminal open, then check again.'); }
    } finally { pending.current = false; if (mounted.current) setConnectionChecking(false); }
  };
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setError('');
    if (backendUnavailable || signoutUnconfirmed || pending.current) return;
    if (!username.trim() || !password) { setError('Enter your issued username and password.'); return; }
    pending.current = true; setBusy(true); setConnectionNotice('');
    try { const response = await api.login(username.trim(), password); setPassword(''); if (!navigation[response.user.role]) { setError('This account does not have a website role.'); return; } onAuthenticated(response.user); }
    catch (failure) { if (isBackendUnavailable(failure)) { onAvailabilityChange(true); setConnectionNotice('The connection was interrupted. Check the server before trying to sign in again.'); } else setError(errorMessage(failure)); setPassword(''); }
    finally { pending.current = false; setBusy(false); }
  };
  const locked = busy || connectionChecking || backendUnavailable;
  return <div className="auth-shell">
    <header className="auth-topbar"><a className="auth-brand" href="/" aria-label="KAPIT-C2 home"><AuthWordmark /></a><div className="auth-topbar-meta"><span className="auth-chip"><span />Training &amp; evaluation</span><a className="auth-back" href="/"><Icon name="arrow" size={15} />Back to home</a></div></header>
    <main className="auth-main">
      <div className="auth-card">
        <p className="auth-kicker"><span className="auth-square" />WORKSPACE ACCESS</p>
        <h1>Welcome back.</h1>
        <p className="auth-intro">Sign in with the account issued to you. Each account opens only the tools for its role.</p>
        {message && <Notice tone={signoutUnconfirmed ? 'warning' : 'info'}>{message}{signoutUnconfirmed && <button className="text-button" onClick={onCompleteSignout} disabled={busy || connectionChecking}>Complete server sign-out<Icon name="arrow" size={16} /></button>}</Notice>}
        {backendUnavailable && <section className="auth-connection" aria-labelledby="login-connection-title"><div className="auth-connection-heading"><Icon name="alert" size={21} /><div><h3 id="login-connection-title">Workspace server unavailable</h3><p>The website is open, but sign-in needs the local application server. Every account needs this connection.</p></div></div><ol><li>In your KAPIT-C2 project folder, open <code>infra</code> and double-click <code>Start KAPIT.cmd</code>.</li><li>Let setup finish and keep its terminal open. Use the application page it opens after the checks pass.</li></ol><details><summary>Start from PowerShell instead</summary><p>From the KAPIT-C2 project folder, run:</p><code className="auth-setup-command">python infra/start_local.py</code></details><button type="button" className="auth-secondary" disabled={connectionChecking || busy} onClick={() => void checkConnection()}><Icon name="refresh" size={16} />{connectionChecking ? 'Checking connection…' : 'Check connection'}</button></section>}
        {connectionNotice && <p className={'auth-connection-notice ' + (backendUnavailable ? '' : 'is-restored')} role="status">{connectionNotice}</p>}
        <form className="auth-form" onSubmit={event => void submit(event)} noValidate>
          {error && <div tabIndex={-1} ref={errorRef}><Notice tone="error">{error}</Notice></div>}
          <label className="auth-field" htmlFor="username"><span>Username</span><input ref={usernameRef} id="username" name="username" autoComplete="username" autoCapitalize="none" spellCheck={false} value={username} onChange={event => setUsername(event.target.value)} placeholder="Your issued username" disabled={locked} /></label>
          <label className="auth-field" htmlFor="password"><span>Password</span><span className="auth-password"><input ref={passwordRef} id="password" name="password" autoComplete="current-password" type={showPassword ? 'text' : 'password'} value={password} onChange={event => setPassword(event.target.value)} placeholder="Enter your password" disabled={locked} /><button type="button" className="auth-reveal" aria-label={showPassword ? 'Hide password' : 'Show password'} onClick={() => setShowPassword(value => !value)} disabled={locked}><Icon name="eye" size={19} /></button></span></label>
          <button className="auth-submit" disabled={locked || signoutUnconfirmed}>{busy ? 'Checking your account…' : 'Sign in to workspace'}<Icon name="arrow" /></button>
        </form>
      </div>
      <p className="auth-boundary">For training and evaluation use only.<br />Not an operational reporting system.</p>
    </main>
    <aside className="auth-story" aria-labelledby="auth-story-title">
      <img className="auth-story-image" src={heroImage} alt="" width={1672} height={941} />
      <div className="auth-story-shade" aria-hidden="true" /><div className="auth-story-frame" aria-hidden="true"><i /><i /><i /><i /></div>
      <div className="auth-story-content"><p className="auth-kicker"><span className="auth-square" />CLARITY THROUGH CAREFUL SHARING</p><h2 id="auth-story-title">From local reports<br />to a <em>shared picture.</em></h2><p>A focused workspace for reporting maintenance issues, reviewing the details, and sharing only approved information.</p>
        <ol className="auth-steps"><li><span><Icon name="report" size={20} /></span><div><strong>Report privately</strong><p>Keep the original intact.</p></div></li><li><span><Icon name="review" size={20} /></span><div><strong>Review carefully</strong><p>Human judgment first.</p></div></li><li><span><Icon name="shield" size={20} /></span><div><strong>Share confidently</strong><p>Only approved content.</p></div></li></ol></div>
      <p className="auth-story-foot"><Icon name="lock" size={16} />Source units · Sharing channels · Separate accounts for each step</p>
    </aside>
  </div>;
}
