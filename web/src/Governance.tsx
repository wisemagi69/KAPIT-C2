import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError, errorMessage } from './api';
import { Loading, Notice } from './components';
import { profileLabel } from './domain';
import type { AdminContext, IntegrationClientMetadata, IntegrationRequest, IntegrationState, PolicyState, Profile, User } from './types';

type KeyExpectation = { requestId?: string; requesterId: string; channelId: string; profile: Profile; expiresAt: string };
type Pending = { path: string; body: Record<string, unknown>; kind: 'proposal' | 'apply' | 'request' | 'approve' | 'collect' | 'revoke'; operationId?: string; expectedKey?: KeyExpectation; integrationContext?: string };
const base = '/administration/integration-clients/';
const profiles: Profile[] = ['DEMO-FULL', 'DEMO-REDUCED', 'DEMO-SUMMARY'];
const uuid = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value);
const hash = (value: unknown) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const localExpiry = () => { const date = new Date(Date.now() + 7 * 86400000); return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16); };
const unconfirmed = () => new ApiError(0, 'UNCONFIRMED_ADMINISTRATION', 'The result could not be confirmed. Retry the same action.');
const date = (value: unknown): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value));

function checkedRequest(value: IntegrationRequest): IntegrationRequest {
  if (!value || !uuid(value.id) || !uuid(value.requester_id) || !uuid(value.channel_id) || !profiles.includes(value.profile_ceiling) || typeof value.label !== 'string' || !date(value.expires_at) || !date(value.collect_deadline) || !date(value.created_at) || typeof value.approved !== 'boolean') throw unconfirmed();
  return { id: value.id, requester_id: value.requester_id, channel_id: value.channel_id, profile_ceiling: value.profile_ceiling, label: value.label, expires_at: value.expires_at, collect_deadline: value.collect_deadline, created_at: value.created_at, approved: value.approved };
}

function checkedClient(value: unknown): IntegrationClientMetadata {
  if (!value || typeof value !== 'object') throw unconfirmed();
  const row = value as IntegrationClientMetadata;
  if (!uuid(row.id) || !uuid(row.request_id) || !uuid(row.channel_id) || !profiles.includes(row.profile_ceiling) || typeof row.label !== 'string' || typeof row.key_prefix !== 'string' || !/^[a-z0-9]{8}$/.test(row.key_prefix) || !date(row.created_at) || !date(row.expires_at) || row.revoked_at !== null && !date(row.revoked_at)) throw unconfirmed();
  return { id: row.id, request_id: row.request_id, channel_id: row.channel_id, profile_ceiling: row.profile_ceiling, label: row.label, key_prefix: row.key_prefix, created_at: row.created_at, expires_at: row.expires_at, revoked_at: row.revoked_at };
}

export default function Governance({ user, context, onWriteLockChange }: { user: User; context: AdminContext; onWriteLockChange: (locked: boolean) => void }) {
  const policyAllowed = context.authorities?.includes('POLICY') === true;
  const integrationAllowed = context.authorities?.includes('INTEGRATION') === true;
  const integrationContext = integrationAllowed ? JSON.stringify({ user: user.id, channels: context.channels.filter(row => row.active).map(row => row.id).sort() }) : '';
  const currentIntegrationContext = useRef(integrationContext);
  currentIntegrationContext.current = integrationContext;
  const [policy, setPolicy] = useState<PolicyState | null>(null), [integration, setIntegration] = useState<IntegrationState | null>(null);
  const [loading, setLoading] = useState(true), [error, setError] = useState(''), [message, setMessage] = useState('');
  const [pending, setPending] = useState<Pending | null>(null), [busy, setBusy] = useState(false), [uncertain, setUncertain] = useState(false);
  const [secret, setSecret] = useState(''), [secretClient, setSecretClient] = useState<IntegrationClientMetadata | null>(null);
  const [secretContext, setSecretContext] = useState('');
  const [page, setPage] = useState(1), [generation, setGeneration] = useState(0);
  const [target, setTarget] = useState(''), [kind, setKind] = useState<'ACTIVATE' | 'DEACTIVATE'>('ACTIVATE'), [policyConfirmed, setPolicyConfirmed] = useState(false);
  const [label, setLabel] = useState(''), [channel, setChannel] = useState(''), [profile, setProfile] = useState<Profile>('DEMO-REDUCED'), [expiry, setExpiry] = useState(localExpiry), [keyConfirmed, setKeyConfirmed] = useState(false);
  const alive = useRef(true), sending = useRef(false), sequence = useRef(0);
  const locked = busy || uncertain;
  useEffect(() => { alive.current = true; return () => { alive.current = false; sequence.current++; }; }, []);
  useEffect(() => { setSecret(''); setSecretClient(null); setIntegration(null); }, [integrationContext]);
  useEffect(() => {
    onWriteLockChange(locked);
    const leaving = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    if (locked) window.addEventListener('beforeunload', leaving);
    return () => { onWriteLockChange(false); window.removeEventListener('beforeunload', leaving); };
  }, [locked, onWriteLockChange]);
  const load = useCallback(async () => {
    const current = ++sequence.current;
    setLoading(true);
    try {
      const [nextPolicy, nextIntegration] = await Promise.all([policyAllowed ? api.policyState() : null, integrationAllowed ? api.integrationState(page) : null]);
      if (!alive.current || current !== sequence.current) return;
      if (nextPolicy && (!Array.isArray(nextPolicy.policies) || !Array.isArray(nextPolicy.proposals) || nextPolicy.proposals.length > 50 || !Number.isInteger(nextPolicy.policy_epoch) || nextPolicy.active_policy_id !== null && !uuid(nextPolicy.active_policy_id) || nextPolicy.policies.some(row => !row || !uuid(row.id) || !hash(row.rules_hash) || typeof row.version !== 'string' || typeof row.supported !== 'boolean') || nextPolicy.proposals.some(row => !row || !uuid(row.id) || !uuid(row.proposer_id) || !uuid(row.target_policy_id) || !hash(row.target_rules_hash) || !['ACTIVATE', 'DEACTIVATE'].includes(row.kind) || row.expected_active_policy_id !== null && !uuid(row.expected_active_policy_id) || !date(row.expires_at) || !date(row.proposed_at) || typeof row.applied !== 'boolean'))) throw unconfirmed();
      if (nextIntegration && (!Array.isArray(nextIntegration.clients) || !Array.isArray(nextIntegration.requests) || nextIntegration.clients.length > 100 || nextIntegration.requests.length > 100 || nextIntegration.page !== page || nextIntegration.page_size !== 25 || !Number.isInteger(nextIntegration.client_count) || nextIntegration.client_count < nextIntegration.clients.length || !Number.isInteger(nextIntegration.request_count) || nextIntegration.request_count < nextIntegration.requests.length || typeof nextIntegration.clients_more !== 'boolean' || typeof nextIntegration.requests_more !== 'boolean')) throw unconfirmed();
      setPolicy(nextPolicy ? { active_policy_id: nextPolicy.active_policy_id, policy_epoch: nextPolicy.policy_epoch, policies: nextPolicy.policies.map(row => ({ id: row.id, version: row.version, rules_hash: row.rules_hash, active: row.active, supported: row.supported })), proposals: nextPolicy.proposals.map(row => ({ id: row.id, kind: row.kind, target_policy_id: row.target_policy_id, target_rules_hash: row.target_rules_hash, expected_active_policy_id: row.expected_active_policy_id, proposer_id: row.proposer_id, proposed_at: row.proposed_at, expires_at: row.expires_at, applied: row.applied })) } : null);
      setIntegration(nextIntegration ? { clients: nextIntegration.clients.map(checkedClient), requests: nextIntegration.requests.map(checkedRequest), page: nextIntegration.page, page_size: nextIntegration.page_size, client_count: nextIntegration.client_count, request_count: nextIntegration.request_count, clients_more: nextIntegration.clients_more, requests_more: nextIntegration.requests_more } : null);
    } catch (failure) { if (alive.current && current === sequence.current) { setPolicy(null); setIntegration(null); setError(errorMessage(failure)); } }
    finally { if (alive.current && current === sequence.current) setLoading(false); }
  }, [policyAllowed, integrationAllowed, page]);
  useEffect(() => { void load(); }, [load, generation]);
  const execute = async (next: Pending) => {
    if (sending.current) return;
    const frozen = pending ?? structuredClone(next);
    if (frozen.integrationContext !== undefined && frozen.integrationContext !== currentIntegrationContext.current) { setError('Your integration context changed. Sign out to clear the unresolved action.'); return; }
    const recovering = uncertain;
    sending.current = true; onWriteLockChange(true); setPending(frozen); setBusy(true); setError(''); setMessage(''); setSecret(''); setSecretClient(null);
    try {
      const result = await api.governanceWrite(frozen.path, frozen.body, frozen.operationId);
      if (!alive.current) return;
      if (frozen.kind === 'request' || frozen.kind === 'collect') {
        const request = result.request as { id?: unknown; requester_id?: unknown; channel_id?: unknown; profile_ceiling?: unknown; expires_at?: unknown } | undefined;
        if (!request || !uuid(request.id) || request.requester_id !== user.id) throw unconfirmed();
        const client = result.client === null ? null : checkedClient(result.client);
        const expected = frozen.expectedKey;
        if (!expected || frozen.integrationContext !== currentIntegrationContext.current || !frozen.integrationContext
            || request.requester_id !== expected.requesterId || expected.requestId !== undefined && request.id !== expected.requestId
            || request.channel_id !== expected.channelId || request.profile_ceiling !== expected.profile || !date(request.expires_at)
            || Date.parse(request.expires_at) !== Date.parse(expected.expiresAt)) throw unconfirmed();
        if (client && (client.request_id !== request.id || client.channel_id !== request.channel_id || client.profile_ceiling !== request.profile_ceiling
            || Date.parse(client.expires_at) !== Date.parse(request.expires_at))) throw unconfirmed();
        if (frozen.kind === 'request' && expected.profile !== 'DEMO-FULL' && !client) throw unconfirmed();
        if (frozen.kind === 'collect' && (!frozen.path.includes(request.id) || !client)) throw unconfirmed();
        if ('key' in result) {
          if (!client || typeof result.key !== 'string' || !new RegExp(`^kapit_ic_${client.key_prefix}_[A-Za-z0-9_-]{43}$`).test(result.key)) throw unconfirmed();
          setSecret(result.key); setSecretClient(client); setSecretContext(frozen.integrationContext);
          setMessage('Key collected. Keep this one-time value private.');
        } else if (client) setMessage('The request is committed, but its one-time key cannot be recovered. Revoke this key and request a replacement if you did not save it.');
        else setMessage('FULL request recorded. A different integration authority holder must approve it before you collect.');
      } else if (frozen.kind === 'proposal') {
        if (!uuid(result.id) || result.proposer_id !== user.id || result.kind !== frozen.body.kind || result.target_policy_id !== frozen.body.target_policy_id || result.target_rules_hash !== frozen.body.target_rules_hash || result.expected_active_policy_id !== frozen.body.expected_active_policy_id) throw unconfirmed();
        setMessage('Proposal recorded. A different policy authority holder must apply it.');
      } else if (frozen.kind === 'apply') {
        if (!uuid(result.activation_id) || !uuid(result.proposal_id) || !frozen.path.includes(result.proposal_id)) throw unconfirmed();
        setMessage('Policy change committed. Reports require fresh processing and human review before sharing.');
      } else if (frozen.kind === 'approve') {
        if (!uuid(result.approval_id) || !uuid(result.request_id) || !frozen.path.includes(result.request_id)) throw unconfirmed();
        setMessage('FULL request approved. Only its requester can collect the key.');
      } else {
        const client = checkedClient(result);
        if (!client.revoked_at || !frozen.path.includes(client.id)) throw unconfirmed();
        setMessage('Key revocation committed. Future reads with this key are denied.');
      }
      setPending(null); setUncertain(false); setPolicyConfirmed(false); setKeyConfirmed(false); setGeneration(value => value + 1);
    } catch (failure) {
      if (!alive.current) return;
      const unresolved = recovering || failure instanceof ApiError && failure.uncertain;
      setUncertain(unresolved); setError(errorMessage(failure));
      if (!unresolved) { setPending(null); if (failure instanceof ApiError && failure.status === 409) { setPolicy(null); setIntegration(null); setMessage('This context changed. Reload before starting a new action.'); } }
    } finally { sending.current = false; if (alive.current) setBusy(false); }
  };
  const propose = () => {
    const selected = policy?.policies.find(row => row.id === target);
    if (!policy || !selected || !selected.supported || !policyConfirmed) return;
    const operation = crypto.randomUUID();
    void execute({ path: '/administration/policy/proposals/', kind: 'proposal', operationId: operation, body: { operation_id: operation, kind, target_policy_id: selected.id, target_rules_hash: selected.rules_hash, expected_active_policy_id: policy.active_policy_id } });
  };
  const requestKey = () => {
    const date = new Date(expiry);
    if (!keyConfirmed || !label.trim() || !channel || !Number.isFinite(date.getTime()) || date.getTime() <= Date.now() || date.getTime() > Date.now() + 90 * 86400000) { setError('Confirm a channel, profile, label and future expiry within 90 days.'); return; }
    const operation = crypto.randomUUID();
    void execute({ path: base, kind: 'request', operationId: operation, body: { operation_id: operation, channel_id: channel, profile_ceiling: profile, label: label.trim(), expires_at: date.toISOString() }, expectedKey: { requesterId: user.id, channelId: channel, profile, expiresAt: date.toISOString() }, integrationContext });
  };
  return <section className="governance" aria-label="Policy and integration administration">
    <header className="section-heading"><div><p className="eyebrow">EXPLICIT AUTHORITY</p><h2>Policy and integration</h2><p>These controls require a separate authority grant. Account administration does not grant report review access.</p></div><button className="button secondary" disabled={loading || locked} onClick={() => { setSecret(''); setSecretClient(null); setError(''); setGeneration(value => value + 1); }}>Reload governance</button></header>
    {loading && <Loading text="Checking current policy and integration authority…" />}
    {error && <Notice tone={uncertain ? 'warning' : 'error'}>{error}{uncertain && <><p>Result not yet confirmed. Keep this exact action until its replay is confirmed. Signing out clears this tab.</p><button className="button primary" disabled={busy || !pending || pending.integrationContext !== undefined && pending.integrationContext !== integrationContext} onClick={() => pending && void execute(pending)}>Retry same administration action</button></>}</Notice>}
    {message && <Notice>{message}</Notice>}
    {integrationAllowed && secretContext === integrationContext && secret && secretClient && context.channels.some(row => row.id === secretClient.channel_id && row.active) && <section className="card one-time-key"><h3>One-time key</h3><p>Save privately now. Closing this value, leaving administration or signing out clears it. It cannot be retrieved again; revoke and reissue if lost.</p><label className="field"><span>One-time integration key</span><textarea aria-label="One-time integration key" value={secret} readOnly autoComplete="off" spellCheck={false} rows={3} /></label><p>Client prefix: {secretClient.key_prefix}</p><button className="button secondary" onClick={() => { setSecret(''); setSecretClient(null); }}>Close one-time key</button></section>}
    <fieldset className="governance-controls" disabled={locked}><legend className="sr-only">Authority actions</legend>
      {policyAllowed && policy && <section className="card"><h3>Policy control</h3><p>Active policy: {policy.policies.find(row => row.id === policy.active_policy_id)?.version ?? 'None'} · Epoch {policy.policy_epoch}</p><p className="mono">Current policy ID: {policy.active_policy_id ?? 'None'}</p>
        <label className="field"><span>Policy action</span><select aria-label="Policy action" value={kind} onChange={event => { setKind(event.target.value as typeof kind); setTarget(''); setPolicyConfirmed(false); }}><option value="ACTIVATE">Activate</option><option value="DEACTIVATE">Deactivate</option></select></label>
        <label className="field"><span>Policy target</span><select aria-label="Policy target" value={target} onChange={event => { setTarget(event.target.value); setPolicyConfirmed(false); }}><option value="">Choose a policy</option>{policy.policies.filter(row => row.supported && (kind === 'ACTIVATE' ? row.id !== policy.active_policy_id : row.id === policy.active_policy_id)).map(row => <option key={row.id} value={row.id}>{row.version}</option>)}</select></label>
        {target && <p className="mono">Target SHA-256: {policy.policies.find(row => row.id === target)?.rules_hash}</p>}
        <label className="checkbox-field"><input type="checkbox" checked={policyConfirmed} onChange={event => setPolicyConfirmed(event.target.checked)} /><span>I checked the policy hash and current active policy.</span></label><button className="button primary" disabled={!target || !policyConfirmed || loading} onClick={propose}>Propose policy change</button>
        <h4>Recent proposals</h4>{policy.proposals.map(row => <article className="governance-row" key={row.id}><p>{row.kind} · {row.target_policy_id}</p><p className="mono">SHA-256 {row.target_rules_hash}</p><p>Proposer: {row.proposer_id} · Expires {row.expires_at}</p><p>Expected active policy: {row.expected_active_policy_id ?? 'None'}</p>{row.applied ? <p>Applied</p> : row.proposer_id === user.id ? <p>A different policy authority holder must apply your proposal.</p> : <button className="button secondary" disabled={loading || row.expected_active_policy_id !== policy.active_policy_id || Date.parse(row.expires_at) <= Date.now()} onClick={() => void execute({ path: `/administration/policy/proposals/${row.id}/apply/`, body: {}, kind: 'apply' })}>Apply proposal {row.id}</button>}</article>)}
      </section>}
      {integrationAllowed && integration && <section className="card"><h3>Integration keys</h3><p>Read-only keys have a fixed channel, disclosure ceiling and expiry. FULL needs a second authority holder; the requester alone collects. A key remains valid after its issuer loses authority until key revocation or expiry.</p>
        <label className="field"><span>Integration label</span><input aria-label="Integration label" maxLength={80} value={label} onChange={event => { setLabel(event.target.value); setKeyConfirmed(false); }} /></label>
        <label className="field"><span>Integration channel</span><select aria-label="Integration channel" value={channel} onChange={event => { setChannel(event.target.value); setKeyConfirmed(false); }}><option value="">Choose a channel</option>{context.channels.filter(row => row.active).map(row => <option key={row.id} value={row.id}>{row.name} ({row.code})</option>)}</select></label>
        <label className="field"><span>Integration profile</span><select aria-label="Integration profile" value={profile} onChange={event => { setProfile(event.target.value as Profile); setKeyConfirmed(false); }}>{profiles.map(row => <option key={row} value={row}>{profileLabel(row)}</option>)}</select></label>
        <label className="field"><span>Integration expiry</span><input aria-label="Integration expiry" type="datetime-local" value={expiry} onChange={event => { setExpiry(event.target.value); setKeyConfirmed(false); }} /></label>
        <label className="checkbox-field"><input type="checkbox" checked={keyConfirmed} onChange={event => setKeyConfirmed(event.target.checked)} /><span>I confirmed the channel, profile and expiry.</span></label><button className="button primary" disabled={loading || !keyConfirmed || !channel || !label.trim()} onClick={requestKey}>Request integration key</button>
        <h4>Requests</h4>{integration.requests.map(row => <article className="governance-row" key={row.id}><strong>{row.label} · {profileLabel(row.profile_ceiling)}</strong><p>Requester: {row.requester_id} · Channel {row.channel_id}</p><p>Collect before {row.collect_deadline} · Expires {row.expires_at}</p>{row.profile_ceiling === 'DEMO-FULL' && Date.parse(row.collect_deadline) > Date.now() && !integration.clients.some(client => client.request_id === row.id) && (row.requester_id === user.id ? row.approved ? <button className="button secondary" disabled={loading} onClick={() => void execute({ path: `${base}requests/${row.id}/collect/`, body: {}, kind: 'collect', expectedKey: { requestId: row.id, requesterId: row.requester_id, channelId: row.channel_id, profile: row.profile_ceiling, expiresAt: row.expires_at }, integrationContext })}>Collect key {row.id}</button> : <p>Waiting for a different authority holder.</p> : !row.approved ? <button className="button secondary" disabled={loading} onClick={() => void execute({ path: `${base}requests/${row.id}/approve/`, body: {}, kind: 'approve' })}>Approve FULL request {row.id}</button> : <p>Approved; only its requester can collect.</p>)}</article>)}
        <h4>Issued clients</h4>{integration.clients.map(row => <article className="governance-row" key={row.id}><strong>{row.label} · {row.key_prefix}</strong><p>{profileLabel(row.profile_ceiling)} · Channel {row.channel_id} · Expires {row.expires_at}</p>{row.revoked_at ? <p>Revoked {row.revoked_at}</p> : <button className="button danger-outline" disabled={loading} onClick={() => void execute({ path: `${base}${row.id}/revoke/`, body: {}, kind: 'revoke' })}>Revoke key {row.key_prefix}</button>}</article>)}
        <p>Metadata page {page} · {integration.client_count} clients · {integration.request_count} requests</p><div className="button-row"><button className="button secondary" disabled={loading || page === 1} onClick={() => { setSecret(''); setSecretClient(null); setPage(value => value - 1); }}>Previous metadata page</button><button className="button secondary" disabled={loading || !integration.clients_more && !integration.requests_more} onClick={() => { setSecret(''); setSecretClient(null); setPage(value => value + 1); }}>Next metadata page</button></div>
      </section>}
    </fieldset>
  </section>;
}
