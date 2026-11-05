import { useEffect, useRef, useState } from 'react';
import { api, ApiError, errorMessage } from './api';
import { BackButton, Loading, Modal, Notice, ProjectionCard, SectionHeading, SourceFields } from './components';
import { profileLabel } from './domain';
import { Icon } from './icons';
import type { BatchDecisionOperation, BatchDecisionResult, BatchReviewDetail, Profile, ReviewAction, User } from './types';

export default function BatchReview({ id, revision, user, onBack, onSource, onCommitted, onWriteLockChange, onSignOut }: { id: string; revision: number; user: User; onBack: () => void; onSource: () => void; onCommitted: () => void; onWriteLockChange: (locked: boolean) => void; onSignOut: () => void }) {
  const [detail, setDetail] = useState<BatchReviewDetail | null>(null);
  const [loading, setLoading] = useState(true), [generation, setGeneration] = useState(0);
  const [error, setError] = useState(''), [action, setAction] = useState<ReviewAction | null>(null);
  const [profiles, setProfiles] = useState<Profile[]>([]), [reason, setReason] = useState(''), [confirmed, setConfirmed] = useState(false);
  const [operation, setOperation] = useState<BatchDecisionOperation | null>(null);
  const [busy, setBusy] = useState(false), [uncertain, setUncertain] = useState(false), [stale, setStale] = useState(false);
  const [result, setResult] = useState<BatchDecisionResult | null>(null);
  const alive = useRef(true), sending = useRef(false);
  const locked = busy || uncertain;
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    onWriteLockChange(locked);
    const preventLeave = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ''; };
    if (locked) window.addEventListener('beforeunload', preventLeave);
    return () => { window.removeEventListener('beforeunload', preventLeave); onWriteLockChange(false); };
  }, [locked, onWriteLockChange]);
  useEffect(() => {
    let active = true; setDetail(null); setLoading(true); setError(''); setStale(false); setResult(null); setProfiles([]);
    (async () => {
      const source = await api.source(id, revision);
      if (!active) return;
      const response = await api.candidateSet(source.receipt.revision_id);
      const knownProfiles = ['DEMO-FULL', 'DEMO-REDUCED', 'DEMO-SUMMARY'];
      const context = response.binding;
      const hash = (value: unknown) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
      const complete = context.revision_id === source.receipt.revision_id && context.revision_no === revision
        && hash(context.policy_hash) && (context.scope_context_hash === null || hash(context.scope_context_hash))
        && response.candidates.length >= 1 && response.candidates.length <= 3 && context.candidates.length === response.candidates.length
        && new Set(context.candidates.map(row => row.variant_id)).size === context.candidates.length
        && new Set(response.candidates.map(row => row.variant_id)).size === response.candidates.length
        && new Set(context.candidates.map(row => row.profile)).size === context.candidates.length
        && new Set(response.candidates.map(row => row.profile)).size === response.candidates.length
        && context.candidates.every(row => knownProfiles.includes(row.profile))
        && context.candidates.every(row => hash(row.candidate_hash) && row.channel_ids.length > 0 && row.channel_ids.every(value => typeof value === 'string' && !!value) && new Set(row.channel_ids).size === row.channel_ids.length)
        && response.candidates.every(row => context.candidates.some(binding => binding.variant_id === row.variant_id && binding.profile === row.profile) && row.candidate.profile === row.profile);
      if (!complete) throw new Error('Incomplete candidate context');
      if (active) setDetail(response);
    })().catch(failure => { if (active) setError(errorMessage(failure)); }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [id, revision, generation]);
  const choose = (value: ReviewAction) => { setAction(value); setReason(''); setConfirmed(false); setError(''); setOperation(null); };
  const commit = async () => {
    if ((!detail && !operation) || !action || sending.current || stale) return;
    if (!operation && (action === 'APPROVE' ? !confirmed || !profiles.length : !reason.trim() || [...reason.trim()].length > 500)) { setError('Confirm the selected profiles, or enter a private reason of up to 500 characters.'); return; }
    const frozen: BatchDecisionOperation = operation ?? { operation_id: crypto.randomUUID(), action, approve_profiles: action === 'APPROVE' ? [...profiles] : [], expected: structuredClone(detail!.binding), reason: reason.trim() || null };
    const recovering = uncertain; sending.current = true; onWriteLockChange(true); setOperation(frozen); setBusy(true); setError('');
    try {
      const response = await api.decideBatch(frozen.expected.revision_id, frozen);
      if (!alive.current) return;
      setResult(response); setUncertain(false); setOperation(null); setAction(null); onCommitted();
    } catch (failure) {
      if (!alive.current) return;
      const unresolved = recovering || failure instanceof ApiError && failure.uncertain;
      setUncertain(unresolved); setError(errorMessage(failure));
      if (!unresolved) setOperation(null);
      if (failure instanceof ApiError && failure.status === 409 && !unresolved) { setStale(true); setAction(null); setDetail(null); }
      if (failure instanceof ApiError && [401, 403, 404].includes(failure.status) && !failure.code.toLowerCase().includes('csrf')) { setDetail(null); if (!unresolved) setAction(null); }
    } finally { sending.current = false; if (alive.current) setBusy(false); }
  };
  const channels = (ids: string[]) => ids.map(value => { const channel = user.channels?.find(row => row.id === value); return channel ? `${channel.name} (${channel.code})` : value; }).join(', ') || 'No eligible sharing channels';
  return <>
    <BackButton onClick={() => { if (!locked) onBack(); }}>Back to review queue</BackButton>
    <SectionHeading eyebrow="ORIGINATING UNIT REVIEW" title={detail?.report.reference ?? 'Review report'} text="Check every candidate and its exact audience. Only the profiles you explicitly approve can be shared." action={<button className="button secondary" disabled={loading || locked} onClick={() => setGeneration(value => value + 1)}>Reload review</button>} />
    {loading && <Loading text="Loading authorized candidate set…" />}
    {error && !action && <Notice tone={stale ? 'warning' : 'error'}>{error}{stale && <p>This review changed. Reload before deciding.</p>}</Notice>}
    {result && <Notice tone="success"><strong>{result.action === 'APPROVE' ? 'Approval committed.' : result.action === 'RETURN' ? 'Report returned for correction.' : 'Report rejected.'}</strong><p>Approved profiles: {result.approved_profiles.join(', ') || 'None'}. Withheld profiles: {result.withheld_profiles.join(', ') || 'None'}.</p><button className="text-button" onClick={onBack}>Return to queue</button></Notice>}
    {detail && <>
      <button className="text-button history-link" disabled={locked} onClick={onSource}>View revision history</button>
      {detail.correction_reason && <Notice><strong>Private correction reason:</strong> {detail.correction_reason}</Notice>}
      <section className="card original-panel"><div className="card-heading"><span className="card-icon"><Icon name="lock" /></span><div><h3>Original report</h3><p>Private · source revision {detail.binding.revision_no}</p></div><span className="panel-label">BEFORE</span></div><SourceFields payload={detail.source} /></section>
      <div className="batch-candidates">{detail.candidates.map(candidate => {
        const binding = detail.binding.candidates.find(row => row.variant_id === candidate.variant_id);
        return <section className="card candidate-panel" key={candidate.variant_id} aria-label={`${profileLabel(candidate.profile)} candidate`}><div className="card-heading"><span className="card-icon"><Icon name="shield" /></span><div><h3>{profileLabel(candidate.profile)}</h3><p>Candidate · not shared until approved</p></div><span className="panel-label teal">AFTER</span></div><ProjectionCard projection={candidate.candidate} candidate />
          {candidate.warnings.length > 0 && <Notice tone="warning"><strong>Review notes</strong><ul>{candidate.warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul></Notice>}
          <dl className="binding-fields"><div><dt>Sharing audience</dt><dd>{binding ? channels(binding.channel_ids) : 'Binding unavailable'}</dd></div><div><dt>Candidate SHA-256</dt><dd className="mono">{binding?.candidate_hash}</dd></div></dl>
          {!result && <label className="checkbox-field candidate-approve"><input type="checkbox" checked={profiles.includes(candidate.profile)} disabled={locked || stale || !binding || candidate.state !== 'CANDIDATE'} onChange={event => setProfiles(values => event.target.checked ? [...values, candidate.profile] : values.filter(value => value !== candidate.profile))} /><span>Approve {profileLabel(candidate.profile)}</span></label>}
        </section>;
      })}</div>
      <section className="card binding-card"><div className="binding-summary"><div><h3>Exact approval context</h3><p>Revision {detail.binding.revision_no} · {detail.binding.policy_version}. Any source, policy, scope or audience change invalidates this review.</p></div></div><dl className="binding-fields"><div><dt>Source revision ID</dt><dd className="mono">{detail.binding.revision_id}</dd></div><div><dt>Policy SHA-256</dt><dd className="mono">{detail.binding.policy_hash}</dd></div><div><dt>Scope context SHA-256</dt><dd className="mono">{detail.binding.scope_context_hash ?? 'Legacy context'}</dd></div></dl></section>
      {!result && <div className="review-actions"><p><Icon name="shield" size={18} />Unselected profiles are withheld. Return and reject apply to the whole candidate set.</p><div className="button-row"><button className="button danger-outline" disabled={locked || stale} onClick={() => choose('REJECT')}>Reject</button><button className="button secondary" disabled={locked || stale} onClick={() => choose('RETURN')}>Return for correction</button><button className="button primary" disabled={locked || stale || !profiles.length} onClick={() => choose('APPROVE')}>Review & approve</button></div></div>}
    </>}
    {action && <Modal title={action === 'APPROVE' ? 'Confirm approval & sharing' : action === 'RETURN' ? 'Return for correction' : 'Reject this report'} locked={locked} onClose={() => { if (!locked) { setAction(null); setError(''); } }}>
      <p>{action === 'APPROVE' ? `Selected profiles: ${(operation?.approve_profiles ?? profiles).map(profileLabel).join(', ')}. Every other profile is withheld.` : 'This decision covers the whole candidate set. Your reason stays private.'}</p>
      {action === 'APPROVE' && <label className="checkbox-field"><input type="checkbox" checked={confirmed} disabled={locked} onChange={event => setConfirmed(event.target.checked)} /><span>I have checked every selected candidate, source revision, policy and sharing audience.</span></label>}
      {action !== 'APPROVE' && <label className="field"><span>Private reason *</span><textarea aria-label="Private reason" maxLength={500} value={reason} disabled={locked} onChange={event => setReason(event.target.value)} /></label>}
      {error && <Notice tone={uncertain ? 'warning' : 'error'}>{uncertain && <strong>Decision result not yet confirmed. </strong>}{error}{uncertain && <p>Retry the same decision before leaving this review.</p>}</Notice>}
      {locked && <button className="text-button" onClick={onSignOut}>Sign out and clear workspace</button>}
      <div className="modal-footer"><button className="button secondary" disabled={locked} onClick={() => setAction(null)}>Cancel</button><button className="button primary" disabled={busy || !uncertain && (action === 'APPROVE' ? !confirmed : !reason.trim())} onClick={() => void commit()}>{busy ? 'Committing decision…' : uncertain ? 'Retry same decision' : action === 'APPROVE' ? 'Approve & share' : action === 'RETURN' ? 'Return report' : 'Reject report'}</button></div>
    </Modal>}
  </>;
}
