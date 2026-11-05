import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError, errorMessage } from '../api';
import { BackButton, EmptyState, Loading, MetricCard, Notice, Pagination, ProjectionCard, SectionHeading } from '../components';
import { allowedProfiles, CATEGORY_LABELS, dateLabel, mapMatchesCount, profileLabel, projectionObserved, publishedLabel, recipientGrants, validateFeedFilters } from '../domain';
import AreaMap from '../map/AreaMap';
import { Icon } from '../icons';
import type { FeedFilters, FeedSummary, MapCounts, PageResult, Publication, RemovedPublication, User } from '../types';

interface Props { user: User; page: string }
const initialFilters = (): FeedFilters => ({ q: '', category: 'ALL', urgency: 'ALL', page: 1, page_size: 10 });
export default function Recipient({ user, page }: Props) {
  const grants = recipientGrants(user);
  const expanded = user.grants !== undefined || user.channels !== undefined;
  const [channelId, setChannelId] = useState(() => grants[0]?.channel.id ?? '');
  const grant = grants.find(value => value.channel.id === channelId);
  const channel = grant?.channel;
  const [summary, setSummary] = useState<FeedSummary | undefined>();
  const [mapCounts, setMapCounts] = useState<MapCounts | null>(null);
  const [removed, setRemoved] = useState<RemovedPublication[]>([]);
  const [publications, setPublications] = useState<Publication[]>([]);
  const [filters, setFilters] = useState<FeedFilters>(() => ({ ...initialFilters(), ...(expanded && grant ? { profile: grant.profile_ceiling } : {}) }));
  const [draft, setDraft] = useState<FeedFilters>(() => ({ ...initialFilters(), ...(expanded && grant ? { profile: grant.profile_ceiling } : {}) }));
  const [filterError, setFilterError] = useState('');
  const [pagination, setPagination] = useState<Omit<PageResult<Publication>, 'results'>>({ count: 0, page: 1, page_size: 10, total_pages: 1 });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [lastSuccess, setLastSuccess] = useState('');
  const [lastSuccessClock, setLastSuccessClock] = useState(0);
  const [clock, setClock] = useState(Date.now());
  const [accessLost, setAccessLost] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Publication | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const alive = useRef(true);
  const requestSequence = useRef(0);
  const detailSequence = useRef(0);
  const selectedRef = useRef<string | null>(null);
  const failureCount = useRef(0);
  const stale = !!error || !lastSuccessClock || clock - lastSuccessClock > 60_000;

  const refresh = useCallback(async () => {
    if (!channel) { setPublications([]); setError('A current channel grant is required.'); setAccessLost(true); setLoading(false); return; }
    const sequence = ++requestSequence.current;
    if (selectedRef.current) { detailSequence.current++; setDetailLoading(false); }
    setRefreshing(true);
    try {
      const response = await api.feed(channel.id, filters);
      if (!alive.current || sequence !== requestSequence.current) return;
      const [map, removals] = expanded ? await Promise.all([filters.profile === 'DEMO-SUMMARY' ? Promise.resolve(null) : api.map(channel.id, filters), api.removed(channel.id)]) : [null, { results: [] }];
      if (!alive.current || sequence !== requestSequence.current) return;
      if (map && !mapMatchesCount(map, response.count)) throw new ApiError(0, 'INVALID_MAP_RESPONSE', 'The current map and list counts could not be confirmed. Refresh to check again.');
      setPublications(response.results); setSummary(response.summary); setMapCounts(map);
      // Tombstones carry no cause, time or replacement; only use their fixed state.
      setRemoved(removals.results.filter(value => typeof value.publication_id === 'string' && ['WITHDRAWN', 'SUPERSEDED'].includes(value.state)).map(value => ({ publication_id: value.publication_id, state: value.state })));
      setPagination({ count: response.count, page: response.page, page_size: response.page_size, total_pages: response.total_pages });
      setLastSuccess(response.refreshed_at); setLastSuccessClock(Date.now()); setClock(Date.now()); setError(''); setAccessLost(false); failureCount.current = 0;
      const selected = selectedRef.current;
      // Page membership is not an authorization decision. Recheck the detail endpoint even
      // when the selected publication has moved off this server-selected page.
      if (selected && removals.results.some(value => value.publication_id === selected)) { setDetail(null); setDetailLoading(false); setDetailError(''); }
      else if (selected) {
        const detailRequest = ++detailSequence.current;
        setDetailLoading(true);
        try {
          const current = await api.publication(selected);
          if (alive.current && sequence === requestSequence.current && detailRequest === detailSequence.current && selectedRef.current === selected) { setDetail(current); setDetailError(''); }
        } catch (failure) {
          if (alive.current && sequence === requestSequence.current && detailRequest === detailSequence.current && selectedRef.current === selected) {
            if (failure instanceof ApiError && [401, 403, 404].includes(failure.status)) setDetail(null);
            setDetailError(errorMessage(failure));
          }
        } finally { if (alive.current && sequence === requestSequence.current && detailRequest === detailSequence.current) setDetailLoading(false); }
      }
    } catch (failure) {
      if (!alive.current || sequence !== requestSequence.current) return;
      failureCount.current++;
      if (failure instanceof ApiError && [401, 403, 404].includes(failure.status)) {
        detailSequence.current++; setSummary(undefined); setMapCounts(null); setRemoved([]); setPublications([]); setPagination({ count: 0, page: filters.page, page_size: filters.page_size, total_pages: 1 }); setDetail(null); setDetailLoading(false); setAccessLost(true); setLastSuccessClock(0);
      }
      setError(errorMessage(failure));
    } finally { if (alive.current && sequence === requestSequence.current) { setLoading(false); setRefreshing(false); } }
  }, [channel?.id, expanded, filters]);
  useEffect(() => {
    alive.current = true;
    let timer: number;
    let stopped = false;
    let polling = false;
    const poll = async () => {
      if (polling || stopped) return;
      polling = true;
      if (document.visibilityState === 'visible') await refresh();
      polling = false;
      if (!stopped) timer = window.setTimeout(() => void poll(), Math.min(60_000, 10_000 * 2 ** Math.min(failureCount.current, 3)));
    };
    void poll();
    const visibility = () => { if (document.visibilityState === 'visible' && !polling) { window.clearTimeout(timer); void poll(); } };
    document.addEventListener('visibilitychange', visibility);
    const clockTimer = window.setInterval(() => setClock(Date.now()), 10_000);
    return () => { stopped = true; alive.current = false; requestSequence.current++; detailSequence.current++; window.clearTimeout(timer); window.clearInterval(clockTimer); document.removeEventListener('visibilitychange', visibility); };
  }, [refresh]);
  const open = async (publication: Publication) => {
    const sequence = ++detailSequence.current;
    const feedSequence = requestSequence.current;
    selectedRef.current = publication.id; setSelectedId(publication.id); setDetail(null); setDetailError(''); setDetailLoading(true);
    try { const result = await api.publication(publication.id); if (alive.current && sequence === detailSequence.current && feedSequence === requestSequence.current) setDetail(result); }
    catch (failure) { if (alive.current && sequence === detailSequence.current && feedSequence === requestSequence.current) setDetailError(errorMessage(failure)); }
    finally { if (alive.current && sequence === detailSequence.current) setDetailLoading(false); }
  };
  const close = () => { detailSequence.current++; selectedRef.current = null; setSelectedId(null); setDetail(null); setDetailError(''); setDetailLoading(false); };
  const apply = (next: FeedFilters) => {
    // Invalidate requests synchronously; effect cleanup alone leaves a brief race after a click.
    requestSequence.current++; close(); setSummary(undefined); setMapCounts(null); setRemoved([]); setPublications([]); setLoading(true); setRefreshing(false); setError(''); setLastSuccess(''); setLastSuccessClock(0); setFilterError('');
    setPagination({ count: 0, page: next.page, page_size: next.page_size, total_pages: 1 });
    setFilters(next); setDraft(next); failureCount.current = 0;
  };
  const hasFilters = !!filters.q || filters.category !== 'ALL' || filters.urgency !== 'ALL' || !!filters.area && filters.area !== 'ALL';
  const profile = filters.profile ?? grant?.profile_ceiling ?? user.profile;
  const controls = expanded && <div className="recipient-scope-controls"><label className="field"><span>Recipient channel</span><select aria-label="Recipient channel" value={channelId} onChange={event => { const next = grants.find(value => value.channel.id === event.target.value); if (next) { apply({ ...initialFilters(), profile: next.profile_ceiling }); setChannelId(next.channel.id); } }}>{grants.map(value => <option key={value.channel.id} value={value.channel.id}>{value.channel.code} · {value.channel.name}</option>)}</select></label><label className="field"><span>Disclosure profile</span><select aria-label="Disclosure profile" value={profile ?? ''} onChange={event => { const next = allowedProfiles(grant!.profile_ceiling).find(value => value === event.target.value); if (next) apply({ ...filters, profile: next, area: undefined, page: 1 }); }}>{grant && allowedProfiles(grant.profile_ceiling).map(value => <option key={value} value={value}>{profileLabel(value)}</option>)}</select></label></div>;
  // Each publication still renders once; the overview only gives the first card more room.
  const featureFirst = page === 'overview' && pagination.page === 1 && publications.length > 1;
  const freshness = <div className={'freshness-bar ' + (stale ? 'stale' : '')}><div><span className="freshness-dot" /><strong>{accessLost ? 'Access unavailable' : loading ? 'Checking current access' : error ? 'Refresh failed · previously authorized content' : stale ? 'Refresh overdue · content may be stale' : 'Live channel · approved content'}</strong><span>{lastSuccess ? `Last successful refresh ${dateLabel(lastSuccess, true)}` : 'No successful refresh yet'}</span></div><button className="text-button" onClick={() => void refresh()} disabled={refreshing}><Icon name="refresh" size={16} />{refreshing ? 'Refreshing…' : 'Refresh now'}</button></div>;

  if (selectedId) return <>
    {controls}
    <BackButton onClick={close}>Back to publications</BackButton>
    <SectionHeading eyebrow="APPROVED PUBLICATION" title="Reviewed maintenance update" text={`${channel?.name ?? 'Assigned channel'} · ${profileLabel(profile)} disclosure`} />
    {freshness}
    {error && <Notice tone={accessLost ? 'error' : 'warning'}>{error}{!accessLost && <p>The last authorized content is dated above. Reconnect to confirm it is current.</p>}</Notice>}
    {removed.some(value => value.publication_id === selectedId) && <Notice tone="warning">This previously delivered publication was withdrawn or superseded. Viewed copies cannot be recalled.</Notice>}
    {detailError && <Notice tone="error">{detailError}</Notice>}
    {detailLoading ? <Loading text="Checking current publication access…" /> : detail && !accessLost && <section className="card publication-detail"><div className="card-heading"><span className="card-icon"><Icon name="shield" /></span><div><h3>{detail.projection.profile === 'DEMO-REDUCED' ? 'Approved reduced representation' : 'Approved representation'}</h3><p>Published {publishedLabel(detail.published_at, detail.projection.profile)} · {detail.channel.code}</p></div><span className="verified-label"><Icon name="check" size={15} />Human reviewed</span></div><ProjectionCard projection={detail.projection} /><div className="publication-footnote"><Icon name="shield" size={17} /><p>This is the full approved representation for your channel and profile. Access is checked on every refresh.</p></div></section>}
  </>;

  return <>
    <SectionHeading hero={page === 'overview'} eyebrow={page === 'overview' ? 'CHANNEL WORKSPACE' : 'APPROVED INFORMATION'} title={page === 'overview' ? `Welcome, ${user.display_name}.` : 'Channel publications'} text="Read maintenance updates explicitly approved for your current channel and disclosure profile." meta={page === 'overview' ? <><span><Icon name="feed" size={14} />{channel?.code ?? 'No current channel'}</span><span>{profileLabel(profile)} disclosure</span><span>Human reviewed only</span></> : undefined} />
    {controls}
    {page === 'overview' && <div className="metrics-grid recipient-metrics"><MetricCard label="Matching publications" value={pagination.count} detail="Total under the applied filters and current grant" icon="feed" /><MetricCard label={summary ? "Matching priority publications" : "Priority on this page"} value={summary?.by_urgency.PRIORITY ?? publications.filter(publication => publication.projection.urgency === 'PRIORITY').length} detail={summary ? "Total under the same current filters" : "Subtotal for the displayed page"} icon="clock" tone="amber" /><MetricCard label={summary ? "Matching areas" : "Areas on this page"} value={profile === 'DEMO-SUMMARY' ? 'Not disclosed' : summary ? Object.keys(summary.by_area).length : new Set(publications.map(publication => publication.projection.area_label).filter(Boolean)).size} detail={summary ? "Area disclosure for the current filtered dataset" : "Distinct areas on the displayed page"} icon="report" tone="blue" /><div className="profile-card"><Icon name="shield" size={23} /><span>Your disclosure profile</span><strong>{profile ? profileLabel(profile) : ''}</strong><p>Human reviewed · reduced content</p></div></div>}
    {freshness}
    {error && <Notice tone={accessLost ? 'error' : 'warning'}>{error}{!accessLost && <p>Previously authorized content is shown with its last successful refresh. It may no longer be current.</p>}</Notice>}
    <section className="card feed-card"><div className="card-heading"><div><h3>{channel?.name ?? 'Your sharing channel'}</h3><p>{channel?.code} · Approved publications only</p></div><span className="verified-label"><Icon name="shield" size={15} />Human reviewed</span></div>
      {expanded && profile !== 'DEMO-SUMMARY' && mapCounts && !accessLost && !loading && <AreaMap counts={mapCounts} selected={filters.area} onArea={area => apply({ ...filters, area, page: 1 })} />}
      {expanded && profile === 'DEMO-SUMMARY' && <p className="profile-map-note">No map for this profile</p>}
      <form className="feed-toolbar recipient-filter-form" noValidate onSubmit={event => { event.preventDefault(); const issue = validateFeedFilters(draft); setFilterError(issue); if (!issue) apply({ ...draft, q: draft.q.trim(), page: 1 }); }}>
        <label className="search-field"><Icon name="search" size={18} /><span className="sr-only">Search approved publications</span><input type="search" placeholder="Search approved updates…" value={draft.q} onChange={event => setDraft({ ...draft, q: event.target.value })} aria-invalid={!!filterError} aria-describedby={filterError ? 'feed-filter-error' : undefined} /></label>
        <label className="filter-field"><span className="sr-only">Filter approved category</span><select value={draft.category} onChange={event => setDraft({ ...draft, category: event.target.value as FeedFilters['category'] })}><option value="ALL">All categories</option>{Object.entries(CATEGORY_LABELS).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label>
        <label className="filter-field"><span className="sr-only">Filter approved urgency</span><select value={draft.urgency} onChange={event => setDraft({ ...draft, urgency: event.target.value as FeedFilters['urgency'] })}><option value="ALL">All urgency</option><option value="ROUTINE">Routine</option><option value="PRIORITY">Priority</option></select></label>
        {expanded && profile !== 'DEMO-SUMMARY' && <label className="filter-field"><span className="sr-only">Filter approved area</span><select value={draft.area ?? 'ALL'} onChange={event => setDraft({ ...draft, area: event.target.value as FeedFilters['area'] })}><option value="ALL">All areas</option>{['Area A', 'Area B', 'Area C'].map(area => <option key={area}>{area}</option>)}</select></label>}
        <div className="button-row"><button className="button secondary" type="submit">Apply filters</button><button className="text-button" type="button" onClick={() => apply({ ...initialFilters(), page_size: filters.page_size, ...(filters.profile ? { profile: filters.profile } : {}) })}>Clear filters</button></div>
        {filterError && <p className="field-error" id="feed-filter-error" role="alert">{filterError}</p>}
      </form>
      {loading ? <Loading rows={3} text="Checking your channel and loading approved content…" /> : accessLost ? <EmptyState icon="lock" title="Channel access unavailable" text="The authorized content has been cleared. Restore your current grant or sign in again before reading publications." action={<button className="button secondary" onClick={() => void refresh()}>Recheck access</button>} /> : !publications.length ? <EmptyState icon="feed" title={hasFilters ? 'No matching publications' : pagination.count ? 'No publications on this page' : 'No approved reports available'} text={hasFilters ? 'Adjust your search, category or urgency to find updates in the approved dataset.' : pagination.count ? 'The available results changed. Use Previous to return to an available page.' : 'There are no approved publications available in this channel and profile. A separate reviewer must explicitly approve content before it appears here.'} /> : <div className="publication-grid">{publications.map((publication, index) => <article className={'publication-card' + (featureFirst && index === 0 ? ' is-featured' : '')} key={publication.id}>{featureFirst && index === 0 && <span className="featured-label">TOP OF YOUR FEED</span>}<div className="publication-card-top"><span className="category-pill">{CATEGORY_LABELS[publication.projection.category]}</span><span className={'urgency-label ' + (publication.projection.urgency === 'PRIORITY' ? 'priority' : '')}>{publication.projection.urgency === 'PRIORITY' ? 'Priority' : 'Routine'}</span></div><h3><button onClick={() => void open(publication)}>{publication.projection.title}</button></h3><p>{publication.projection.text}</p><div className="publication-card-context">{publication.projection.profile !== 'DEMO-SUMMARY' && <span>{publication.projection.area_label}</span>}<span>{projectionObserved(publication.projection)}</span><span>{profileLabel(publication.projection.profile)}</span></div><div className="publication-card-bottom"><span><Icon name="check" size={14} />Human reviewed</span><button className="text-button" onClick={() => void open(publication)}>Read update<Icon name="arrow" size={16} /></button></div></article>)}</div>}
      {!accessLost && <Pagination data={pagination} busy={loading || refreshing} onPage={next => apply({ ...filters, page: next })} onPageSize={size => apply({ ...filters, page: 1, page_size: size })} />}
    </section>
    {!accessLost && removed.length > 0 && <section className="card removed-publications" aria-label="Previously delivered publications"><h3>Previously delivered publications</h3><p>{removed.length} previously delivered {removed.length === 1 ? 'publication is' : 'publications are'} withdrawn or superseded. Viewed copies cannot be recalled.</p></section>}
    <p className="feed-boundary-note"><Icon name="lock" size={15} />Your workspace uses only approved content. Originals, review notes and pending-report totals are private.</p>
  </>;
}
