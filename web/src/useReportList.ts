import { useCallback, useEffect, useRef, useState } from 'react';
import { api, errorMessage } from './api';
import type { PageResult, ReportFilters, SourceSummary } from './types';
import { parseReportActivity } from './reportActivity';

export function useReportList(reviewer = false) {
  const [filters, updateFilters] = useState<ReportFilters>({ status: reviewer ? 'AWAITING_REVIEW' : 'ALL', date_from: '', date_to: '', page: 1, page_size: 10 });
  const [data, setData] = useState<PageResult<SourceSummary>>({ results: [], count: 0, page: 1, page_size: 10, total_pages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refreshed, setRefreshed] = useState('');
  const sequence = useRef(0);
  const setFilters = (next: ReportFilters) => { sequence.current++; setLoading(true); setError(''); updateFilters(next); };
  // A background poll keeps the current rows, counts and keyboard focus in place while it
  // checks; explicit refreshes and filter changes still hide earlier results until they settle.
  const refresh = useCallback(async (background = false) => {
    const request = ++sequence.current;
    if (!background) setLoading(true);
    try {
      const result = await (reviewer ? api.queue(filters) : api.reports(filters));
      if (request !== sequence.current) return;
      setData(result); setError(''); setRefreshed(new Date().toISOString());
    } catch (failure) {
      if (request !== sequence.current) return;
      // Do not show stale rows/counts under newly selected filters or changed permissions.
      setData({ results: [], count: 0, page: filters.page, page_size: filters.page_size, total_pages: 1 });
      setError(errorMessage(failure));
    } finally { if (request === sequence.current) setLoading(false); }
  }, [filters, reviewer]);
  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => { if (document.visibilityState === 'visible') void refresh(true); }, 10_000);
    return () => { sequence.current++; window.clearInterval(timer); };
  }, [refresh]);
  const activity = loading || error ? null : parseReportActivity(data.activity);
  return { data, activity, filters, setFilters, loading, error, refreshed, refresh };
}
