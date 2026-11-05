export type Role = 'submitter' | 'reviewer' | 'recipient' | 'administrator';
export type Category = 'INFRASTRUCTURE' | 'WATER_SUPPLY' | 'EQUIPMENT';
export type Urgency = 'ROUTINE' | 'PRIORITY';
export type Area = 'Area A' | 'Area B' | 'Area C';
export type Assistance = 'Repair assistance' | 'Inspection' | 'Replacement parts';
export type Profile = 'DEMO-FULL' | 'DEMO-REDUCED' | 'DEMO-SUMMARY';
export interface Context { id: string; code: string; name: string }
export interface ChannelGrant { channel: Context; profile_ceiling: Profile }
export interface User {
  id: string; username: string; display_name: string; role: Role;
  unit: Context | null; channel: Context | null; profile: Profile | null;
  channels?: Context[]; grants?: ChannelGrant[];
}
export interface EnrolledDevice {
  id: string; label: string; created_at: string; last_authenticated_at: string; revoked_at: string | null;
}
export interface EnrolledDevices { results: EnrolledDevice[]; count: number }
export interface DeviceRevocation { id: string; revoked: true; revoked_at: string }
export interface Payload {
  observed_at: string; category: Category; urgency: Urgency; area_label: Area;
  site_label: string; reporter_label: string; narrative: string; assistance_requested: Assistance;
}
export interface Operation {
  operation_id: string; report_id: string; expected_revision: number;
  template_version: 'demo-maintenance-v1'; payload: Payload;
  correction_reason?: string;
}
export interface Receipt {
  operation_id: string; report_id: string; revision_id: string; revision_no: number;
  delivery_status: 'RECEIVED'; processing_status: 'PENDING'; shared: false;
}
export type ReportStatus = 'PENDING' | 'PROCESSING' | 'AWAITING_REVIEW' | 'APPROVED' | 'RETURNED' | 'REJECTED' | 'FAILED';
export interface SourceSummary {
  id: string; reference: string; category: Category; urgency: Urgency; area_label: Area;
  created_at: string; observed_date: string; revision_no: number; status: ReportStatus;
  variant_id: string | null; feedback: string | null;
}
export interface RevisionSummary { revision_no: number; received_at: string; status: ReportStatus }
export interface Workflow {
  revision_no: number; is_current: boolean; received_at: string;
  processing: { state: 'PENDING' | 'PROCESSING' | 'DONE' | 'FAILED'; attempts: number };
  review: { state: 'NOT_READY' | 'AWAITING_REVIEW' | 'APPROVED' | 'RETURNED' | 'REJECTED'; prepared_at: string | null; decided_at: string | null };
  sharing: { state: 'NOT_SHARED' | 'AVAILABLE' | 'WITHDRAWN' | 'SUPERSEDED' | 'UNAVAILABLE'; published_at: string | null };
}
export interface SourceDetail { report: SourceSummary; payload: Payload; receipt: Receipt; can_correct: boolean; history: RevisionSummary[]; workflow: Workflow; correction_reason?: string }
export interface ReportFilters { status: ReportStatus | 'ALL'; date_from: string; date_to: string; page: number; page_size: number }
export interface ReportActivityCounts { total: number; by_status: Record<ReportStatus, number>; unclassified: number }
export type JobStatus = 'PENDING' | 'PROCESSING' | 'DONE' | 'FAILED';
export type FailureCode = 'RULE_PROCESSING_FAILED' | 'ATTEMPTS_EXHAUSTED' | 'STALE_CONTEXT';
export type BackupState = 'CURRENT' | 'DUE' | 'OVERDUE' | 'NONE' | 'UNAVAILABLE';
export interface OperationsHealth {
  generated_utc: string;
  jobs: { by_status: Record<JobStatus, number>; unknown_status: number; expired_leases: number; missing_leases: number; oldest_pending_available_age_seconds: number | null; failures_by_code: Record<FailureCode, number>; unclassified_failures: number };
  backup: { status: BackupState; last_verified_utc: string | null; age_seconds: number | null; interval_hours: number; rpo_hours: number };
}
export interface PageResult<T> { results: T[]; count: number; page: number; page_size: number; total_pages: number; activity?: unknown }
export interface AdminContext {
  authorities?: ('POLICY' | 'INTEGRATION')[];
  units: (Context & { active: boolean })[]; channels: (Context & { active: boolean })[];
  channel_sources: { unit_id: string; channel_id: string; active: boolean }[];
}
export interface AdminUser {
  id: string; username: string; display_name: string; role: Role; is_active: boolean;
  permission_version: number; unit_id: string | null; channel_id: string | null;
}
export interface PolicyProposal {
  id: string; kind: 'ACTIVATE' | 'DEACTIVATE'; target_policy_id: string; target_rules_hash: string;
  expected_active_policy_id: string | null; proposer_id: string; proposed_at: string; expires_at: string; applied?: boolean;
}
export interface PolicyState {
  active_policy_id: string | null; policy_epoch: number;
  policies: { id: string; version: string; rules_hash: string; active: boolean; supported: boolean }[];
  proposals: PolicyProposal[];
}
export interface IntegrationRequest {
  id: string; requester_id: string; channel_id: string; profile_ceiling: Profile; label: string;
  expires_at: string; collect_deadline: string; created_at: string; approved?: boolean;
}
export interface IntegrationClientMetadata {
  id: string; request_id: string; channel_id: string; profile_ceiling: Profile; label: string; key_prefix: string;
  created_at: string; expires_at: string; revoked_at: string | null;
}
export interface IntegrationState {
  clients: IntegrationClientMetadata[]; requests: IntegrationRequest[];
  page: number; page_size: number; client_count: number; request_count: number; clients_more: boolean; requests_more: boolean;
}
export interface AccountFields { display_name: string; role: Role; is_active: boolean; unit_id: string | null; channel_id: string | null }
export interface AdminFilters { q: string; role: Role | 'ALL'; active: 'true' | 'false' | 'ALL'; page: number; page_size: number }
interface ProjectionBase { title: string; text: string; category: Category; urgency: Urgency; verification: 'Human reviewed' }
export interface ReducedProjection extends ProjectionBase { profile: 'DEMO-REDUCED'; area_label: Area; assistance_requested: Assistance; observed_date: string; observed_hour?: never; observed_week?: never; originating_unit?: never }
export interface FullProjection extends ProjectionBase { profile: 'DEMO-FULL'; area_label: Area; assistance_requested: Assistance; observed_hour: string; originating_unit: { code: string; name: string }; observed_date?: never; observed_week?: never }
export interface SummaryProjection extends ProjectionBase { profile: 'DEMO-SUMMARY'; observed_week: string; area_label?: never; assistance_requested?: never; observed_date?: never; observed_hour?: never; originating_unit?: never }
export type Projection = ReducedProjection | FullProjection | SummaryProjection;
export interface Binding {
  revision_id: string; revision_no: number; candidate_hash: string; policy_version: string;
  policy_hash: string; profile: string; channel_ids: string[];
}
export interface ReviewDetail { report: SourceSummary; source: Payload; candidate: Projection; warnings: string[]; binding: Binding }
export type ReviewAction = 'APPROVE' | 'RETURN' | 'REJECT';
export interface DecisionOperation { operation_id: string; action: ReviewAction; expected: Binding; reason: string }
export interface DecisionResult { decision_id: string; action: ReviewAction; publication_ids: string[]; report_status: ReportStatus }
export interface BatchBinding {
  revision_id: string; revision_no: number; policy_version: string; policy_hash: string; scope_context_hash: string | null;
  candidates: { variant_id: string; profile: Profile; candidate_hash: string; channel_ids: string[] }[];
}
export interface BatchReviewDetail { report: SourceSummary; source: Payload; candidates: { variant_id: string; profile: Profile; candidate: Projection; warnings: string[]; state: string }[]; binding: BatchBinding; correction_reason?: string }
export interface BatchDecisionOperation { operation_id: string; action: ReviewAction; approve_profiles: Profile[]; expected: BatchBinding; reason: string | null }
export interface BatchDecisionResult { batch_id: string; action: ReviewAction; report_status: ReportStatus; publication_ids: string[]; approved_profiles: Profile[]; withheld_profiles: Profile[]; withheld_variant_ids: string[] }
export interface WithdrawalOperation { operation_id: string; expected_revision_no: number; reason: string }
export interface WithdrawalResult { withdrawal_id: string; report_status: 'WITHDRAWN'; publication_ids: string[] }
export interface Publication { id: string; published_at: string; channel: Context; projection: Projection }
export interface FeedFilters { q: string; category: Category | 'ALL'; urgency: Urgency | 'ALL'; page: number; page_size: number; area?: Area | 'ALL'; profile?: Profile }
export interface FeedSummary { by_category: Partial<Record<Category, number>>; by_urgency: Partial<Record<Urgency, number>>; by_area: Partial<Record<Area, number>>; unmapped: number }
export interface MapCounts { areas: { area_id: string; count: number }[]; unmapped: number }
export interface RemovedPublication { publication_id: string; state: 'WITHDRAWN' | 'SUPERSEDED' }
export interface Feed extends PageResult<Publication> { refreshed_at: string; profile?: Profile; summary?: FeedSummary }
