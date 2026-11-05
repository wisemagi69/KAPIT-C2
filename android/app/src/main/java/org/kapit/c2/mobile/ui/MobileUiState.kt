package org.kapit.c2.mobile.ui

/**
 * Presentation only. The controller must publish fresh snapshots, never mutable collections,
 * and remove protected models when access closes. The composable also gates all protected content.
 * No model belongs in a saved-state bundle, log, notification, or WorkManager input.
 */
data class MobileUiState(
    val accountGeneration: Long = 0,
    val access: MobileAccess = MobileAccess.STARTING,
    val screen: MobileScreen = MobileScreen.HOME,
    val capabilities: MobileCapabilities = MobileCapabilities(),
    val context: AccountContextUi? = null,
    val connection: ConnectionUi = ConnectionUi.NOT_CHECKED,
    val busy: Boolean = false,
    /** Increment after every completed/rejected command, including failure, to release UI latches. */
    val interactionRevision: Long = 0,
    val notice: MobileNotice? = null,
    val signInPurpose: SignInPurpose = SignInPurpose.ENROLL_OR_RECOVER,
    val localDataLoaded: Boolean = false,
    val drafts: List<DraftUi> = emptyList(),
    val outbox: List<OutboxItemUi> = emptyList(),
    val reports: ReportPageUi = ReportPageUi(),
    val editor: EditorUi? = null,
    val reportDetail: ReportDetailUi? = null,
) {
    val showsProtectedContent: Boolean get() = access == MobileAccess.READY && context != null
    override fun toString(): String = "MobileUiState(access=$access, screen=$screen, content=redacted)"
}

enum class MobileAccess {
    STARTING, SIGNED_OUT, READY, LOCKED, UNLOCK_REQUIRED, LEASE_EXPIRED,
    KEY_UNAVAILABLE, ENROLLMENT_SUSPENDED, CONTEXT_CHANGED, UNSUPPORTED_DEVICE, STORAGE_UNAVAILABLE, TEMPLATE_UNSUPPORTED,
}

enum class MobileScreen { HOME, DRAFTS, EDITOR, OUTBOX, REPORTS, REPORT_DETAIL, ACCOUNT }
enum class SignInPurpose { ENROLL_OR_RECOVER, RECOVER_ENROLLMENT }
enum class ConnectionUi { NOT_CHECKED, CONNECTED, OFFLINE, CONNECTING, UNAVAILABLE }

data class MobileCapabilities(
    val authenticate: Boolean = false,
    val unlock: Boolean = false,
    val saveDraft: Boolean = false,
    val queueSubmission: Boolean = false,
    val synchronize: Boolean = false,
    val readReports: Boolean = false,
)

data class AccountContextUi(
    val displayName: String,
    val organizationLabel: String,
    val unitLabel: String,
    val channelLabel: String,
    val profileLabel: String,
    val offlineAccessLabel: String,
    val templateSupported: Boolean,
) {
    override fun toString(): String = "AccountContextUi(redacted)"
}

/** Safe, allowlisted messages: never display a raw exception or an arbitrary server error body. */
enum class MobileNotice(val title: String, val message: String, val isError: Boolean = false) {
    DRAFT_SAVED("Draft saved", "Your editable draft is stored on this phone."),
    SUBMISSION_QUEUED("Queued on this phone", "The fixed submission is waiting for confirmed server receipt."),
    RECEIPT_SAVED("Receipt confirmed", "Delivery is recorded. Processing, human review and sharing are separate steps."),
    CONNECTION_UNAVAILABLE("Cannot reach the local service", "Check the local connection, then try again. Pending work is retained.", true),
    CREDENTIALS_REJECTED("Sign-in was not accepted", "Check your account details and try again.", true),
    VALIDATION_REQUIRED("Check the report", "Review the marked fields before submitting.", true),
    STORAGE_UNAVAILABLE("Protected storage is unavailable", "Your encrypted files are retained. Unlock or recover access before continuing.", true),
    CONTEXT_CHANGED("Account scope changed", "Existing submissions are paused. Reconcile them explicitly before sending with the new scope.", true),
    CONFLICT("A newer or conflicting revision exists", "The original submission is retained. Refresh the report and review the next step.", true),
    AUTH_REQUIRED("Sign in again", "Online authorization is required. Your pending work is retained.", true),
    TEMPORARY_FAILURE("Try again later", "The action was not confirmed. Pending work remains available after authorized unlock.", true),
    TEMPLATE_UNSUPPORTED("App update required", "This account uses an unsupported template. Existing pending submissions are preserved.", true),
    SIGNED_OUT_LOCAL("Signed out on this phone", "Pending encrypted work is retained. Server session revocation was not confirmed; manage enrolled devices from the website if needed."),
    SIGNED_OUT_CONFIRMED("Signed out", "This phone is signed out and the server confirmed session revocation. Pending encrypted work is retained."),
}

enum class MaintenanceCategory(val wireValue: String, val label: String) {
    INFRASTRUCTURE("INFRASTRUCTURE", "Infrastructure"),
    WATER_SUPPLY("WATER_SUPPLY", "Water supply"),
    EQUIPMENT("EQUIPMENT", "Equipment"),
}

enum class MaintenanceUrgency(val wireValue: String, val label: String) {
    ROUTINE("ROUTINE", "Routine"), PRIORITY("PRIORITY", "Priority"),
}

enum class MaintenanceArea(val wireValue: String) { A("Area A"), B("Area B"), C("Area C") }
enum class MaintenanceAssistance(val wireValue: String) {
    REPAIR("Repair assistance"), INSPECTION("Inspection"), PARTS("Replacement parts"),
}

enum class MaintenanceField(val label: String) {
    OBSERVED_AT("Observed at (with timezone)"), CATEGORY("Category"), URGENCY("Urgency"), AREA("Area"),
    SITE("Site label"), REPORTER("Reporter label"), NARRATIVE("Maintenance details"), ASSISTANCE("Assistance requested"),
}

data class MaintenanceForm(
    val observedAt: String = "",
    val category: MaintenanceCategory? = null,
    val urgency: MaintenanceUrgency? = null,
    val area: MaintenanceArea? = null,
    val siteLabel: String = "",
    val reporterLabel: String = "",
    val narrative: String = "",
    val assistance: MaintenanceAssistance? = null,
) {
    override fun toString(): String = "MaintenanceForm(redacted)"
    companion object { const val TEMPLATE_VERSION: String = "demo-maintenance-v1" }
}

data class DraftUi(val id: String, val title: String, val categoryLabel: String, val savedAtLabel: String) {
    override fun toString(): String = "DraftUi(redacted)"
}

data class EditorUi(
    val draftId: String,
    /** Stale draft revisions must be rejected by the controller's transaction. */
    val draftRevision: Long,
    val form: MaintenanceForm,
    val expectedReportRevision: Int = 0,
    val correctionReference: String? = null,
    val returnFeedback: String? = null,
    val serverFieldErrors: Map<MaintenanceField, String> = emptyMap(),
    val estimatedServerTimeMillis: Long? = null,
) {
    override fun toString(): String = "EditorUi(redacted)"
}

enum class DeliveryUi(val label: String) {
    QUEUED("Queued on this phone"), SENDING("Awaiting receipt"), RECEIVED("Received by server"),
    NEEDS_CORRECTION("Needs correction"), CONFLICT("Conflict to resolve"),
}

enum class PauseUi(val message: String) {
    AUTH_REQUIRED("Sign in to resume"), LOCKED("Unlock to resume"), LEASE_EXPIRED("Online sign-in required"),
    REVOKED("Enrollment revoked"), SCOPE_DENIED("Current access does not permit sending"),
    CONTEXT_CHANGED("Account scope changed; reconciliation required"),
}

data class OutboxItemUi(
    val id: String,
    val title: String,
    val queuedAtLabel: String,
    val delivery: DeliveryUi,
    val pause: PauseUi? = null,
    val retryAtLabel: String? = null,
    val canRetry: Boolean = false,
    val canCreateCorrection: Boolean = false,
) {
    override fun toString(): String = "OutboxItemUi(delivery=$delivery, pause=$pause, content=redacted)"
}

enum class ProcessingUi(val label: String) { PENDING("Pending"), PROCESSING("Processing"), PREPARED("Prepared"), FAILED("Failed; kept private") }
enum class ReviewUi(val label: String) { NOT_READY("Not ready"), AWAITING_REVIEW("Awaiting human review"), APPROVED("Approved"), RETURNED("Returned for correction"), REJECTED("Rejected") }
enum class SharingUi(val label: String) { NOT_SHARED("Not shared"), SHARED("Approved projection shared"), UNKNOWN("Not yet verified") }
enum class ReportFilterUi(val label: String) {
    ALL("All"), PENDING("Pending"), PROCESSING("Processing"), AWAITING_REVIEW("Awaiting review"),
    FAILED("Failed"), APPROVED("Approved"), RETURNED("Returned"), REJECTED("Rejected"),
}

data class ReportSummaryUi(
    val id: String,
    val reference: String,
    val categoryLabel: String,
    val areaLabel: String,
    val observedDateLabel: String,
    val revision: Int,
    val statusLabel: String,
) {
    override fun toString(): String = "ReportSummaryUi(redacted)"
}

data class ReportPageUi(
    val loaded: Boolean = false,
    val items: List<ReportSummaryUi> = emptyList(),
    val filter: ReportFilterUi = ReportFilterUi.ALL,
    val page: Int = 1,
    val totalPages: Int = 0,
    val totalCount: Int = 0,
    val lastCheckedLabel: String? = null,
)

data class ReportHistoryUi(val revision: Int, val receivedAtLabel: String, val statusLabel: String)
data class ReportDetailUi(
    val reportId: String,
    val reference: String,
    val revision: Int,
    val form: MaintenanceForm,
    val delivery: DeliveryUi,
    val processing: ProcessingUi?,
    val review: ReviewUi?,
    val sharing: SharingUi = SharingUi.UNKNOWN,
    val feedback: String? = null,
    val canCorrect: Boolean = false,
    val lastCheckedLabel: String? = null,
    val history: List<ReportHistoryUi> = emptyList(),
    val revisionId: String? = null,
    val photos: List<org.kapit.c2.mobile.domain.PhotoPending> = emptyList(),
    val photoStatus: String? = null,
) {
    override fun toString(): String = "ReportDetailUi(redacted)"
}
