package org.kapit.c2.mobile.ui

/**
 * Real controller seam. Reject stale generation on EVERY action, including navigation/read actions.
 * Validate current lease, keys, scope and template in the data layer; UI enablement is not authority.
 * Commands must not be logged. Retain the same commandId for repeated delivery of a user command;
 * only the durable queue transaction creates operation/report IDs. Publish a new interactionRevision
 * after success or denial. No callback here represents successful authentication or a server receipt.
 */
fun interface MobileActions { fun dispatch(action: MobileAction) }

sealed interface MobileAction {
    val generation: Long
    class QueuePhoto(override val generation: Long, val reportId: String, val revisionId: String,
        val revision: Int, val operationId: String, val capture: String, bytes: ByteArray) : MobileAction, java.io.Closeable {
        private val owned = bytes.also {
            if (it.size !in 4..org.kapit.c2.mobile.domain.PhotoPolicy.LOCAL_BYTES) throw org.kapit.c2.mobile.domain.StoreFailure(org.kapit.c2.mobile.domain.StoreCode.VALIDATION_ERROR)
            org.kapit.c2.mobile.domain.PhotoPolicy.validateCapture(capture)
        }.copyOf()
        private var closed = false
        @Synchronized fun bytes(): ByteArray { if (closed) throw org.kapit.c2.mobile.domain.StoreFailure(org.kapit.c2.mobile.domain.StoreCode.STALE_GENERATION); return owned.copyOf() }
        @Synchronized override fun close() { owned.fill(0); closed = true }
        override fun toString() = "QueuePhoto(redacted)"
    }
    data class UploadPhoto(override val generation: Long, val operationId: String) : MobileAction
    data class PhotoStatus(override val generation: Long, val evidenceId: String) : MobileAction

    class SignIn(
        override val generation: Long,
        val purpose: SignInPurpose,
        val username: String,
        val password: String,
    ) : MobileAction { override fun toString(): String = "SignIn(redacted)" }

    data class Unlock(override val generation: Long) : MobileAction
    data class BeginSignIn(override val generation: Long, val recoverEnrollment: Boolean) : MobileAction
    data class Navigate(override val generation: Long, val screen: MobileScreen) : MobileAction
    data class NewDraft(override val generation: Long) : MobileAction
    data class OpenDraft(override val generation: Long, val draftId: String) : MobileAction

    class SaveDraft(
        override val generation: Long,
        val commandId: String,
        val draftId: String,
        val expectedDraftRevision: Long,
        val form: MaintenanceForm,
    ) : MobileAction { override fun toString(): String = "SaveDraft(redacted)" }

    class QueueSubmission(
        override val generation: Long,
        val commandId: String,
        val draftId: String,
        val expectedDraftRevision: Long,
        val expectedReportRevision: Int,
        val form: MaintenanceForm,
    ) : MobileAction { override fun toString(): String = "QueueSubmission(redacted)" }

    data class SyncNow(override val generation: Long) : MobileAction
    data class RetryOperation(override val generation: Long, val localOperationId: String) : MobileAction
    data class ReconcileOperation(override val generation: Long, val localOperationId: String) : MobileAction
    data class LoadReports(override val generation: Long, val filter: ReportFilterUi, val page: Int) : MobileAction
    data class OpenReport(override val generation: Long, val reportId: String, val revision: Int) : MobileAction
    data class CorrectReport(override val generation: Long, val reportId: String, val expectedRevision: Int) : MobileAction
    data class Lock(override val generation: Long) : MobileAction
    data class SignOut(override val generation: Long) : MobileAction
    data class DismissNotice(override val generation: Long) : MobileAction
}
