package org.kapit.c2.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
internal fun HomeScreen(state: MobileUiState, actions: MobileActions) {
    val context = state.context ?: return
    PageTitle("Mobile workspace", "Keep maintenance moving.", "Capture clearly. Deliver reliably. Follow every review.")
    ConnectionStatus(state.connection)
    if (!context.templateSupported) NoticeCard(MobileNotice.TEMPLATE_UNSUPPORTED)
    ContentCard {
        Fact("Signed in", context.displayName)
        Fact("Unit", context.unitLabel)
        QuietText(context.offlineAccessLabel)
        PrimaryAction("Create maintenance report", !state.busy && state.capabilities.saveDraft && context.templateSupported, KapitIcon.PLUS) {
            actions.dispatch(MobileAction.NewDraft(state.accountGeneration))
        }
    }
    SectionHeading("On this phone")
    if (state.localDataLoaded) {
        ContentCard {
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatTile("Editable drafts", state.drafts.size.toString(), Modifier.weight(1f))
                StatTile("Waiting for confirmed receipt", state.outbox.count { it.delivery != DeliveryUi.RECEIVED }.toString(), Modifier.weight(1f))
            }
            SecondaryAction("Open drafts") { actions.dispatch(MobileAction.Navigate(state.accountGeneration, MobileScreen.DRAFTS)) }
            SecondaryAction("Open outbox") { actions.dispatch(MobileAction.Navigate(state.accountGeneration, MobileScreen.OUTBOX)) }
        }
    } else EmptyState("Loading protected work", "Drafts and outbox counts appear after the account store is opened and checked.")
    ContentCard {
        SectionHeading("One clear path to review")
        StepRow(1, "Saved", "An editable draft exists only on this phone.")
        StepRow(2, "Queued", "A fixed submission is waiting for a valid server receipt.")
        StepRow(3, "Received", "The server has committed the submission. Processing follows.")
        StepRow(4, "Reviewed & shared", "A human reviews the prepared version. Only its approved projection can be shared.")
    }
}

@Composable
internal fun DraftsScreen(state: MobileUiState, actions: MobileActions) {
    PageTitle("On this phone", "Your drafts", "Editable work stays separate from fixed submissions in the outbox.")
    PrimaryAction("Create maintenance report", !state.busy && state.capabilities.saveDraft && state.context?.templateSupported == true) {
        actions.dispatch(MobileAction.NewDraft(state.accountGeneration))
    }
    when {
        !state.localDataLoaded -> EmptyState("Drafts are loading", "Protected storage must finish opening before drafts can be shown.")
        state.drafts.isEmpty() -> EmptyState("A clean starting point", "Create a maintenance report and save it here while you work. Incomplete drafts are welcome.")
        else -> state.drafts.forEach { draft ->
            ContentCard {
                StatusPill("Saved draft")
                SectionHeading(draft.title)
                Fact("Category", draft.categoryLabel)
                QuietText("Saved ${draft.savedAtLabel}")
                SecondaryAction("Edit draft", !state.busy) { actions.dispatch(MobileAction.OpenDraft(state.accountGeneration, draft.id)) }
            }
        }
    }
}

@Composable
internal fun OutboxScreen(state: MobileUiState, actions: MobileActions) {
    PageTitle("Delivery", "Outbox", "Pending submissions stay here until a valid receipt is saved. Retry keeps the original submission unchanged.")
    ConnectionStatus(state.connection)
    PrimaryAction("Sync now", state.capabilities.synchronize && !state.busy && state.localDataLoaded, KapitIcon.REFRESH) {
        actions.dispatch(MobileAction.SyncNow(state.accountGeneration))
    }
    when {
        !state.localDataLoaded -> EmptyState("Outbox is loading", "Protected storage must finish opening before delivery state can be shown.")
        state.outbox.isEmpty() -> EmptyState("Nothing queued yet", "Review a completed draft and confirm submission to add it to the outbox.")
        else -> state.outbox.forEach { item ->
            ContentCard {
                StatusPill(item.delivery.label, warning = item.pause != null || item.delivery in setOf(DeliveryUi.NEEDS_CORRECTION, DeliveryUi.CONFLICT),
                    positive = item.pause == null && item.delivery == DeliveryUi.RECEIVED)
                SectionHeading(item.title)
                QuietText("Queued ${item.queuedAtLabel}")
                item.pause?.let { Fact("Paused", it.message) }
                item.retryAtLabel?.let { Fact("Next attempt", it) }
                when (item.delivery) {
                    DeliveryUi.QUEUED -> QuietText("No server receipt has been confirmed.")
                    DeliveryUi.SENDING -> QuietText("Waiting for a valid receipt. A lost response does not prove rejection.")
                    DeliveryUi.RECEIVED -> QuietText("Delivery is confirmed. Check Reports for current processing, review and sharing status.")
                    DeliveryUi.NEEDS_CORRECTION -> QuietText("This fixed submission needs a new correction. It will not be edited or silently replaced.")
                    DeliveryUi.CONFLICT -> QuietText("Keep this submission while you compare it with the current report. Nothing is merged automatically.")
                }
                if (item.canRetry && item.pause == null && item.delivery in setOf(DeliveryUi.QUEUED, DeliveryUi.SENDING)) {
                    SecondaryAction("Retry same submission", !state.busy && state.capabilities.synchronize) {
                        actions.dispatch(MobileAction.RetryOperation(state.accountGeneration, item.id))
                    }
                }
                if (item.canCreateCorrection) SecondaryAction("Review correction options", !state.busy) {
                    actions.dispatch(MobileAction.ReconcileOperation(state.accountGeneration, item.id))
                }
            }
        }
    }
    QuietText("Android may delay background work. After a force-stop, open the app and unlock it to resume checking pending submissions.")
}

@Composable
internal fun ReportsScreen(state: MobileUiState, actions: MobileActions) {
    val page = state.reports
    PageTitle("Your reports", "Follow the review", "Only reports available to your current account are shown. Cached status can change after the next online check.")
    SecondaryAction("Refresh report status", state.capabilities.readReports && !state.busy, KapitIcon.REFRESH) {
        actions.dispatch(MobileAction.LoadReports(state.accountGeneration, page.filter, page.page))
    }
    SectionHeading("Filter by status")
    // Two columns wrap labels at large font sizes instead of hiding choices in a horizontal strip.
    ReportFilterUi.entries.chunked(2).forEach { choices ->
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            choices.forEach { filter ->
                FilterChip(selected = page.filter == filter, enabled = state.capabilities.readReports && !state.busy,
                    onClick = { actions.dispatch(MobileAction.LoadReports(state.accountGeneration, filter, 1)) },
                    label = { Text(filter.label, Modifier.padding(vertical = 6.dp)) }, modifier = Modifier.weight(1f).heightInTouchTarget())
            }
        }
    }
    if (state.capabilities.readReports) page.lastCheckedLabel?.let { QuietText("Last checked $it") }
    when {
        !state.capabilities.readReports -> EmptyState("Report service unavailable", "Saved drafts and queued work remain on this phone. Current server status is unavailable.")
        !page.loaded -> EmptyState("Report status has not loaded", "Refresh when the local service is available. No report count has been confirmed yet.")
        page.items.isEmpty() -> EmptyState("No reports in this view", "Try another status filter, or check again after a queued submission receives a server receipt.")
        else -> page.items.forEach { report ->
            ContentCard {
                StatusPill(report.statusLabel, warning = report.statusLabel.contains("return", ignoreCase = true),
                    positive = report.statusLabel.equals("Approved", ignoreCase = true))
                SectionHeading(report.reference)
                Fact("Report", "${report.categoryLabel} · ${report.areaLabel}")
                QuietText("Observed ${report.observedDateLabel} · Revision ${report.revision}")
                SecondaryAction("Open report", !state.busy) {
                    actions.dispatch(MobileAction.OpenReport(state.accountGeneration, report.id, report.revision))
                }
            }
        }
    }
    if (state.capabilities.readReports && page.loaded) {
        QuietText("${page.totalCount} report${if (page.totalCount == 1) "" else "s"} in this view")
        if (page.totalPages > 0) {
            Text("Page ${page.page} of ${page.totalPages}", style = MaterialTheme.typography.bodyMedium)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(onClick = { actions.dispatch(MobileAction.LoadReports(state.accountGeneration, page.filter, page.page - 1)) },
                    enabled = page.page > 1 && !state.busy && state.capabilities.readReports, modifier = Modifier.weight(1f).heightInTouchTarget()) { Text("Previous") }
                OutlinedButton(onClick = { actions.dispatch(MobileAction.LoadReports(state.accountGeneration, page.filter, page.page + 1)) },
                    enabled = page.page < page.totalPages && !state.busy && state.capabilities.readReports, modifier = Modifier.weight(1f).heightInTouchTarget()) { Text("Next") }
            }
        }
    }
}

@Composable
internal fun ReportDetailScreen(state: MobileUiState, actions: MobileActions) {
    val report = state.reportDetail
    if (!state.capabilities.readReports || report == null) {
        EmptyState("Report unavailable", "The report has not loaded or is outside current access. Return to your reports and refresh.")
        return
    }
    PageTitle("Private report detail", report.reference, "Revision ${report.revision} · This is your original source view, not a recipient projection.")
    SecondaryAction("Back to reports") { actions.dispatch(MobileAction.Navigate(state.accountGeneration, MobileScreen.REPORTS)) }
    ContentCard {
        SectionHeading("Delivery is one step")
        StageRow("Delivery", report.delivery.label, when (report.delivery) {
            DeliveryUi.RECEIVED -> StageTone.DONE
            DeliveryUi.NEEDS_CORRECTION, DeliveryUi.CONFLICT -> StageTone.ATTENTION
            else -> StageTone.PENDING
        })
        StageRow("Processing", report.processing?.label ?: "Not yet verified", when (report.processing) {
            ProcessingUi.PREPARED -> StageTone.DONE
            ProcessingUi.FAILED -> StageTone.ATTENTION
            else -> StageTone.PENDING
        })
        StageRow("Human review", report.review?.label ?: "Not yet verified", when (report.review) {
            ReviewUi.APPROVED -> StageTone.DONE
            ReviewUi.RETURNED, ReviewUi.REJECTED -> StageTone.ATTENTION
            else -> StageTone.PENDING
        })
        StageRow("Sharing", report.sharing.label, if (report.sharing == SharingUi.SHARED) StageTone.DONE else StageTone.PENDING)
        report.lastCheckedLabel?.let { QuietText("Last checked $it") }
    }
    report.feedback?.let { ContentCard { Fact("Private reviewer feedback", it) } }
    if (android.os.Build.VERSION.SDK_INT >= 35) {
        androidx.compose.runtime.key(state.accountGeneration, report.revisionId, report.history.firstOrNull()?.revision == report.revision) { PrivatePhotoPanel(state, actions, report) }
    }
    if (report.canCorrect && report.review == ReviewUi.RETURNED) {
        PrimaryAction("Create returned-report correction", state.capabilities.saveDraft && state.context?.templateSupported == true && !state.busy) {
            actions.dispatch(MobileAction.CorrectReport(state.accountGeneration, report.reportId, report.revision))
        }
        QuietText("This creates a new editable draft. The current received revision and its history remain unchanged.")
    }
    ContentCard {
        SectionHeading("Original maintenance details")
        Fact("Observed at", report.form.observedAt)
        Fact("Category", report.form.category?.label ?: "Unavailable")
        Fact("Urgency", report.form.urgency?.label ?: "Unavailable")
        Fact("Area", report.form.area?.wireValue ?: "Unavailable")
        Fact("Site label", report.form.siteLabel)
        Fact("Reporter label", report.form.reporterLabel)
        Fact("Maintenance details", report.form.narrative)
        Fact("Assistance requested", report.form.assistance?.wireValue ?: "Unavailable")
    }
    if (report.history.isNotEmpty()) ContentCard {
        SectionHeading("Received revision history")
        report.history.forEach { revision ->
            Fact("Revision ${revision.revision}", "${revision.statusLabel} · ${revision.receivedAtLabel}")
            if (revision.revision == report.revision) StatusPill("Viewing this revision", positive = true)
            else TextButton(onClick = { actions.dispatch(MobileAction.OpenReport(state.accountGeneration, report.reportId, revision.revision)) },
                enabled = state.capabilities.readReports && !state.busy, modifier = Modifier.heightInTouchTarget()) { Text("Open revision ${revision.revision}") }
        }
    }
}

@Composable
internal fun AccountScreen(state: MobileUiState, actions: MobileActions) {
    val context = state.context ?: return
    var confirmSignOut by remember { mutableStateOf(false) }
    var submitted by remember(state.interactionRevision) { mutableStateOf(false) }
    PageTitle("Account", "Your protected workspace", "Access is tied to this account and its current organization, unit and channel permissions.")
    ContentCard {
        Fact("Account", context.displayName)
        Fact("Organization", context.organizationLabel)
        Fact("Unit", context.unitLabel)
        Fact("Channel", context.channelLabel)
        Fact("Disclosure profile", context.profileLabel)
        Fact("Offline access", context.offlineAccessLabel)
    }
    ContentCard {
        SectionHeading("Lock without losing pending work")
        Text("Locking closes the protected workspace. Signing out closes local access and retains encrypted drafts and pending submissions. Server revocation is shown as confirmed only after the service acknowledges it.")
        PrimaryAction("Lock workspace", icon = KapitIcon.LOCK) { actions.dispatch(MobileAction.Lock(state.accountGeneration)) }
        SecondaryAction("Sign out on this phone", !state.busy && !submitted) { confirmSignOut = true }
    }
    ContentCard {
        SectionHeading("Device access & recovery")
        Text("Manage your own enrolled devices from the website's account page. Revocation stops future online access after the server records it.")
        QuietText("A disconnected phone cannot learn about revocation immediately. Device unlock and the bounded offline lease still apply.")
        QuietText("Lost encryption keys, uninstalling or clearing app data may make unsent work unrecoverable. There is no automatic transfer to a different account.")
    }
    if (confirmSignOut) AlertDialog(onDismissRequest = { confirmSignOut = false }, title = { Text("Sign out and keep pending work?") },
        text = { Text("Encrypted drafts and queued submissions will remain on this phone. Sign in to this same account again to restore authorized access. Nothing is reassigned or deleted.") },
        confirmButton = { TextButton(enabled = !submitted && !state.busy, onClick = {
            confirmSignOut = false
            submitted = true
            actions.dispatch(MobileAction.SignOut(state.accountGeneration))
        }) { Text("Sign out") } },
        dismissButton = { TextButton(onClick = { confirmSignOut = false }) { Text("Stay signed in") } })
}

@Composable
private fun ConnectionStatus(connection: ConnectionUi) {
    StatusPill(when (connection) {
        ConnectionUi.NOT_CHECKED -> "Connection not checked"
        ConnectionUi.CONNECTED -> "Local service reachable"
        ConnectionUi.OFFLINE -> "Offline · pending work stays here"
        ConnectionUi.CONNECTING -> "Checking local connection"
        ConnectionUi.UNAVAILABLE -> "Local service unavailable"
    }, warning = connection != ConnectionUi.CONNECTED, positive = connection == ConnectionUi.CONNECTED)
}
