package org.kapit.c2.mobile.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.focusable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.error
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import java.util.UUID

@Composable
internal fun MaintenanceEditor(state: MobileUiState, editor: EditorUi, actions: MobileActions) {
    var form by remember { mutableStateOf(editor.form) }
    var attempted by remember { mutableStateOf(false) }
    var editedFields by remember { mutableStateOf(emptySet<MaintenanceField>()) }
    var confirmation by remember { mutableStateOf<MaintenanceForm?>(null) }
    var confirmationCommandId by remember { mutableStateOf<String?>(null) }
    var leaving by remember { mutableStateOf(false) }
    var pending by remember(state.interactionRevision) { mutableStateOf(false) }
    var focusRequest by remember { mutableStateOf(0) }
    val focus = LocalFocusManager.current
    val focusTargets = remember { MaintenanceField.entries.associateWith { FocusRequester() } }
    val validation = if (attempted) validateMaintenanceForm(form, editor.estimatedServerTimeMillis) else emptyMap()
    val errors = editor.serverFieldErrors.filterKeys { it !in editedFields } + validation
    val supported = state.context?.templateSupported == true
    val enabled = !state.busy && !pending
    fun change(field: MaintenanceField, updated: MaintenanceForm) { form = updated; editedFields = editedFields + field }
    fun leave() {
        if (form != editor.form) leaving = true
        else actions.dispatch(MobileAction.Navigate(state.accountGeneration, MobileScreen.DRAFTS))
    }
    BackHandler { if (enabled) leave() }
    LaunchedEffect(focusRequest) {
        if (focusRequest > 0) MaintenanceField.entries.firstOrNull { errors.containsKey(it) }?.let { focusTargets.getValue(it).requestFocus() }
    }

    PageTitle(if (editor.expectedReportRevision > 0) "Returned correction" else "New maintenance report",
        if (editor.expectedReportRevision > 0) "Prepare a new revision" else "Capture the essentials.",
        "Drafts stay editable. Confirming submission creates a fixed copy for delivery and human review.")
    TextButton(onClick = { leave() }, enabled = enabled) { Text("Back to drafts") }
    if (!supported) NoticeCard(MobileNotice.TEMPLATE_UNSUPPORTED)
    if (editor.correctionReference != null) ContentCard {
        Fact("Correcting", "${editor.correctionReference} · revision ${editor.expectedReportRevision}")
        editor.returnFeedback?.let { Fact("Private reviewer feedback", it) }
        QuietText("The received original stays unchanged. This draft will become a new revision only after server acceptance.")
    }
    if (errors.isNotEmpty()) Text("${errors.size} field${if (errors.size == 1) " needs" else "s need"} attention. Review the marked fields.",
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive }, color = MaterialTheme.colorScheme.error)

    ContentCard {
        SectionHeading("01 · Observation")
        FormTextField(MaintenanceField.OBSERVED_AT, form.observedAt, errors[MaintenanceField.OBSERVED_AT], focusTargets.getValue(MaintenanceField.OBSERVED_AT),
            enabled, hint = "UTC format: 2026-10-17T09:30:00Z", sentenceCase = false) { change(MaintenanceField.OBSERVED_AT, form.copy(observedAt = it)) }
        ChoiceField(MaintenanceField.CATEGORY, MaintenanceCategory.entries, form.category, { it.label }, errors[MaintenanceField.CATEGORY],
            focusTargets.getValue(MaintenanceField.CATEGORY), enabled) { change(MaintenanceField.CATEGORY, form.copy(category = it)) }
        ChoiceField(MaintenanceField.URGENCY, MaintenanceUrgency.entries, form.urgency, { it.label }, errors[MaintenanceField.URGENCY],
            focusTargets.getValue(MaintenanceField.URGENCY), enabled) { change(MaintenanceField.URGENCY, form.copy(urgency = it)) }
    }
    ContentCard {
        SectionHeading("02 · Location & reporter")
        ChoiceField(MaintenanceField.AREA, MaintenanceArea.entries, form.area, { it.wireValue }, errors[MaintenanceField.AREA],
            focusTargets.getValue(MaintenanceField.AREA), enabled) { change(MaintenanceField.AREA, form.copy(area = it)) }
        FormTextField(MaintenanceField.SITE, form.siteLabel, errors[MaintenanceField.SITE], focusTargets.getValue(MaintenanceField.SITE), enabled,
            hint = "Site label · 100 characters maximum") { change(MaintenanceField.SITE, form.copy(siteLabel = it)) }
        FormTextField(MaintenanceField.REPORTER, form.reporterLabel, errors[MaintenanceField.REPORTER], focusTargets.getValue(MaintenanceField.REPORTER), enabled,
            hint = "Reporter label · 100 characters maximum") { change(MaintenanceField.REPORTER, form.copy(reporterLabel = it)) }
    }
    ContentCard {
        SectionHeading("03 · Maintenance request")
        FormTextField(MaintenanceField.NARRATIVE, form.narrative, errors[MaintenanceField.NARRATIVE], focusTargets.getValue(MaintenanceField.NARRATIVE), enabled,
            hint = "Describe the maintenance or water-supply issue · 2,000 characters maximum", multiline = true) { change(MaintenanceField.NARRATIVE, form.copy(narrative = it)) }
        ChoiceField(MaintenanceField.ASSISTANCE, MaintenanceAssistance.entries, form.assistance, { it.wireValue }, errors[MaintenanceField.ASSISTANCE],
            focusTargets.getValue(MaintenanceField.ASSISTANCE), enabled) { change(MaintenanceField.ASSISTANCE, form.copy(assistance = it)) }
    }
    SecondaryAction(if (pending) "Saving or queueing…" else "Save editable draft", enabled && state.capabilities.saveDraft) {
        pending = true
        focus.clearFocus()
        actions.dispatch(MobileAction.SaveDraft(state.accountGeneration, UUID.randomUUID().toString(), editor.draftId, editor.draftRevision, form))
    }
    PrimaryAction("Review & queue submission", enabled && supported && state.capabilities.queueSubmission) {
        attempted = true
        val currentErrors = validateMaintenanceForm(form, editor.estimatedServerTimeMillis)
        if (currentErrors.isEmpty()) {
            focus.clearFocus()
            confirmation = form.copy()
            confirmationCommandId = UUID.randomUUID().toString()
        } else focusRequest++
    }
    QuietText("Save and submit text first. Private photos can be added from the received report's current source detail. Do not enter personal or sensitive information.")

    confirmation?.let { candidate ->
        AlertDialog(onDismissRequest = { confirmation = null; confirmationCommandId = null },
            title = { Text("Queue this fixed submission?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("This creates an immutable copy of the current draft. Retries will send the same copy until a valid receipt is recorded.")
                    Text("Queueing does not mean the server has received, processed, reviewed or shared the report.")
                    Text("Later changes require an explicit correction. The submitted copy stays in its original account.")
                }
            },
            confirmButton = {
                TextButton(enabled = enabled && supported && state.capabilities.queueSubmission, onClick = {
                    val commandId = confirmationCommandId ?: return@TextButton
                    confirmation = null
                    confirmationCommandId = null
                    pending = true
                    actions.dispatch(MobileAction.QueueSubmission(state.accountGeneration, commandId, editor.draftId,
                        editor.draftRevision, editor.expectedReportRevision, candidate))
                }) { Text("Confirm & queue") }
            },
            dismissButton = { TextButton(onClick = { confirmation = null; confirmationCommandId = null }) { Text("Keep editing") } })
    }
    if (leaving) AlertDialog(onDismissRequest = { leaving = false }, title = { Text("Leave unsaved changes?") },
        text = { Text("Changes made since the last confirmed save will be discarded. Existing saved drafts and queued submissions stay on this phone.") },
        confirmButton = { TextButton(onClick = { form = editor.form; leaving = false; actions.dispatch(MobileAction.Navigate(state.accountGeneration, MobileScreen.DRAFTS)) }) { Text("Leave editor") } },
        dismissButton = { TextButton(onClick = { leaving = false }) { Text("Keep editing") } })
}

@Composable
private fun FormTextField(field: MaintenanceField, value: String, errorText: String?, requester: FocusRequester,
    enabled: Boolean, hint: String, multiline: Boolean = false, sentenceCase: Boolean = true, onChange: (String) -> Unit) {
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth().focusRequester(requester), enabled = enabled,
        label = { Text(field.label) }, isError = errorText != null, minLines = if (multiline) 4 else 1,
        maxLines = if (multiline) 12 else 1, singleLine = !multiline,
        supportingText = { Text(errorText ?: hint) },
        keyboardOptions = KeyboardOptions(capitalization = if (sentenceCase) KeyboardCapitalization.Sentences else KeyboardCapitalization.None,
            autoCorrectEnabled = false, imeAction = if (multiline) ImeAction.Default else ImeAction.Next))
}

@Composable
private fun <T> ChoiceField(field: MaintenanceField, choices: List<T>, selected: T?, label: (T) -> String,
    errorText: String?, requester: FocusRequester, enabled: Boolean, select: (T) -> Unit) {
    Column(Modifier.fillMaxWidth().selectableGroup().focusRequester(requester).focusable().semantics {
        if (errorText != null) error(errorText)
    }, verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(field.label, style = MaterialTheme.typography.labelLarge)
        choices.forEach { choice ->
            Row(Modifier.fillMaxWidth().heightInTouchTarget().selectable(selected == choice, enabled = enabled, role = Role.RadioButton) { select(choice) }
                .padding(horizontal = 4.dp, vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected == choice, onClick = null, enabled = enabled)
                Text(label(choice), Modifier.padding(start = 8.dp))
            }
        }
        if (errorText != null) Text(errorText, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
    }
}
