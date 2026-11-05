package org.kapit.c2.mobile.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

/**
 * Stateless integration entry point; no mock authentication, repository or transport is installed.
 * The Activity/controller also owns secure-window, lifecycle lock, key closure and generation fences.
 * remember-only buffers are discarded on gate/screen/generation changes; Strings are not zeroizable.
 */
@Composable
fun KapitMobileApp(state: MobileUiState, actions: MobileActions) {
    KapitMobileTheme {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            key(state.accountGeneration, state.access, state.screen) {
                when {
                    state.access == MobileAccess.STARTING -> GatePage {
                        BrandHeader()
                        PageTitle("Private by default", "Opening your workspace")
                        CircularProgressIndicator(Modifier.semantics { contentDescription = "Checking protected storage" })
                        QuietText("Checking account access and protected storage.")
                    }
                    state.access == MobileAccess.SIGNED_OUT -> SignInScreen(state, actions)
                    state.showsProtectedContent -> Workspace(state, actions)
                    else -> AccessScreen(state, actions)
                }
            }
        }
    }
}

@Composable
private fun GatePage(content: @Composable ColumnScope.() -> Unit) {
    Box(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing).imePadding(), contentAlignment = Alignment.TopCenter) {
        Column(Modifier.widthIn(max = 600.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp), content = content)
    }
}

@Composable
private fun SignInScreen(state: MobileUiState, actions: MobileActions) {
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var attempted by remember { mutableStateOf(false) }
    var sent by remember(state.interactionRevision) { mutableStateOf(false) }
    val focus = LocalFocusManager.current
    val usernameFocus = remember { FocusRequester() }
    val passwordFocus = remember { FocusRequester() }
    val enabled = state.capabilities.authenticate && !state.busy && !sent
    val usernameError = attempted && !validCredentialText(username, 150)
    val passwordError = attempted && !validCredentialText(password, 128)
    fun signIn() {
        attempted = true
        if (!enabled) return
        if (!validCredentialText(username, 150)) { usernameFocus.requestFocus(); return }
        if (!validCredentialText(password, 128)) { passwordFocus.requestFocus(); return }
        val command = MobileAction.SignIn(state.accountGeneration, state.signInPurpose, username, password)
        // Drop our references before handing over. The controller owns clearing its request afterward.
        username = ""
        password = ""
        attempted = false
        sent = true
        focus.clearFocus()
        actions.dispatch(command)
    }
    GatePage {
        BrandHeader()
        StatusPill("Training and evaluation")
        PageTitle("Your reporting companion", if (state.signInPurpose == SignInPurpose.RECOVER_ENROLLMENT) "Restore account access" else "Ready when you are.",
            "Capture maintenance reports, keep drafts on your phone and follow each submission through review.")
        ContentCard {
            SectionHeading(if (state.signInPurpose == SignInPurpose.RECOVER_ENROLLMENT) "Sign in to the same account" else "Sign in & enroll this phone")
            QuietText("Online sign-in verifies your account and this app installation. Device unlock remains a separate step.")
            if (state.notice != null) NoticeCard(state.notice)
            if (!state.capabilities.authenticate) {
                if (state.connection in setOf(ConnectionUi.OFFLINE, ConnectionUi.UNAVAILABLE)) NoticeCard(MobileNotice.CONNECTION_UNAVAILABLE)
                else QuietText("Confirm your device credential before entering account details. Your account has not been checked.")
                if (state.capabilities.unlock) SecondaryAction("Verify device unlock", !state.busy) {
                    actions.dispatch(MobileAction.Unlock(state.accountGeneration))
                }
            }
            OutlinedTextField(username, { username = it }, Modifier.fillMaxWidth().focusRequester(usernameFocus), enabled = enabled,
                label = { Text("Username") }, singleLine = true, isError = usernameError,
                supportingText = if (usernameError) ({ Text("Enter a username of 150 characters or fewer.") }) else null,
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Text, imeAction = ImeAction.Next),
                keyboardActions = KeyboardActions(onNext = { focus.moveFocus(FocusDirection.Down) }))
            OutlinedTextField(password, { password = it }, Modifier.fillMaxWidth().focusRequester(passwordFocus), enabled = enabled,
                label = { Text("Password") }, singleLine = true, isError = passwordError,
                visualTransformation = PasswordVisualTransformation(),
                supportingText = if (passwordError) ({ Text("Enter a password of 128 characters or fewer.") }) else null,
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(onDone = { signIn() }))
            if (usernameError || passwordError) Text("Check the marked sign-in fields.",
                color = MaterialTheme.colorScheme.error, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive })
            PrimaryAction(if (state.busy || sent) "Signing in…" else "Continue securely", enabled) { signIn() }
            if (state.busy || sent) LinearProgressIndicator(Modifier.fillMaxWidth())
        }
        QuietText("Maintenance and water-supply reports for training and evaluation. Sharing requires a separate human review on the website.")
    }
}

@Composable
private fun AccessScreen(state: MobileUiState, actions: MobileActions) {
    val copy = when (state.access) {
        MobileAccess.LOCKED, MobileAccess.UNLOCK_REQUIRED -> "Workspace locked" to "Unlock with your device credential to access this account's protected work."
        MobileAccess.LEASE_EXPIRED -> "Connect to renew access" to "Offline access has expired or cannot be verified after restart. Sign in online to this account before opening its work."
        MobileAccess.KEY_UNAVAILABLE -> "Protected key unavailable" to "The encrypted files are retained. Signing in cannot recreate a lost encryption key or guarantee recovery of unsent work."
        MobileAccess.ENROLLMENT_SUSPENDED -> "Account access paused" to "This enrollment or account no longer has current permission. Pending work stays protected and cannot move to another account."
        MobileAccess.CONTEXT_CHANGED -> "Account scope changed" to "Sign in online to verify current permissions. Existing fixed submissions keep their original scope and require explicit reconciliation."
        MobileAccess.UNSUPPORTED_DEVICE -> "Android 15 or later required" to "This app requires Android 15 (API 35) or later and a secure device credential for protected reporting. Enrollment, report entry, storage and synchronization are unavailable on this device."
        MobileAccess.STORAGE_UNAVAILABLE -> "Protected storage unavailable" to "The encrypted files are retained. The app could not safely open this workspace. No replacement store has been created."
        MobileAccess.TEMPLATE_UNSUPPORTED -> "App update required" to "This account requires a report template this app cannot use. Update the app before reopening this workspace. Encrypted drafts and fixed pending submissions are retained."
        else -> "Workspace unavailable" to "Account and storage checks have not completed. Your report content is hidden until access is verified."
    }
    GatePage {
        BrandHeader()
        StatusPill("Protected workspace", warning = true)
        PageTitle("Access check", copy.first, copy.second)
        if (state.notice != null) NoticeCard(state.notice)
        if (state.access != MobileAccess.UNSUPPORTED_DEVICE) ContentCard {
            SectionHeading("Your pending work stays on this phone")
            QuietText("Locking or signing out does not delete encrypted drafts or queued submissions. Another account cannot open or send them.")
            if (state.access in setOf(MobileAccess.LOCKED, MobileAccess.UNLOCK_REQUIRED)) {
                PrimaryAction("Unlock workspace", state.capabilities.unlock && !state.busy) {
                    actions.dispatch(MobileAction.Unlock(state.accountGeneration))
                }
            }
            if (state.access !in setOf(MobileAccess.KEY_UNAVAILABLE, MobileAccess.ENROLLMENT_SUSPENDED, MobileAccess.TEMPLATE_UNSUPPORTED)) {
                SecondaryAction("Sign in online to this account", state.capabilities.authenticate && !state.busy) {
                    actions.dispatch(MobileAction.BeginSignIn(state.accountGeneration, recoverEnrollment = true))
                }
            }
            TextButton(onClick = { actions.dispatch(MobileAction.BeginSignIn(state.accountGeneration, recoverEnrollment = false)) },
                enabled = !state.busy && (state.capabilities.authenticate || state.capabilities.unlock)) {
                Text("Use another account")
            }
        }
        if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (state.access != MobileAccess.UNSUPPORTED_DEVICE) QuietText("Do not clear app data or uninstall to solve an access problem. Those actions can remove pending work.")
    }
}

@Composable
private fun Workspace(state: MobileUiState, actions: MobileActions) {
    val tabs = listOf(MobileScreen.HOME to "Home", MobileScreen.OUTBOX to "Outbox", MobileScreen.REPORTS to "Reports", MobileScreen.ACCOUNT to "Account")
    val selected = when (state.screen) {
        MobileScreen.DRAFTS, MobileScreen.EDITOR -> MobileScreen.HOME
        MobileScreen.REPORT_DETAIL -> MobileScreen.REPORTS
        else -> state.screen
    }
    // The editor owns back/discard confirmation so unsaved changes are never silently dropped.
    BackHandler(enabled = state.screen != MobileScreen.HOME && state.screen != MobileScreen.EDITOR) {
        actions.dispatch(MobileAction.Navigate(state.accountGeneration, MobileScreen.HOME))
    }
    Scaffold(containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            Surface(color = MaterialTheme.colorScheme.background) {
                Column(Modifier.windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Top))
                    .fillMaxWidth().padding(horizontal = 20.dp, vertical = 12.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        BrandHeader(compact = true)
                        TextButton(onClick = { actions.dispatch(MobileAction.Lock(state.accountGeneration)) }, modifier = Modifier.heightInTouchTarget()) {
                            KapitIconView(KapitIcon.LOCK, size = 18.dp); Spacer(Modifier.width(6.dp)); Text("Lock")
                        }
                    }
                    if (state.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                }
            }
        },
        bottomBar = {
            if (state.screen != MobileScreen.EDITOR) NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                tabs.forEach { (screen, label) ->
                    NavigationBarItem(selected = selected == screen,
                        onClick = { actions.dispatch(MobileAction.Navigate(state.accountGeneration, screen)) },
                        icon = { KapitIconView(when (screen) { MobileScreen.HOME -> KapitIcon.HOME; MobileScreen.OUTBOX -> KapitIcon.OUTBOX; MobileScreen.REPORTS -> KapitIcon.REPORT; else -> KapitIcon.ACCOUNT }) },
                        label = { Text(label) })
                }
            }
        }) { padding ->
        Box(Modifier.fillMaxSize().padding(padding).imePadding(), contentAlignment = Alignment.TopCenter) {
            Column(Modifier.widthIn(max = 720.dp).fillMaxWidth().verticalScroll(rememberScrollState()).padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(20.dp)) {
                if (state.notice != null) NoticeCard(state.notice) { actions.dispatch(MobileAction.DismissNotice(state.accountGeneration)) }
                when (state.screen) {
                    MobileScreen.HOME -> HomeScreen(state, actions)
                    MobileScreen.DRAFTS -> DraftsScreen(state, actions)
                    MobileScreen.EDITOR -> {
                        val editor = state.editor
                        if (editor == null) EmptyState("Draft unavailable", "Open an existing draft or create a new one after storage is ready.")
                        else key(editor.draftId, editor.draftRevision) { MaintenanceEditor(state, editor, actions) }
                    }
                    MobileScreen.OUTBOX -> OutboxScreen(state, actions)
                    MobileScreen.REPORTS -> ReportsScreen(state, actions)
                    MobileScreen.REPORT_DETAIL -> ReportDetailScreen(state, actions)
                    MobileScreen.ACCOUNT -> AccountScreen(state, actions)
                }
                QuietText("KAPIT-C2 · Maintenance reporting workflow")
            }
        }
    }
}
