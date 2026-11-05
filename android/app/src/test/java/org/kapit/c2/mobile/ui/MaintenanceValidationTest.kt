package org.kapit.c2.mobile.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MaintenanceValidationTest {
    private fun complete(observed: String = "2026-10-17T09:30:00Z") = MaintenanceForm(
        observedAt = observed, category = MaintenanceCategory.WATER_SUPPLY, urgency = MaintenanceUrgency.ROUTINE,
        area = MaintenanceArea.A, siteLabel = "Fictional pump A", reporterLabel = "Synthetic reporter",
        narrative = "Synthetic inspection request.", assistance = MaintenanceAssistance.INSPECTION,
    )

    @Test fun incompleteDraftGetsGuidanceForEveryRequiredField() {
        assertEquals(MaintenanceField.entries.toSet(), validateMaintenanceForm(MaintenanceForm()).keys)
    }

    @Test fun historicalOffsetsAndFractionsRemainUnchanged() {
        listOf("2026-10-17T09:30:00.123456Z", "2026-10-17T17:30:00+08:00", "2026-10-17T09:30:00+0000").forEach { timestamp ->
            val form = complete(timestamp)
            assertTrue(validateMaintenanceForm(form).isEmpty())
            assertEquals(timestamp, form.observedAt)
        }
    }

    @Test fun invalidDatesAndOffsetsAreRejectedWithoutEchoingInput() {
        listOf("2026-02-30T09:30:00Z", "2026-10-17T09:30:00+25:00", "2026-10-17T09:30:00+08:70", "2026-10-17T09:30:00").forEach { timestamp ->
            val errors = validateMaintenanceForm(complete(timestamp))
            assertTrue(errors.containsKey(MaintenanceField.OBSERVED_AT))
            assertFalse(errors.values.any { it.contains(timestamp) })
        }
    }

    @Test fun scalarBoundsAcceptSupplementaryUnicodeAndPreserveWhitespace() {
        val pair = "\uD83D\uDEE0"
        val atLimit = complete().copy(siteLabel = pair.repeat(100), narrative = pair.repeat(2000), reporterLabel = "  Fictional reporter  ")
        assertTrue(validateMaintenanceForm(atLimit).isEmpty())
        assertEquals("  Fictional reporter  ", atLimit.reporterLabel)
        val overLimit = validateMaintenanceForm(atLimit.copy(siteLabel = atLimit.siteLabel + pair, narrative = atLimit.narrative + pair))
        assertTrue(overLimit.containsKey(MaintenanceField.SITE))
        assertTrue(overLimit.containsKey(MaintenanceField.NARRATIVE))
    }

    @Test fun loneSurrogatesAreRejected() {
        assertTrue(validateMaintenanceForm(complete().copy(narrative = "bad\uD800")).containsKey(MaintenanceField.NARRATIVE))
        assertFalse(hasValidUnicode("\uDC00"))
    }

    @Test fun futureGuidanceUsesProvidedServerTimeAndInclusiveFiveMinuteBound() {
        // 17 Oct 2026 09:30 UTC, independent of device timezone and local wall-clock settings.
        val server = 1792229400000L
        assertTrue(validateMaintenanceForm(complete("2026-10-17T09:35:00Z"), server).isEmpty())
        assertTrue(validateMaintenanceForm(complete("2026-10-17T09:35:01Z"), server).containsKey(MaintenanceField.OBSERVED_AT))
    }

    @Test fun credentialLimitsCountScalarsWithoutTrimming() {
        val pair = "\uD83D\uDEE0"
        assertTrue(validCredentialText(pair.repeat(128), 128))
        assertFalse(validCredentialText(pair.repeat(129), 128))
        assertTrue(validCredentialText(" ", 128))
        assertFalse(validCredentialText("bad\uD800", 128))
    }

    @Test fun allNonReadyStatesHideStaleProtectedModels() {
        val context = AccountContextUi("Synthetic", "Demo", "Unit", "Channel", "DEMO-REDUCED", "Expires soon", true)
        MobileAccess.entries.filter { it != MobileAccess.READY }.forEach { access ->
            assertFalse(MobileUiState(access = access, context = context, editor = EditorUi("draft", 0, complete())).showsProtectedContent)
        }
        assertFalse(MobileUiState(access = MobileAccess.READY).showsProtectedContent)
        assertTrue(MobileUiState(access = MobileAccess.READY, context = context).showsProtectedContent)
    }

    @Test fun sensitiveModelAndCommandStringsDoNotExposeContent() {
        val canary = "SYNTHETIC_UI_REDACTION_CANARY"
        val form = complete().copy(narrative = canary)
        assertFalse(form.toString().contains(canary))
        assertFalse(MobileAction.SignIn(1, SignInPurpose.ENROLL_OR_RECOVER, canary, canary).toString().contains(canary))
        assertFalse(MobileAction.QueueSubmission(1, "command", "draft", 0, 0, form).toString().contains(canary))
        assertFalse(MobileUiState(editor = EditorUi("draft", 0, form)).toString().contains(canary))
    }
}
