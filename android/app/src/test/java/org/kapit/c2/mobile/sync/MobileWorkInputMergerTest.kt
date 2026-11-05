package org.kapit.c2.mobile.sync

import androidx.work.Data
import androidx.work.workDataOf
import org.junit.Assert.*
import org.junit.Test

class MobileWorkInputMergerTest {
    private val ref = "a".repeat(64)
    private val chain = "00000000-0000-4000-8000-000000000001"
    private fun own() = workDataOf("store_ref" to ref, "chain_ref" to chain)
    private fun rejected(vararg inputs: Data) {
        try { MobileWorkInputMerger().merge(inputs.toList()); fail("Expected invalid input") }
        catch (_: IllegalArgumentException) { }
    }

    @Test fun fixedParentOutcomeNeverEntersWorkerInput() {
        val merged = MobileWorkInputMerger().merge(listOf(workDataOf("outcome" to "completed"), own(), workDataOf("outcome" to "paused")))
        assertEquals(setOf("store_ref", "chain_ref"), merged.keyValueMap.keys)
        assertEquals(ref, merged.getString("store_ref"))
        assertEquals(chain, merged.getString("chain_ref"))
        assertEquals(merged, MobileWorkInputMerger().merge(listOf(own())))
    }
    @Test fun duplicatedOrConflictingOpaqueIdentityIsRejected() {
        rejected(own(), own())
        rejected(own(), workDataOf("store_ref" to "b".repeat(64), "chain_ref" to chain))
        rejected(own(), workDataOf("store_ref" to ref))
    }
    @Test fun unknownPredecessorMetadataIsRejected() {
        rejected(own(), workDataOf("outcome" to "unexpected"))
        rejected(own(), workDataOf("outcome" to "completed", "extra" to "value"))
        rejected(own(), Data.EMPTY)
    }
    @Test fun missingOrMalformedOpaquePairIsRejected() {
        rejected(workDataOf("outcome" to "completed"))
        rejected(workDataOf("store_ref" to "A".repeat(64), "chain_ref" to chain))
        rejected(workDataOf("store_ref" to ref, "chain_ref" to "invalid"))
        rejected(workDataOf("store_ref" to 4, "chain_ref" to chain))
    }
}
