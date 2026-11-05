package org.kapit.c2.mobile.sync

import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
import org.kapit.c2.mobile.data.remote.*
import org.kapit.c2.mobile.domain.*
import org.kapit.c2.mobile.ui.SignInPurpose

class EnrollmentServiceTest {
    @Test fun reservesOwnerBeforeAnyProofAndDoesNotPublishReady() = runBlocking {
        val repo = RepositoryFixture()
        val journal = JournalFixture()
        val protocol = EnrollmentProtocol(journal)
        EnrollmentService(repo, journal, protocol).authenticate(repo.beginOnlineRequest(1), SignInPurpose.ENROLL_OR_RECOVER,
            "synthetic", "fixture").use { assertEquals(testContext, it.context) }
        assertEquals(listOf("discovery", "reserve", "sign", "bind"), journal.events)
        assertFalse(repo.access.value.ready); assertEquals(1L, repo.access.value.generation)
        assertEquals(1, protocol.challenges)
    }

    @Test fun existingOwnerUsesFreshOwnedKeyChallenge() = runBlocking {
        val repo = RepositoryFixture()
        val journal = JournalFixture().apply { existingOwner = true }
        val protocol = EnrollmentProtocol(journal)
        EnrollmentService(repo, journal, protocol).authenticate(repo.beginOnlineRequest(1), SignInPurpose.ENROLL_OR_RECOVER,
            "synthetic", "fixture").close()
        assertEquals(2, protocol.challenges)
        assertEquals(listOf(1.toByte(), 2.toByte()), protocol.keys)
        assertEquals(1, protocol.tokens)
    }

    @Test fun changedOwnerBetweenChallengesFailsBeforeSigning() = runBlocking {
        val repo = RepositoryFixture()
        val journal = JournalFixture().apply { existingOwner = true }
        val protocol = EnrollmentProtocol(journal).apply { changeSecondOwner = true }
        try {
            EnrollmentService(repo, journal, protocol).authenticate(repo.beginOnlineRequest(1), SignInPurpose.ENROLL_OR_RECOVER, "synthetic", "fixture")
            fail()
        } catch (failure: StoreFailure) { assertEquals(StoreCode.CONTEXT_CHANGED, failure.code) }
        assertFalse(journal.events.contains("sign")); assertEquals(0, protocol.tokens)
    }

    @Test fun proofBoundExistingEnrollmentRecoversSameOpaqueQueue() = runBlocking {
        val repo = RepositoryFixture().apply { access.value = StoreAccess(1, storeRef = testContext.capture.account.storeRef) }
        val journal = JournalFixture().apply { existingOwner = true; bound = true }
        val protocol = EnrollmentProtocol(journal).apply { enrollmentExists = true }
        EnrollmentService(repo, journal, protocol).authenticate(repo.beginOnlineRequest(1), SignInPurpose.RECOVER_ENROLLMENT,
            "synthetic", "fixture").use { assertEquals(testContext.capture.account, it.context.capture.account) }
        assertEquals(3, protocol.challenges); assertEquals(2, protocol.tokens)
        assertEquals(testContext.capture.account, protocol.expectedAccounts.last())
        assertEquals(1, journal.events.count { it == "bind" })
    }

    @Test fun wrongRecoveredEnrollmentCannotAdoptSelectedQueue() = runBlocking {
        val repo = RepositoryFixture().apply { access.value = StoreAccess(1, storeRef = testContext.capture.account.storeRef) }
        val journal = JournalFixture().apply { existingOwner = true; bound = true }
        val protocol = EnrollmentProtocol(journal).apply { enrollmentExists = true; recoveredEnrollment = id(99) }
        try {
            EnrollmentService(repo, journal, protocol).authenticate(repo.beginOnlineRequest(1), SignInPurpose.RECOVER_ENROLLMENT, "synthetic", "fixture")
            fail()
        } catch (failure: StoreFailure) { assertEquals(StoreCode.CONTEXT_CHANGED, failure.code) }
        assertEquals(1, protocol.tokens); assertFalse(journal.events.contains("bind"))
    }

    @Test fun authorityRenewalDuringChallengeRejectsBeforeReservationOrSigning() = runBlocking {
        val repo = RepositoryFixture()
        val journal = JournalFixture()
        val protocol = EnrollmentProtocol(journal).apply { afterChallenge = { repo.revision++ } }
        try {
            EnrollmentService(repo, journal, protocol).authenticate(repo.beginOnlineRequest(1), SignInPurpose.ENROLL_OR_RECOVER, "synthetic", "fixture")
            fail()
        } catch (failure: StoreFailure) { assertEquals(StoreCode.STALE_GENERATION, failure.code) }
        assertEquals(listOf("discovery"), journal.events); assertEquals(0, protocol.tokens)
    }

    @Test fun cancellationAfterTokenResponseClosesSecretsWithoutBinding() = runBlocking<Unit> {
        val repo = RepositoryFixture()
        val journal = JournalFixture()
        val entered = CompletableDeferred<Unit>()
        val released = CompletableDeferred<Unit>()
        val response = remoteSession()
        val protocol = object : EnrollmentProtocol(journal) {
            override suspend fun token(challenge: ValidatedChallenge, signature: ByteArray, start: ClockStamp): RemoteSession = withContext(NonCancellable) {
                entered.complete(Unit); released.await(); response
            }
        }
        val job = launch {
            EnrollmentService(repo, journal, protocol).authenticate(repo.beginOnlineRequest(1), SignInPurpose.ENROLL_OR_RECOVER, "synthetic", "fixture").close()
        }
        entered.await(); job.cancel(); released.complete(Unit); job.join()
        assertFalse(journal.events.contains("bind"))
        assertThrows(StoreFailure::class.java) { response.secrets.copyAccessToken() }
    }

    private class Discovery : DiscoveryHandle { override val generation = 1L; override val installationId = id(30) }
    private class Attempt : EnrollmentAttempt { override val generation = 1L; override val installationId = id(30) }
    private class JournalFixture : EnrollmentJournal {
        var existingOwner = false
        var bound = false
        val events = mutableListOf<String>()
        override fun discovery(generation: Long): DiscoveryHandle { events += "discovery"; return Discovery() }
        override fun publicSpki(discovery: DiscoveryHandle) = byteArrayOf(1)
        override fun reserveOwner(discovery: DiscoveryHandle, organizationId: String, userId: String): EnrollmentReservation {
            assertEquals(testContext.capture.account.organizationId, organizationId)
            assertEquals(testContext.capture.account.userId, userId)
            events += "reserve"; return EnrollmentReservation(Attempt(), existingOwner)
        }
        override fun publicSpki(attempt: EnrollmentAttempt) = byteArrayOf(2)
        override fun sign(attempt: EnrollmentAttempt, validatedProof: ByteArray): ByteArray { assertTrue(events.contains("reserve")); events += "sign"; return byteArrayOf(7) }
        override fun bindEnrollment(attempt: EnrollmentAttempt, account: AccountIdentity): EnrollmentBinding {
            events += "bind"; bound = true; return EnrollmentBinding("a".repeat(64), account.storeRef, attempt.installationId)
        }
        override fun bindingForStore(generation: Long, storeRef: String) = if (bound) EnrollmentBinding("a".repeat(64), storeRef, id(30)) else null
        override fun matchesOwner(binding: EnrollmentBinding, organizationId: String, userId: String) =
            organizationId == testContext.capture.account.organizationId && userId == testContext.capture.account.userId
    }
    private open class EnrollmentProtocol(private val journal: JournalFixture) : ProtocolFixture() {
        var challenges = 0
        var tokens = 0
        var changeSecondOwner = false
        var enrollmentExists = false
        var recoveredEnrollment = testContext.capture.account.enrollmentId
        var afterChallenge: (() -> Unit)? = null
        val keys = mutableListOf<Byte>()
        val expectedAccounts = mutableListOf<AccountIdentity?>()
        override suspend fun challenge(request: ChallengeRequest, start: ClockStamp): ValidatedChallenge {
            challenges++; keys += request.keyCopy().single(); expectedAccounts += request.expectedAccount
            afterChallenge?.invoke()
            return ValidatedChallenge(id(40 + challenges), "fixture", if (changeSecondOwner && challenges == 2) id(88) else testContext.capture.account.userId,
                testContext.capture.account.organizationId, request.enrollmentId, 121_000, 1_000, "boot", byteArrayOf(5), request.keyCopy())
        }
        override suspend fun token(challenge: ValidatedChallenge, signature: ByteArray, start: ClockStamp): RemoteSession {
            assertTrue(journal.events.contains("reserve")); tokens++
            if (enrollmentExists && tokens == 1) throw RemoteFailure(RemoteFailureKind.HTTP, 409, RemoteCode.ENROLLMENT_EXISTS, enrollmentId = recoveredEnrollment)
            return remoteSession()
        }
    }
}
