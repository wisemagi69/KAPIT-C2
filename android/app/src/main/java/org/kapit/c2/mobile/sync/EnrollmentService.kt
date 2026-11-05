package org.kapit.c2.mobile.sync

import androidx.annotation.RequiresApi
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kapit.c2.mobile.data.remote.*
import org.kapit.c2.mobile.domain.*
import org.kapit.c2.mobile.ui.MobileSession
import org.kapit.c2.mobile.ui.SignInPurpose

/** Password entry discovers identity; only durable owner reservation permits a token proof. */
@RequiresApi(35)
internal class EnrollmentService(
    private val repository: ProtectedRepository,
    private val journal: EnrollmentJournal,
    private val remote: RemoteProtocol,
    private val gate: Mutex = Mutex(),
) {

    suspend fun authenticate(anchor: OnlineRequestAnchor, purpose: SignInPurpose, username: String, password: String): MobileSession = gate.withLock {
        checkCurrent(anchor)
        val expected = if (purpose == SignInPurpose.RECOVER_ENROLLMENT) {
            val selected = repository.access.value.storeRef ?: throw StoreFailure(StoreCode.AUTH_REQUIRED)
            journal.bindingForStore(anchor.generation, selected) ?: throw StoreFailure(StoreCode.KEY_UNAVAILABLE)
        } else null
        val discovery = journal.discovery(anchor.generation)
        requireCurrent(discovery.generation == anchor.generation)
        val first = challenge(anchor, username, password, discovery.installationId, journal.publicSpki(discovery), null)
        checkCurrent(anchor)
        expected?.let {
            if (it.installationId != discovery.installationId || !journal.matchesOwner(it, first.organizationId, first.accountUserId))
                throw StoreFailure(StoreCode.CONTEXT_CHANGED)
        }
        val reservation = journal.reserveOwner(discovery, first.organizationId, first.accountUserId)
        val attempt = reservation.attempt
        requireCurrent(attempt.generation == anchor.generation && attempt.installationId == discovery.installationId)
        var challenge = if (reservation.requiresFreshChallenge || expected != null) {
            challenge(anchor, username, password, attempt.installationId, journal.publicSpki(attempt), null)
        } else first
        checkCurrent(anchor)
        requireOwner(challenge, first)
        val response = try { issue(anchor, attempt, challenge) }
        catch (failure: RemoteFailure) {
            if (failure.code != RemoteCode.ENROLLMENT_EXISTS || failure.enrollmentId == null) throw failure
            // This ID is accepted only from080's bound proof-token response, never an arbitrary error.
            val account = AccountIdentity(challenge.organizationId, challenge.accountUserId, failure.enrollmentId)
            if (expected != null && expected.storeRef != account.storeRef) throw StoreFailure(StoreCode.CONTEXT_CHANGED)
            checkCurrent(anchor)
            challenge = challenge(anchor, username, password, attempt.installationId, journal.publicSpki(attempt), account)
            requireOwner(challenge, first)
            issue(anchor, attempt, challenge)
        }
        try {
            checkCurrent(anchor)
            val account = response.context.authority.capture.account
            if (expected != null && expected.storeRef != account.storeRef) throw StoreFailure(StoreCode.CONTEXT_CHANGED)
            val binding = journal.bindEnrollment(attempt, account)
            requireCurrent(binding.storeRef == account.storeRef && binding.installationId == attempt.installationId &&
                journal.matchesOwner(binding, account.organizationId, account.userId))
            checkCurrent(anchor)
            // The controller alone activates the original anchor. A valid network response is not READY.
            val access = response.secrets.copyAccessToken()
            val refresh = response.secrets.copyRefreshToken()
            try {
                MobileSession(response.context.authority, response.context.lease, SessionSecrets(access, refresh,
                    response.secrets.accessExpiresServerMillis, response.secrets.refreshExpiresServerMillis))
            } finally { access.fill(0); refresh.fill(0) }
        } finally { response.close() }
    }

    private suspend fun challenge(anchor: OnlineRequestAnchor, username: String, password: String, installation: String,
        publicKey: ByteArray, expected: AccountIdentity?): ValidatedChallenge {
        checkCurrent(anchor)
        val passwordChars = password.toCharArray()
        try {
            return ChallengeRequest(username, passwordChars, installation, expected?.enrollmentId, publicKey,
                "KAPIT Android", expected).use { request ->
                remote.challenge(request, anchor.clock).also { checkCurrent(anchor) }
            }
        } finally { passwordChars.fill('\u0000'); publicKey.fill(0) }
    }

    private suspend fun issue(anchor: OnlineRequestAnchor, attempt: EnrollmentAttempt, challenge: ValidatedChallenge): RemoteSession {
        checkCurrent(anchor)
        val proof = challenge.copyProofBytes()
        val signature = try { journal.sign(attempt, proof) } finally { proof.fill(0) }
        try {
            checkCurrent(anchor)
            val response = remote.token(challenge, signature, anchor.clock)
            try { checkCurrent(anchor); return response }
            catch (failure: Throwable) { response.close(); throw failure }
        } finally { signature.fill(0) }
    }

    private suspend fun checkCurrent(anchor: OnlineRequestAnchor) {
        currentCoroutineContext().ensureActive()
        requireCurrent(repository.access.value.generation == anchor.generation)
        val current = repository.beginOnlineRequest(anchor.generation)
        requireCurrent(current.authorityRevision == anchor.authorityRevision)
        requireCurrent(current.clock.bootId != null && current.clock.bootId == anchor.clock.bootId && current.clock.elapsedMillis >= anchor.clock.elapsedMillis)
    }
    private fun requireCurrent(value: Boolean) { if (!value) throw StoreFailure(StoreCode.STALE_GENERATION) }
    private fun requireOwner(current: ValidatedChallenge, discovered: ValidatedChallenge) {
        if (current.organizationId != discovered.organizationId || current.accountUserId != discovered.accountUserId)
            throw StoreFailure(StoreCode.CONTEXT_CHANGED)
    }
}
