package org.kapit.c2.mobile.security

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.kapit.c2.mobile.data.local.AndroidProtectedRepository
import org.kapit.c2.mobile.domain.*

@RunWith(AndroidJUnit4::class)
class EnrollmentJournalTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val root = File(context.noBackupFilesDir, "journal-test-${UUID.randomUUID()}")
    private val env = AndroidAccessEnvironment(context)
    private val ownedRefs = mutableSetOf<String>()
    private val repositories = mutableListOf<AndroidProtectedRepository>()
    private fun uuid() = UUID.randomUUID().toString()
    private fun keys() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun aliases() = keys().aliases().toList().filter { it.startsWith("kapit.proof.v1.") }.toSet()
    private fun repository() = AndroidProtectedRepository(context, root, env, false).also(repositories::add)
    private fun remember() {
        File(root, "proofs").listFiles()?.map { it.name.substringBefore('.') }?.filter { Regex("[0-9a-f-]{36}").matches(it) }?.let(ownedRefs::addAll)
        val file = File(root, "enrollment.journal")
        if (file.isFile) try {
            val json = StrictJson.objectFrom(file.readBytes())
            (json["discovery_ref"] as? JsonPrimitive)?.contentOrNull?.let(ownedRefs::add)
            json["owners"]?.jsonArray?.forEach { ownedRefs += it.jsonObject.requiredString("proof_ref") }
        } catch (_: Exception) {}
    }
    private fun denied(code: StoreCode? = null, body: () -> Unit) {
        try { body(); fail("Expected recovery denial") } catch (failure: StoreFailure) { if (code != null) assertEquals(code, failure.code) }
    }
    private class Guard : EnrollmentJournalGuard {
        var generation = 1L
        var commits = 0
        var afterCommit: ((Int) -> Unit)? = null
        override fun <T> operation(generation: Long, body: (commit: (() -> Unit) -> Unit) -> T): T = synchronized(this) {
            requireStore(this.generation == generation, StoreCode.STALE_GENERATION)
            val result = body { mutation ->
                requireStore(this.generation == generation, StoreCode.STALE_GENERATION)
                mutation(); commits++; afterCommit?.invoke(commits)
            }
            requireStore(this.generation == generation, StoreCode.STALE_GENERATION); result
        }
    }
    private fun journal(guard: Guard) = EnrollmentJournalStore(root, env, guard)
    private fun proof(attempt: OwnedEnrollmentAttempt, owner: EnrollmentOwner, spki: ByteArray, enrollment: String? = null,
        installation: String = attempt.installationId): ByteArray {
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(spki).joinToString("") { "%02x".format(it) }
        val nonce = Base64.encodeToString(ByteArray(32) { 7 }, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        return listOf("KAPIT-C2-MOBILE-PROOF-V1", if (enrollment == null) "NEW_ENROLLMENT" else "REAUTHENTICATE", uuid(),
            owner.userId, owner.organizationId, enrollment ?: "-", installation, fingerprint, nonce, "1792195260", "").joinToString("\n").toByteArray()
    }
    @Before fun prepare() {
        check(context.packageName.endsWith(".spike") && InstrumentationRegistry.getArguments().getString("ownedEmulator") == "true")
        check(android.os.Build.HARDWARE in setOf("ranchu", "goldfish")); check(!root.exists())
        env.requireEligibleUnlockedDevice()
        // A new journal must not adopt another fixture's keys. Never erase pre-existing aliases.
        check(aliases().isEmpty())
    }
    @After fun cleanup() {
        repositories.forEach { try { it.close() } catch (_: Exception) {} }
        remember(); val store = keys(); ownedRefs.forEach { store.deleteEntry("kapit.proof.v1.$it") }
        check(root.parentFile.canonicalFile == context.noBackupFilesDir.canonicalFile && root.name.startsWith("journal-test-")); root.deleteRecursively()
    }
    @Test fun lostIssuanceReusesOwnedKeyAfterRepositoryRestartAndBindsOnlyExactEnrollment() {
        var repo = repository(); var generation = repo.access.value.generation
        val owner = EnrollmentOwner(uuid(), uuid()); val account = AccountIdentity(owner.organizationId, owner.userId, uuid())
        var journal = repo.enrollmentJournal
        val discovery = journal.discovery(generation); val spki = journal.publicSpki(discovery)
        assertArrayEquals(spki, journal.publicSpki(journal.discovery(generation)))
        val reserved = journal.reserveOwner(discovery, owner); assertFalse(reserved.requiresFreshChallenge); remember()
        val message = proof(reserved.attempt, owner, spki); val signature = journal.sign(reserved.attempt, message)
        assertTrue(Signature.getInstance("SHA256withECDSA").run { initVerify(KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))); update(message); verify(signature) })
        // Simulated server issuance response lost before local binding. No server success claim.
        repo.close(); repo = repository(); generation = repo.access.value.generation; journal = repo.enrollmentJournal
        val recovered = journal.reserveOwner(journal.discovery(generation), owner)
        assertTrue(recovered.requiresFreshChallenge); assertArrayEquals(spki, journal.publicSpki(recovered.attempt))
        assertTrue(journal.sign(recovered.attempt, proof(recovered.attempt, owner, spki, account.enrollmentId)).isNotEmpty())
        val binding = journal.bindEnrollment(recovered.attempt, account); assertEquals(account.storeRef, binding.storeRef)
        val same = journal.reserveOwner(journal.discovery(generation), owner)
        denied(StoreCode.SCOPE_DENIED) { journal.bindEnrollment(same.attempt, account.copy(enrollmentId = uuid())) }
        assertFalse(repo.access.value.ready)
    }
    @Test fun wrongOwnerInstallationKeyAndBoundEnrollmentNeverSign() {
        val guard = Guard(); val journal = journal(guard); val owner = EnrollmentOwner(uuid(), uuid())
        val attempt = journal.reserveOwner(journal.discovery(1), owner).attempt; remember(); val public = journal.publicSpki(attempt)
        denied(StoreCode.SCOPE_DENIED) { journal.sign(attempt, proof(attempt, EnrollmentOwner(uuid(), owner.userId), public)) }
        denied(StoreCode.SCOPE_DENIED) { journal.sign(attempt, proof(attempt, owner, public, installation = uuid())) }
        denied(StoreCode.SCOPE_DENIED) { journal.sign(attempt, proof(attempt, owner, public + byteArrayOf(0))) }
        val account = AccountIdentity(owner.organizationId, owner.userId, uuid()); journal.bindEnrollment(attempt, account)
        val bound = journal.reserveOwner(journal.discovery(1), owner).attempt; remember()
        denied(StoreCode.SCOPE_DENIED) { journal.sign(bound, proof(bound, owner, public, uuid())) }
        assertTrue(journal.sign(bound, proof(bound, owner, public, account.enrollmentId)).isNotEmpty())
    }
    @Test fun staleGenerationRevisionAndForeignIssuerCannotMutateJournal() {
        val guard = Guard(); val journal = journal(guard); val ticket = journal.discovery(1); remember()
        val owner = EnrollmentOwner(uuid(), uuid()); val attempt = journal.reserveOwner(ticket, owner).attempt
        denied(StoreCode.STALE_GENERATION) { journal.reserveOwner(ticket, EnrollmentOwner(uuid(), uuid())) }
        val replacement = journal(guard)
        denied(StoreCode.STALE_GENERATION) { replacement.publicSpki(attempt) }
        guard.generation = 2
        denied(StoreCode.STALE_GENERATION) { journal.sign(attempt, proof(attempt, owner, byteArrayOf(1))) }
        assertEquals(1, aliases().size)
    }
    @Test fun crashAfterDiscoveryReservationFailsClosedWithoutGeneratingRepeatedAliases() {
        val guard = Guard(); guard.afterCommit = { if (it == 2) throw StoreFailure(StoreCode.STORAGE_UNAVAILABLE) }
        denied(StoreCode.STORAGE_UNAVAILABLE) { journal(guard).discovery(1) }; remember()
        assertEquals(0, aliases().size); guard.afterCommit = null
        repeat(3) { denied(StoreCode.KEY_UNAVAILABLE) { journal(guard).discovery(1) } }
        assertEquals(0, aliases().size); assertEquals(1, ownedRefs.size)
    }
    @Test fun interruptedCandidatePersistenceRetainsOneKeyAndRefusesAliasGrowth() {
        val guard = Guard(); journal(guard).discovery(1); remember()
        // Reproduce the durable crash boundary: key generation completed, but its
        // candidate completion marker did not persist. The earlier intent remains.
        val reference = ownedRefs.single(); check(File(root, "proofs/$reference.candidate").delete())
        assertTrue(File(root, "proofs/$reference.creation").isFile); assertEquals(1, aliases().size)
        repeat(3) { denied(StoreCode.KEY_UNAVAILABLE) { journal(guard).discovery(1) } }
        assertEquals(1, aliases().size)
        val keys = EnrollmentProofKeys(File(root, "proofs"), env)
        denied(StoreCode.KEY_UNAVAILABLE) { keys.createCandidate() }; assertEquals(1, aliases().size)
    }
    @Test fun interruptedBindingRetainsOwnerAndSameKeyForExplicitRecovery() {
        val guard = Guard(); var journal = journal(guard); val owner = EnrollmentOwner(uuid(), uuid())
        val attempt = journal.reserveOwner(journal.discovery(1), owner).attempt; remember()
        val public = journal.publicSpki(attempt); val account = AccountIdentity(owner.organizationId, owner.userId, uuid())
        // Reproduce crash after the exact write-once key binding but before the
        // journal's store_ref commit. No server call or actual process kill is claimed.
        EnrollmentProofKeys(File(root, "proofs"), env).bind(ProofKeyReference(attempt.proofRef), account)
        journal = journal(guard)
        val recovered = journal.reserveOwner(journal.discovery(1), owner); remember()
        assertArrayEquals(public, journal.publicSpki(recovered.attempt)); assertTrue(recovered.requiresFreshChallenge)
        assertEquals(account.storeRef, journal.bindEnrollment(recovered.attempt, account).storeRef)
    }
    @Test fun missingOrCorruptJournalPreservesKeysAndCannotInitializeReplacement() {
        val guard = Guard(); val journal = journal(guard); journal.discovery(1); remember(); val original = aliases()
        val file = File(root, "enrollment.journal"); val bytes = file.readBytes(); check(file.delete())
        repeat(2) { denied(StoreCode.KEY_UNAVAILABLE) { journal(guard).discovery(1) } }; assertEquals(original, aliases())
        file.writeText("invalid fixture")
        denied(StoreCode.KEY_UNAVAILABLE) { journal(guard).discovery(1) }; assertEquals(original, aliases()); file.writeBytes(bytes)
    }
    @Test fun concurrentProofPreparationBindingAndPublicReadCompleteWithoutLockInversion() {
        check(File(root, "proofs").mkdirs()); val keys = EnrollmentProofKeys(File(root, "proofs"), env)
        val reference = keys.createCandidate(); ownedRefs += reference.opaqueId
        val account = AccountIdentity(uuid(), uuid(), uuid()); val start = CountDownLatch(1); val pool = Executors.newFixedThreadPool(3)
        try {
            val prepare = pool.submit { start.await(); repeat(12) { keys.prepareBinding(reference, account) } }
            val reads = pool.submit { start.await(); repeat(12) { assertTrue(keys.publicKey(reference).isNotEmpty()) } }
            val bind = pool.submit { start.await(); repeat(12) { keys.bind(reference, account) } }
            start.countDown(); listOf(prepare, reads, bind).forEach { it.get(30, TimeUnit.SECONDS) }
            assertEquals(reference, keys.bound(account))
        } finally { pool.shutdownNow() }
    }
}
