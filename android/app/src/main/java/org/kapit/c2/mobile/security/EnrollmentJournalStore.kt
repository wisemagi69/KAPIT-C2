package org.kapit.c2.mobile.security

import android.util.AtomicFile
import android.util.Base64
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import kotlinx.serialization.json.*
import org.kapit.c2.mobile.domain.*

/** The repository holds its IO owner and performs short mutations under its generation fence. */
internal interface EnrollmentJournalGuard {
    fun <T> operation(generation: Long, body: (commit: (() -> Unit) -> Unit) -> T): T
}

/** Opaque no-backup recovery metadata; it never grants local protected-store authority. */
internal class EnrollmentJournalStore(
    private val root: File,
    environment: StoreEnvironment,
    private val guard: EnrollmentJournalGuard,
) : ProtectedEnrollmentJournal {
    private val file = File(root, "enrollment.journal")
    private val proofRoot = File(root, "proofs")
    private val keys = EnrollmentProofKeys(proofRoot, environment)
    private val issuer = UUID.randomUUID().toString()
    private data class Entry(val owner: String, val proof: String, val store: String?)
    private data class Journal(val installation: String, val revision: Long, val discovery: String?, val owners: List<Entry>)

    override fun discovery(expectedGeneration: Long): DiscoveryTicket = guard.operation(expectedGeneration) { commit ->
        var journal = readOrInitialize(commit)
        if (journal.discovery == null) {
            requireStore(journal.owners.size <= 99, StoreCode.STORAGE_UNAVAILABLE)
            val candidate = ProofKeyReference(UUID.randomUUID().toString())
            val next = journal.copy(revision = nextRevision(journal), discovery = candidate.opaqueId)
            // Reserve the only discovery reference before generating its key.
            // A crash/fence cannot leave an untracked candidate and create another on retry.
            commit { write(next) }; journal = next
            keys.createReservedCandidate(candidate)
        }
        keys.publicKey(ProofKeyReference(journal.discovery!!))
        DiscoveryTicket(expectedGeneration, journal.installation, journal.revision, journal.discovery!!, issuer)
    }

    override fun publicSpki(discovery: DiscoveryTicket): ByteArray = guard.operation(discovery.generation) {
        val journal = read(); requireDiscovery(journal, discovery)
        keys.publicKey(ProofKeyReference(discovery.proofRef))
    }

    override fun reserveOwner(discovery: DiscoveryTicket, owner: EnrollmentOwner): OwnerReservation = guard.operation(discovery.generation) { commit ->
        val journal = read(); requireDiscovery(journal, discovery)
        val index = ownerIndex(owner)
        val existing = journal.owners.singleOrNull { it.owner == index }
        if (existing != null) {
            keys.publicKey(ProofKeyReference(existing.proof))
            OwnerReservation(attempt(journal, discovery.generation, existing), true)
        } else {
            requireStore(journal.owners.size < 99, StoreCode.STORAGE_UNAVAILABLE)
            val entry = Entry(index, discovery.proofRef, null)
            val next = journal.copy(revision = nextRevision(journal), discovery = null, owners = journal.owners + entry)
            commit { write(next) }
            OwnerReservation(attempt(next, discovery.generation, entry), false)
        }
    }

    override fun publicSpki(attempt: OwnedEnrollmentAttempt): ByteArray = guard.operation(attempt.generation) {
        val entry = requireAttempt(read(), attempt)
        keys.publicKey(ProofKeyReference(entry.proof))
    }

    override fun sign(attempt: OwnedEnrollmentAttempt, validatedProof: ByteArray): ByteArray = guard.operation(attempt.generation) {
        val journal = read(); val entry = requireAttempt(journal, attempt)
        validateProof(journal, entry, validatedProof)
        keys.sign(ProofKeyReference(entry.proof), validatedProof)
    }

    override fun bindEnrollment(attempt: OwnedEnrollmentAttempt, account: AccountIdentity): EnrollmentStoreBinding = guard.operation(attempt.generation) { commit ->
        val journal = read(); val entry = requireAttempt(journal, attempt)
        requireStore(entry.owner == ownerIndex(EnrollmentOwner(account.organizationId, account.userId)), StoreCode.SCOPE_DENIED)
        requireStore(entry.store == null || entry.store == account.storeRef, StoreCode.SCOPE_DENIED)
        requireStore(journal.owners.none { it.owner != entry.owner && it.store == account.storeRef }, StoreCode.SCOPE_DENIED)
        val next = if (entry.store == null) journal.copy(revision = nextRevision(journal),
            owners = journal.owners.map { if (it.owner == entry.owner) it.copy(store = account.storeRef) else it }) else journal
        val proofBinding = keys.prepareBinding(ProofKeyReference(entry.proof), account)
        commit {
            // The already durable pending owner retains this same key if a crash interrupts binding.
            keys.commitBinding(proofBinding)
            if (next !== journal) write(next)
        }
        binding(next, attempt.generation, next.owners.single { it.owner == entry.owner })
    }

    override fun bindingForStore(expectedGeneration: Long, storeRef: String): EnrollmentStoreBinding? = guard.operation(expectedGeneration) {
        requireHash(storeRef)
        val journal = read()
        journal.owners.singleOrNull { it.store == storeRef }?.let { binding(journal, expectedGeneration, it) }
    }

    override fun matchesOwner(binding: EnrollmentStoreBinding, owner: EnrollmentOwner): Boolean = guard.operation(binding.generation) {
        val journal = read()
        // Bindings are immutable. Creating a later discovery ticket may advance
        // the journal revision without changing this retained owner/store pair.
        requireStore(binding.issuer == issuer && binding.installationId == journal.installation && binding.journalRevision <= journal.revision,
            StoreCode.STALE_GENERATION)
        val entry = journal.owners.singleOrNull { it.owner == binding.ownerIndex && it.store == binding.storeRef }
            ?: throw StoreFailure(StoreCode.KEY_UNAVAILABLE)
        entry.owner == ownerIndex(owner)
    }

    private fun readOrInitialize(commit: (() -> Unit) -> Unit): Journal {
        if (file.exists() || File(file.path + ".bak").exists()) return read()
        val earlier = File(root, "selection").exists() || proofRoot.listFiles()?.isNotEmpty() == true || keys.hasAnyProofAlias() ||
            root.listFiles()?.any { it.isDirectory && Regex("[0-9a-f]{64}").matches(it.name) } == true
        requireStore(!earlier, StoreCode.KEY_UNAVAILABLE)
        val initial = Journal(UUID.randomUUID().toString(), 0, null, emptyList())
        commit { write(initial) }
        return initial
    }

    private fun read(): Journal {
        try {
            val bytes = AtomicFile(file).openRead().use { input ->
                val buffer = ByteArray(65_537)
                try {
                    var count = 0
                    while (count < buffer.size) {
                        val read = input.read(buffer, count, buffer.size - count)
                        if (read < 0) break
                        requireStore(read > 0, StoreCode.KEY_UNAVAILABLE)
                        count += read
                    }
                    buffer.copyOf(count)
                } finally { buffer.fill(0) }
            }
            try {
                val json = StrictJson.objectFrom(bytes, 65_536)
                requireStore(json.keys == setOf("version", "installation_id", "revision", "discovery_ref", "owners"), StoreCode.KEY_UNAVAILABLE)
                requireStore(json.requiredLong("version") == 1L, StoreCode.KEY_UNAVAILABLE)
                val installation = canonicalUuid(json.requiredString("installation_id"))
                val revision = json.requiredLong("revision"); requireStore(revision in 0 until Long.MAX_VALUE, StoreCode.KEY_UNAVAILABLE)
                val discovery = optionalString(json, "discovery_ref")?.also(::canonicalUuid)
                val entries = json["owners"] as? JsonArray ?: throw StoreFailure(StoreCode.KEY_UNAVAILABLE)
                requireStore(entries.size <= 99, StoreCode.KEY_UNAVAILABLE)
                val owners = entries.map { value ->
                    val item = value as? JsonObject ?: throw StoreFailure(StoreCode.KEY_UNAVAILABLE)
                    requireStore(item.keys == setOf("owner_index", "proof_ref", "store_ref"), StoreCode.KEY_UNAVAILABLE)
                    Entry(item.requiredString("owner_index").also(::requireHash), canonicalUuid(item.requiredString("proof_ref")),
                        optionalString(item, "store_ref")?.also(::requireHash))
                }
                requireStore(owners.map { it.owner }.distinct().size == owners.size && owners.map { it.proof }.distinct().size == owners.size &&
                    owners.mapNotNull { it.store }.distinct().size == owners.count { it.store != null } && owners.none { it.proof == discovery }, StoreCode.KEY_UNAVAILABLE)
                return Journal(installation, revision, discovery, owners)
            } finally { bytes.fill(0) }
        } catch (failure: Exception) {
            throw StoreFailure(StoreCode.KEY_UNAVAILABLE)
        }
    }

    private fun write(journal: Journal) {
        val value = buildJsonObject {
            put("version", 1); put("installation_id", journal.installation); put("revision", journal.revision); put("discovery_ref", journal.discovery)
            put("owners", JsonArray(journal.owners.map { entry -> buildJsonObject {
                put("owner_index", entry.owner); put("proof_ref", entry.proof); put("store_ref", entry.store)
            } }))
        }
        val bytes = CanonicalJson.bytes(value)
        try { requireStore(bytes.size <= 65_536, StoreCode.STORAGE_UNAVAILABLE); atomicWrite(file, bytes) } finally { bytes.fill(0) }
    }

    private fun requireDiscovery(journal: Journal, ticket: DiscoveryTicket) {
        requireStore(ticket.issuer == issuer && ticket.journalRevision == journal.revision && ticket.installationId == journal.installation &&
            ticket.proofRef == journal.discovery, StoreCode.STALE_GENERATION)
    }
    private fun requireAttempt(journal: Journal, ticket: OwnedEnrollmentAttempt): Entry {
        requireStore(ticket.issuer == issuer && ticket.journalRevision == journal.revision && ticket.installationId == journal.installation, StoreCode.STALE_GENERATION)
        return journal.owners.singleOrNull { it.owner == ticket.ownerIndex && it.proof == ticket.proofRef }
            ?: throw StoreFailure(StoreCode.KEY_UNAVAILABLE)
    }
    private fun attempt(journal: Journal, generation: Long, entry: Entry) = OwnedEnrollmentAttempt(generation, journal.installation, journal.revision, entry.owner, entry.proof, issuer)
    private fun binding(journal: Journal, generation: Long, entry: Entry) = EnrollmentStoreBinding(generation, entry.owner,
        entry.store ?: throw StoreFailure(StoreCode.KEY_UNAVAILABLE), journal.installation, journal.revision, issuer)
    private fun optionalString(json: JsonObject, key: String) = if (json[key] == JsonNull) null else json.requiredString(key)
    private fun nextRevision(journal: Journal): Long { requireStore(journal.revision < Long.MAX_VALUE - 1, StoreCode.STORAGE_UNAVAILABLE); return journal.revision + 1 }
    private fun requireHash(value: String) { requireStore(Regex("[0-9a-f]{64}").matches(value), StoreCode.KEY_UNAVAILABLE) }
    private fun ownerIndex(owner: EnrollmentOwner) = hash("$MOBILE_PROTOCOL\nowner\n${owner.organizationId}\n${owner.userId}\n".toByteArray(Charsets.US_ASCII))
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun validateProof(journal: Journal, entry: Entry, bytes: ByteArray) {
        requireStore(bytes.size in 1..2048 && bytes.all { it.toInt() in 0..127 }, StoreCode.VALIDATION_ERROR)
        val lines = bytes.toString(Charsets.US_ASCII).split('\n')
        requireStore(lines.size == 11 && lines.last().isEmpty() && lines[0] == "KAPIT-C2-MOBILE-PROOF-V1", StoreCode.VALIDATION_ERROR)
        canonicalUuid(lines[2]); canonicalUuid(lines[3]); canonicalUuid(lines[4]); canonicalUuid(lines[6])
        requireStore(lines[6] == journal.installation && ownerIndex(EnrollmentOwner(lines[4], lines[3])) == entry.owner, StoreCode.SCOPE_DENIED)
        val key = keys.publicKey(ProofKeyReference(entry.proof))
        requireStore(lines[7] == hash(key), StoreCode.SCOPE_DENIED)
        requireStore(Regex("[A-Za-z0-9_-]{43}").matches(lines[8]), StoreCode.VALIDATION_ERROR)
        val flags = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
        val nonce = try { Base64.decode(lines[8], flags) } catch (_: Exception) { throw StoreFailure(StoreCode.VALIDATION_ERROR) }
        requireStore(nonce.size == 32 && Base64.encodeToString(nonce, flags) == lines[8], StoreCode.VALIDATION_ERROR)
        requireStore(Regex("[1-9][0-9]{0,18}").matches(lines[9]) && (lines[9].toLongOrNull() ?: 0) > 0, StoreCode.VALIDATION_ERROR)
        when (lines[1]) {
            "NEW_ENROLLMENT" -> requireStore(lines[5] == "-", StoreCode.VALIDATION_ERROR)
            "REAUTHENTICATE" -> {
                val account = AccountIdentity(lines[4], lines[3], canonicalUuid(lines[5]))
                requireStore(entry.store == null || entry.store == account.storeRef, StoreCode.SCOPE_DENIED)
            }
            else -> throw StoreFailure(StoreCode.VALIDATION_ERROR)
        }
    }
}
