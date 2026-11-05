package org.kapit.c2.mobile.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.security.KeyFactory
import java.security.KeyStore
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import org.junit.Test
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.kapit.c2.mobile.domain.*

@RunWith(AndroidJUnit4::class)
class EnrollmentProofKeysTest {
    @Test fun separateAccountProofAliasesCannotRebindOrUnlockContent() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        check(context.packageName.endsWith(".spike") && InstrumentationRegistry.getArguments().getString("ownedEmulator") == "true")
        check(android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        val root = File(context.noBackupFilesDir, "proof-test-${UUID.randomUUID()}"); check(!root.exists())
        val keys = EnrollmentProofKeys(root, AndroidAccessEnvironment(context))
        val references = mutableListOf<ProofKeyReference>()
        fun uuid() = UUID.randomUUID().toString()
        val a = AccountIdentity(uuid(), uuid(), uuid()); val b = AccountIdentity(uuid(), uuid(), uuid())
        try {
            val first = keys.createCandidate().also(references::add); val second = keys.createCandidate().also(references::add)
            keys.bind(first, a); keys.bind(second, b)
            assertEquals(first, keys.bound(a)); assertEquals(second, keys.bound(b))
            assertFalse(keys.publicKey(first).contentEquals(keys.publicKey(second)))
            try { keys.bind(first, b); fail("Cross-account binding must fail") } catch (failure: StoreFailure) { assertEquals(StoreCode.SCOPE_DENIED, failure.code) }
            val message = "KAPIT synthetic proof fixture\n".toByteArray()
            val signature = keys.sign(first, message)
            val publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(keys.publicKey(first)))
            fun verify(bytes: ByteArray): Boolean = Signature.getInstance("SHA256withECDSA").run { initVerify(publicKey); update(bytes); this.verify(signature) }
            assertTrue(verify(message)); assertFalse(verify("changed".toByteArray()))
            assertEquals(0x30, signature[0].toInt())
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            assertNull(store.getKey("kapit.proof.v1.${first.opaqueId}", null).encoded)
            assertFalse(store.containsAlias("kapit.wrap.v1.${a.storeRef}"))
        } finally {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            references.forEach { store.deleteEntry("kapit.proof.v1.${it.opaqueId}") }
            check(root.parentFile.canonicalFile == context.noBackupFilesDir.canonicalFile && root.name.startsWith("proof-test-")); root.deleteRecursively()
        }
    }
}
