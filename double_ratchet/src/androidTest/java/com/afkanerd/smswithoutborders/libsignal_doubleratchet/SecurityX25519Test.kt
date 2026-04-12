package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.filters.SmallTest
import androidx.test.platform.app.InstrumentationRegistry
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature

@SmallTest
class SecurityX25519Test {

    var context: Context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun keystoreEd25519() {
        val keystoreAlias = "keystoreAlias"
        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )
        val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
            keystoreAlias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).run {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            build()
        }

        kpg.initialize(parameterSpec)
        val kp = kpg.generateKeyPair()

        val ks: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }
        val entry: KeyStore.Entry = ks.getEntry(keystoreAlias, null)
        if (entry !is KeyStore.PrivateKeyEntry) {
            throw Exception("No instance of keystore")
        }

        val data = "Hello world".encodeToByteArray()
        val signature: ByteArray = Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.privateKey)
            update(data)
            sign()
        }

    }

    @Test
    fun sharedSecret() {
        val protocols = Protocols(context)
        val alice = protocols.generateDH()
        val bob = protocols.generateDH()

        val aliceSharedSecret = protocols.dh(alice, bob.public)
        val bobSharedSecret = protocols.dh(bob, alice.public)

        assertArrayEquals(aliceSharedSecret, bobSharedSecret)
    }
}