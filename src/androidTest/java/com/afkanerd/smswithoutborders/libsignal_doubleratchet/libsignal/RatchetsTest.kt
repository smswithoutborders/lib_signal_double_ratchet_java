package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.content.Context
import androidx.core.util.component1
import androidx.core.util.component2
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SmallTest
import androidx.test.platform.app.InstrumentationRegistry
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.KeystoreHelpers
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityCurve25519
import junit.framework.TestCase.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom

@SmallTest
class RatchetsTest {
    var context: Context =
        InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun completeRatchetTest() {
        val alice = SecurityCurve25519()
        val bob = SecurityCurve25519()

        val SK = alice.calculateSharedSecret(bob.generateKey())
        val SK1 = bob.calculateSharedSecret(alice.generateKey())
        assertArrayEquals(SK, SK1)

        val aliceState = States()
        Ratchets.ratchetInitAlice(aliceState, SK, bob.generateKey())

        val bobState = States()
        Ratchets.ratchetInitBob(bobState, SK, bob.getKeypair())

        val originalText = SecureRandom.getSeed(32);
        val (header, aliceCipherText) = Ratchets.ratchetEncrypt(aliceState, originalText,
            bob.generateKey())

        var header1: Headers? = null
        var aliceCipherText1: ByteArray? = null
        for(i in 1..10) {
            val (header, aliceCipherText) = Ratchets.ratchetEncrypt(aliceState, originalText,
                bob.generateKey())
            header1 = header
            aliceCipherText1 = aliceCipherText
        }

        val bobPlainText = Ratchets.ratchetDecrypt(bobState, header, aliceCipherText,
            bob.generateKey())

        val bobPlainText1 = Ratchets.ratchetDecrypt(bobState, header1, aliceCipherText1,
            bob.generateKey())
        println(bobState.serializedStates)

        assertArrayEquals(originalText, bobPlainText)
        assertArrayEquals(originalText, bobPlainText1)
    }
}

