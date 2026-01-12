package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.content.Context
import androidx.core.util.component1
import androidx.core.util.component2
import androidx.test.filters.SmallTest
import androidx.test.platform.app.InstrumentationRegistry
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoHelpers
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityCurve25519
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.security.SecureRandom

@SmallTest
class RatchetsTest {
    var context: Context =
        InstrumentationRegistry.getInstrumentation().targetContext
    @Test
    fun completeRatchetHETest() {
        val aliceEphemeralKeyPair = SecurityCurve25519()
        val aliceEphemeralHeaderKeyPair = SecurityCurve25519()
        val aliceEphemeralNextHeaderKeyPair = SecurityCurve25519()

        val bobStaticKeyPair = SecurityCurve25519()
        val bobEphemeralKeyPair = SecurityCurve25519()
        val bobEphemeralHeaderKeyPair = SecurityCurve25519()
        val bobEphemeralNextHeaderKeyPair = SecurityCurve25519()

        val aliceNonce = CryptoHelpers.generateRandomBytes(16)
        val bobNonce = CryptoHelpers.generateRandomBytes(16)

        val (aliceSk, aliceSkH, aliceSkNh) = SecurityCurve25519(aliceEphemeralKeyPair.privateKey)
            .agreeWithAuthAndNonce(
                authenticationPublicKey = bobStaticKeyPair.generateKey(),
                authenticationPrivateKey = null,
                headerPrivateKey = aliceEphemeralHeaderKeyPair.privateKey,
                nextHeaderPrivateKey = aliceEphemeralNextHeaderKeyPair.privateKey,
                publicKey = bobEphemeralKeyPair.generateKey(),
                headerPublicKey = bobEphemeralHeaderKeyPair.generateKey(),
                nextHeaderPublicKey = bobEphemeralNextHeaderKeyPair.generateKey(),
                salt = "RelaySMS v1".encodeToByteArray(),
                nonce1 = aliceNonce,
                nonce2 = bobNonce,
                info = "RelaySMS C2S DR v1".encodeToByteArray()
            )

        val (bobSk, bobSkH, bobSkNh) = SecurityCurve25519(bobEphemeralKeyPair.privateKey)
            .agreeWithAuthAndNonce(
                authenticationPublicKey = null,
                authenticationPrivateKey = bobStaticKeyPair.privateKey,
                headerPrivateKey = bobEphemeralHeaderKeyPair.privateKey,
                nextHeaderPrivateKey = bobEphemeralNextHeaderKeyPair.privateKey,
                publicKey = aliceEphemeralKeyPair.generateKey(),
                headerPublicKey = aliceEphemeralHeaderKeyPair.generateKey(),
                nextHeaderPublicKey = aliceEphemeralNextHeaderKeyPair.generateKey(),
                salt = "RelaySMS v1".encodeToByteArray(),
                nonce1 = aliceNonce,
                nonce2 = bobNonce,
                info = "RelaySMS C2S DR v1".encodeToByteArray()
            )

        assertArrayEquals(aliceSk, bobSk)
        assertArrayEquals(aliceSkH, bobSkH)
        assertArrayEquals(aliceSkNh, bobSkNh)

        val aliceState = States()
        RatchetsHE.ratchetInitAlice(
            state = aliceState,
            SK = aliceSk,
            bobDhPublicKey = bobEphemeralKeyPair.generateKey(),
            sharedHka = aliceSkH,
            sharedNhkb = aliceSkNh
        )

        val bobState = States()
        RatchetsHE.ratchetInitBob(
            state = bobState,
            SK = bobSk,
            bobDhPublicKeypair = bobEphemeralKeyPair.getKeypair(),
            sharedHka = bobSkH,
            sharedNhkb = bobSkNh
        )

        val originalText = SecureRandom.getSeed(32);
        val (encHeader, aliceCipherText) = RatchetsHE.ratchetEncrypt(
            aliceState,
            originalText,
            bobStaticKeyPair.generateKey()
        )

        var encHeader1: ByteArray? = null
        var aliceCipherText1: ByteArray? = null
        for(i in 1..10) {
            val (encHeader2, aliceCipherText2) = RatchetsHE.ratchetEncrypt(
                aliceState,
                originalText,
                bobStaticKeyPair.generateKey()
            )
            encHeader1 = encHeader2
            aliceCipherText1 = aliceCipherText2
        }

        val bobPlainText = RatchetsHE.ratchetDecrypt(
            state = bobState,
            encHeader = encHeader,
            cipherText = aliceCipherText,
            AD = bobStaticKeyPair.generateKey()
        )

        val bobPlainText1 = RatchetsHE.ratchetDecrypt(
            state = bobState,
            encHeader = encHeader1!!,
            cipherText = aliceCipherText1!!,
            AD = bobStaticKeyPair.generateKey()
        )

        assertArrayEquals(originalText, bobPlainText)
        assertArrayEquals(originalText, bobPlainText1)
    }

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
        println(bobState.serialize())

        assertArrayEquals(originalText, bobPlainText)
        assertArrayEquals(originalText, bobPlainText1)
    }
}

