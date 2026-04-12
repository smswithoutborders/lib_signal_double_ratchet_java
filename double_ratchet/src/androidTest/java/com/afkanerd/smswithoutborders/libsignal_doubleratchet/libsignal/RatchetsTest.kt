package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.content.Context
import androidx.test.filters.SmallTest
import androidx.test.platform.app.InstrumentationRegistry
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoUtils
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoUtils.sha256
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.generateRandomBytes
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Before
import org.junit.Test
import java.security.SecureRandom

@SmallTest
class RatchetsTest {
    var context: Context =
        InstrumentationRegistry.getInstrumentation().targetContext
    val protocol = Protocols(context)

    lateinit var aliceRk: ByteArray
    lateinit var aliceHk: ByteArray
    lateinit var aliceNhk: ByteArray

    lateinit var bobRk: ByteArray
    lateinit var bobHk: ByteArray
    lateinit var bobNhk: ByteArray

    val aliceKeypair = protocol.generateDH()
    val bobStaticKeypair = protocol.generateDH()
    val bobKeypair = protocol.generateDH()

    val salt = "completeRatchetTest_v1".encodeToByteArray()
    val info = context.generateRandomBytes(16) +
            (aliceKeypair.public as X25519PublicKeyParameters).encoded +
            (bobKeypair.public as X25519PublicKeyParameters).encoded +
            (bobStaticKeypair.public as X25519PublicKeyParameters).encoded

    @Before
    fun start() {
        CryptoUtils.generateKeysNK(
            context = context,
            ephemeralKeyPair = aliceKeypair,
            authenticationPublicKey = bobStaticKeypair.public,
            ephemeralPublicKey = bobKeypair.public,
            salt = salt,
            info = info
        ).let {
            aliceRk = it.first
            aliceHk = it.second
            aliceNhk = it.third
        }

        CryptoUtils.generateKeysNKServer(
            context = context,
            authenticationKeypair = bobStaticKeypair,
            ephemeralKeyPair = bobKeypair,
            ephemeralPublicKey = aliceKeypair.public,
            salt = salt,
            info = info
        ).let {
            bobRk = it.first
            bobHk = it.second
            bobNhk = it.third
        }

        assertArrayEquals(aliceRk, bobRk)
        assertArrayEquals(aliceHk, bobHk)
        assertArrayEquals(aliceNhk, bobNhk)
    }

    @Test
    fun completeRatchetTest() {
        val ratchets = RatchetsHE(context)
        val aliceState = States()
        ratchets.ratchetInitAlice(
            state = aliceState,
            sk = aliceRk,
            bobDhPublicKey = bobKeypair.public,
            sharedHka = aliceHk,
            sharedNHka = aliceNhk
        )

        val bobState = States()
        ratchets.ratchetInitBob(
            state = bobState,
            sk = bobRk,
            bobKeypair = bobKeypair,
            sharedHka = bobHk,
            sharedNHka = bobNhk
        )

        val originalText = SecureRandom.getSeed(32);

        val ad = "RatchetsTest".encodeToByteArray().sha256()
        var ratchetPayload = ratchets.ratchetEncrypt(
            state = aliceState,
            plaintext = originalText,
            ad = ad
        )

        var plaintext = ratchets.ratchetDecrypt(
            state = bobState,
            encHeader = ratchetPayload.header,
            cipherText = ratchetPayload.cipherText,
            ad = ad
        )

        assertArrayEquals(originalText, plaintext)

        ratchetPayload = ratchets.ratchetEncrypt(
            state = bobState,
            plaintext = originalText,
            ad = ad
        )

        plaintext = ratchets.ratchetDecrypt(
            state = aliceState,
            encHeader = ratchetPayload.header,
            cipherText = ratchetPayload.cipherText,
            ad = ad
        )

        assertArrayEquals(originalText, plaintext)
    }

    @Test
    fun completeRatchetOutOfOrderTest() {
        val ratchets = RatchetsHE(context)
        val aliceState = States()
        ratchets.ratchetInitAlice(
            state = aliceState,
            sk = aliceRk,
            bobDhPublicKey = bobKeypair.public,
            sharedHka = aliceHk,
            sharedNHka = aliceNhk
        )

        val bobState = States()
        ratchets.ratchetInitBob(
            state = bobState,
            sk = bobRk,
            bobKeypair = bobKeypair,
            sharedHka = bobHk,
            sharedNHka = bobNhk
        )

        val originalText = SecureRandom.getSeed(32);

        val ad = "RatchetsTest".encodeToByteArray().sha256()
        var ratchetPayload = ratchets.ratchetEncrypt(
            state = aliceState,
            plaintext = originalText,
            ad = ad
        )
        for(i in 1..5) {
            ratchetPayload = ratchets.ratchetEncrypt(
                state = aliceState,
                plaintext = originalText,
                ad = ad
            )
        }

        var plaintext = ratchets.ratchetDecrypt(
            state = bobState,
            encHeader = ratchetPayload.header,
            cipherText = ratchetPayload.cipherText,
            ad = ad
        )

        assertArrayEquals(originalText, plaintext)

        ratchetPayload = ratchets.ratchetEncrypt(
            state = bobState,
            plaintext = originalText,
            ad = ad
        )

        plaintext = ratchets.ratchetDecrypt(
            state = aliceState,
            encHeader = ratchetPayload.header,
            cipherText = ratchetPayload.cipherText,
            ad = ad
        )

        assertArrayEquals(originalText, plaintext)
    }
}

