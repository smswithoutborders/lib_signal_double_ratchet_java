package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.content.Context
import androidx.test.filters.SmallTest
import androidx.test.platform.app.InstrumentationRegistry
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoUtils
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoUtils.sha256
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.Cryptography
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

    val aliceKeypair = protocol.generateDH()
    val bobStaticKeypair = protocol.generateDH()
    val bobKeypair = protocol.generateDH()

    val salt = "completeRatchetTest_v1".encodeToByteArray()
    val info = context.generateRandomBytes(16) +
            aliceKeypair.publicKey +
            bobKeypair.publicKey +
            bobStaticKeypair.publicKey

    @Test
    fun completeRatchetTest() {
        Cryptography.generateKeysNK(
            context = context,
            ephemeralKeyPair = aliceKeypair,
            authenticationPublicKey = X25519PublicKeyParameters(bobStaticKeypair.publicKey),
            ephemeralPublicKey = X25519PublicKeyParameters(bobKeypair.publicKey),
            salt = salt,
            info = info
        ).use { alice ->
            Cryptography.generateKeysNKServer(
                context = context,
                authenticationKeypair = bobStaticKeypair,
                ephemeralKeyPair = bobKeypair,
                ephemeralPublicKey = X25519PublicKeyParameters(aliceKeypair.publicKey),
                salt = salt,
                info = info
            ).let { bob ->
                assertArrayEquals(alice.rk, bob.first)
                assertArrayEquals(alice.hk, bob.second)
                assertArrayEquals(alice.nhk, bob.third)

                val ratchets = RatchetsHE(context)
                val aliceState = States()
                ratchets.ratchetInitAlice(
                    state = aliceState,
                    sk = alice.rk,
                    bobDhPublicKey = X25519PublicKeyParameters(bobKeypair.publicKey),
                    sharedHka = alice.hk,
                    sharedNHka = alice.nhk
                )

                val bobState = States()
                ratchets.ratchetInitBob(
                    state = bobState,
                    sk = bob.first,
                    bobKeypair = bobKeypair,
                    sharedHka = bob.second,
                    sharedNHka = bob.third
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

        }


    }

    @Test
    fun completeRatchetOutOfOrderTest() {
        Cryptography.generateKeysNK(
            context = context,
            ephemeralKeyPair = aliceKeypair,
            authenticationPublicKey = X25519PublicKeyParameters(bobStaticKeypair.publicKey),
            ephemeralPublicKey = X25519PublicKeyParameters(bobKeypair.publicKey),
            salt = salt,
            info = info
        ).use { alice ->
            Cryptography.generateKeysNKServer(
                context = context,
                authenticationKeypair = bobStaticKeypair,
                ephemeralKeyPair = bobKeypair,
                ephemeralPublicKey = X25519PublicKeyParameters(aliceKeypair.publicKey),
                salt = salt,
                info = info
            ).let { bob ->
                assertArrayEquals(alice.rk, bob.first)
                assertArrayEquals(alice.hk, bob.second)
                assertArrayEquals(alice.nhk, bob.third)

                val ratchets = RatchetsHE(context)
                val aliceState = States()
                ratchets.ratchetInitAlice(
                    state = aliceState,
                    sk = alice.rk,
                    bobDhPublicKey = X25519PublicKeyParameters(bobKeypair.publicKey),
                    sharedHka = alice.hk,
                    sharedNHka = alice.nhk
                )

                val bobState = States()
                ratchets.ratchetInitBob(
                    state = bobState,
                    sk = bob.first,
                    bobKeypair = bobKeypair,
                    sharedHka = bob.second,
                    sharedNHka = bob.third
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

                for(i in 1..5) {
                    ratchetPayload = ratchets.ratchetEncrypt(
                        state = aliceState,
                        plaintext = originalText,
                        ad = ad
                    )
                }

                plaintext = ratchets.ratchetDecrypt(
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
    }
}

