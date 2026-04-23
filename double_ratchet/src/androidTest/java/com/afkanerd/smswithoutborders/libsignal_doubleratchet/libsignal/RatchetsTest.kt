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


    val salt = "completeRatchetTest_v1".encodeToByteArray()

    @Test
    fun completeRatchetTest() {
        val aliceKeypair = protocol.generateDH()
        val bobStaticKeypair = protocol.generateDH()
        val bobKeypair = protocol.generateDH()
//        val info = context.generateRandomBytes(16) +
//                aliceKeypair.publicKey +
//                bobKeypair.publicKey +
//                bobStaticKeypair.publicKey
        val info = ByteArray(32)

        val ad = "RatchetsTest".encodeToByteArray().sha256()
        val originalText = SecureRandom.getSeed(32);
        var ratchetPayload: RatchetPayload?

        aliceKeypair.use { aliceKeypair ->
            bobKeypair.use { bobKeypair ->

                val alicePublicKey = aliceKeypair.publicKey.copyOf()
                val bobPublicKey = bobKeypair.publicKey.copyOf()
                val authenticationPublicKey = bobStaticKeypair.publicKey.copyOf()

                val aliceKey = Cryptography.generateKeysNK(
                    context = context,
                    ephemeralKeyPair = aliceKeypair,
                    authenticationPublicKey = authenticationPublicKey,
                    ephemeralPublicKey = bobPublicKey,
                    salt = salt,
                    info = info
                )

                val bob = Cryptography.generateKeysNKServer(
                    context = context,
                    authenticationKeypair = bobStaticKeypair,
                    ephemeralKeyPair = bobKeypair,
                    ephemeralPublicKey = alicePublicKey,
                    salt = salt,
                    info = info
                )


                val ratchets = RatchetsHE(context)

                aliceKey.use { alice ->
                    assertArrayEquals(alice.rk, bob.first)
                    assertArrayEquals(alice.hk, bob.second)
                    assertArrayEquals(alice.nhk, bob.third)

                    val aliceState = States()
                    aliceState.use { aliceState ->
                        ratchets.ratchetInitAlice(
                            state = aliceState,
                            sk = alice.rk,
                            bobDhPublicKey = bobPublicKey.copyOf(),
                            sharedHka = alice.hk,
                            sharedNHka = alice.nhk
                        )

                        ratchetPayload = ratchets.ratchetEncrypt(
                            state = aliceState,
                            plaintext = originalText,
                            ad = ad
                        )
                    }
                }


                val bobState = States()
                bobState.use { bobState ->
                    ratchets.ratchetInitBob(
                        state = bobState,
                        sk = bob.first,
                        bobKeypair = bobKeypair,
                        sharedHka = bob.second,
                        sharedNHka = bob.third
                    )
                    val plaintext = ratchets.ratchetDecrypt(
                        state = bobState,
                        encHeader = ratchetPayload!!.header,
                        cipherText = ratchetPayload.cipherText,
                        ad = ad
                    )
                    assertArrayEquals(originalText, plaintext)
                }
            }
        }
    }

    @Test
    fun completeRatchetOutOfOrderTest() {
        val aliceKeypair = protocol.generateDH()
        val bobStaticKeypair = protocol.generateDH()
        val bobKeypair = protocol.generateDH()
        val info = context.generateRandomBytes(16) +
                aliceKeypair.publicKey +
                bobKeypair.publicKey +
                bobStaticKeypair.publicKey
        Cryptography.generateKeysNK(
            context = context,
            ephemeralKeyPair = aliceKeypair,
            authenticationPublicKey = bobStaticKeypair.publicKey,
            ephemeralPublicKey = bobKeypair.publicKey,
            salt = salt,
            info = info
        ).use { alice ->
            Cryptography.generateKeysNKServer(
                context = context,
                authenticationKeypair = bobStaticKeypair,
                ephemeralKeyPair = bobKeypair,
                ephemeralPublicKey = aliceKeypair.publicKey,
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
                    bobDhPublicKey = bobKeypair.publicKey,
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

