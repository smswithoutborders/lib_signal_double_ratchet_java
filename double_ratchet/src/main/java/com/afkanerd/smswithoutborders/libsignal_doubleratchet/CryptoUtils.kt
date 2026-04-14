package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.content.Context
import at.favre.lib.hkdf.HKDF
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols
import com.google.common.primitives.Bytes
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.EphemeralKeyPair
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

object CryptoUtils {
    fun hkdf(
        ikm: ByteArray,
        salt: ByteArray?,
        info: ByteArray?,
        len: Int,
    ): ByteArray {
        return HKDF.fromHmacSha512()
            .extractAndExpand(
                salt,
                ikm,
                info,
                len
            )
    }

    fun hmac(data: ByteArray?): Mac {
        val algorithm = "HmacSHA512"
        val output = Mac.getInstance(algorithm)
        val key: SecretKey = SecretKeySpec(data, algorithm)
        output.init(key)
        return output
    }

    fun generateKeysNK(
        context: Context,
        ephemeralKeyPair: AsymmetricCipherKeyPair,
        authenticationPublicKey: CipherParameters,
        ephemeralPublicKey: CipherParameters,
        salt: ByteArray,
        info: ByteArray,
    ): Triple<ByteArray, ByteArray, ByteArray> {
        val protocols = Protocols(context)
        val dh1 = protocols.dh(ephemeralKeyPair, authenticationPublicKey)
        val dh2 = protocols.dh(ephemeralKeyPair, ephemeralPublicKey)
        return hkdf(
            ikm = dh1,
            salt = salt,
            info = info,
            len = 32,
        ).run {
            hkdf(
                ikm = dh2,
                salt = this,
                info = info,
                len = 96,
            ).run {
                Triple(
                    this.sliceArray(0 until 32),
                    this.sliceArray(32 until 64),
                    this.sliceArray(64 until 96),
                )
            }
        }
    }

    fun generateKeysNKServer(
        context: Context,
        authenticationKeypair: AsymmetricCipherKeyPair,
        ephemeralKeyPair: AsymmetricCipherKeyPair,
        ephemeralPublicKey: CipherParameters,
        salt: ByteArray,
        info: ByteArray,
    ): Triple<ByteArray, ByteArray, ByteArray> {
        val protocols = Protocols(context)
        val dh1 = protocols.dh(authenticationKeypair, ephemeralPublicKey)
        val dh2 = protocols.dh(ephemeralKeyPair, ephemeralPublicKey)
        return hkdf(
            ikm = dh1,
            salt = salt,
            info = info,
            len = 32,
        ).run {
            hkdf(
                ikm = dh2,
                salt = this,
                info = info,
                len = 96,
            ).run {
                Triple(
                    this.sliceArray(0 until 32),
                    this.sliceArray(32 until 64),
                    this.sliceArray(64 until 96),
                )
            }
        }
    }

    data class NoiseIKKey(
        val keys: Triple<ByteArray, ByteArray, ByteArray>,
        val h: ByteArray
    )

    fun generateKeysIK(
        context: Context,
        ephemeralKeyPair: AsymmetricCipherKeyPair,
        authenticationPublicKey: CipherParameters,
        staticKeyPair: AsymmetricCipherKeyPair,
        info: ByteArray,
        headerInfo: ByteArray,
    ) : NoiseIKKey {
        val protocols = Protocols(context)

        var h = "Noise_IK_25519_AESGCM_SHA256".encodeToByteArray().sha256()
        var ck = h

        h = (h + (authenticationPublicKey as X25519PublicKeyParameters).encoded).sha256()
        h = (h + (ephemeralKeyPair.public as X25519PublicKeyParameters).encoded).sha256()

        val dhEs = protocols.dh(ephemeralKeyPair, authenticationPublicKey)

        return hkdf(
            ikm = dhEs,
            salt = ck,
            info = info,
            len = 2
        ).run {
            ck = this.sliceArray(0 until 32)
            var k = this.sliceArray(32 until 64)
            val csPkEnc = Cryptography.AesGcm.encrypt(
                SecretKeySpec(k, "AES"),
                (staticKeyPair.public as X25519PublicKeyParameters).encoded,
                h
            )
            h = (h + csPkEnc).sha256()
            val dhSs = protocols.dh(staticKeyPair, authenticationPublicKey)

            hkdf(
                ikm = dhSs,
                salt = ck,
                info = info,
                len = 2
            ).run {
                ck = this.sliceArray(0 until 32)
                k = this.sliceArray(32 until 64)
                val ciphertext = Cryptography.AesGcm.encrypt(
                    SecretKeySpec(k, "AES"),
                    "".encodeToByteArray(),
                    h
                )
                h = (h + ciphertext).sha256()

                hkdf(
                    ikm = dhSs,
                    salt = ck,
                    info = headerInfo,
                    len = 3
                ).run {
                    NoiseIKKey(
                        Triple(
                            this.sliceArray(0 until 32),
                            this.sliceArray(32 until 64),
                            this.sliceArray(64 until 96),
                        ),
                        h
                    )
                }
            }
        }
    }

    fun generateKeysIKForwardSecrecy(
        context: Context,
        h: ByteArray,
        ck: ByteArray,
        ephemeralKeyPair: AsymmetricCipherKeyPair,
        ephemeralResponderPublicKey: CipherParameters,
        authenticationPublicKey: CipherParameters,
        info: ByteArray,
        headerInfo: ByteArray,
    ) : NoiseIKKey{
        val protocols = Protocols(context)

        var h = (h + (ephemeralResponderPublicKey as X25519PublicKeyParameters).encoded).sha256()
        val dhEe = protocols.dh(ephemeralKeyPair, ephemeralResponderPublicKey)

        return hkdf(
            ikm = dhEe,
            salt = ck,
            info = info,
            len = 2
        ).run {
            var ck = this.sliceArray(0 until 32)
            var k = this.sliceArray(32 until 64)
            var ciphertext = Cryptography.AesGcm.encrypt(
                SecretKeySpec(k, "AES"),
                "".encodeToByteArray(),
                h
            )
            h = (h + ciphertext).sha256()
            val dhSe = protocols.dh(ephemeralKeyPair, authenticationPublicKey)
            hkdf(
                ikm = dhSe,
                salt = ck,
                info = info,
                len = 2
            ).run {
                ck = this.sliceArray(0 until 32)
                k = this.sliceArray(32 until 64)
                ciphertext = Cryptography.AesGcm.encrypt(
                    SecretKeySpec(k, "AES"),
                    "".encodeToByteArray(),
                    h
                )
                h = (h + ciphertext).sha256()

                hkdf(
                    ikm = "".encodeToByteArray(),
                    salt = ck,
                    info = headerInfo,
                    len = 3
                ).run {
                    NoiseIKKey(
                        Triple(
                            this.sliceArray(0 until 32),
                            this.sliceArray(32 until 64),
                            this.sliceArray(64 until 96),
                        ),
                        h
                    )
                }
            }
        }
    }

    fun ByteArray.sha256(): ByteArray {
        return MessageDigest
            .getInstance("SHA-256")
            .digest(this)
    }



}
