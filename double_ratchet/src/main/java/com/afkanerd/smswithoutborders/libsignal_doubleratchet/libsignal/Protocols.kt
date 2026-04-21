package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.content.Context
import android.util.Pair
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoUtils
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoUtils.hkdf
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoUtils.hmac
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.Cryptography
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.R
import com.google.common.primitives.Bytes
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.lang.AutoCloseable
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * These implementations are based on the signal protocols specifications.
 * 
 * These are based on the recommended algorithms and parameters for the encryption
 * and decryption.
 * 
 * The goal for this would be to transform it into library which can be used across
 * other SMS projects.
 * 
 * [...](https://signal.org/docs/specifications/doubleratchet/)
 */
open class Protocols(private val context: Context) {

    private val MAC_LEN = 64

    init {
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())
    }

    data class CloseableCurve15519KeyPair(
        var publicKey: ByteArray,
        var privateKey: ByteArray?
    ): AutoCloseable {
        private var isClosed = false

        fun use(block: (CloseableCurve15519KeyPair) -> Unit) {
            if (isClosed) throw IllegalStateException("Cannot use zeroed RatchetState")
            block(this)
        }

        override fun close() {
            if(isClosed) return
            publicKey.fill(0)
            privateKey?.fill(0)
            isClosed = true
        }

    }

    fun generateDH(): CloseableCurve15519KeyPair {
        val generator = X25519KeyPairGenerator()
        generator.init(X25519KeyGenerationParameters(SecureRandom()))

        val keypair = generator.generateKeyPair()
        return try {
            CloseableCurve15519KeyPair(
                publicKey = (keypair.public as X25519PublicKeyParameters).encoded,
                privateKey = (keypair.private as X25519PrivateKeyParameters).encoded,
            )
        } catch(e: Exception) {
            e.printStackTrace()
            (keypair.private as? X25519PrivateKeyParameters)?.encoded?.fill(0)
            throw e
        }
    }

    fun dh(keypair: CloseableCurve15519KeyPair, publicKey: CipherParameters): ByteArray {
        val sharedSecret = ByteArray(32)
        val agreement = X25519Agreement()
        keypair.use { kp ->
            agreement.init(X25519PrivateKeyParameters(kp.privateKey, 0))
            agreement.calculateAgreement(publicKey, sharedSecret, 0)
        }
        return sharedSecret
    }

    fun kdfRk(
        rk: ByteArray,
        dhOut: ByteArray
    ): Triple<ByteArray, ByteArray, ByteArray> {
        val info = context.getString(R.string.dr_rk_info).encodeToByteArray()
        return hkdf(dhOut, rk, info, 32*3).run {
            Triple(
                this.sliceArray(0 until 32),
                this.sliceArray(32 until 64),
                this.sliceArray(64 until 96),
            )
        }
    }

    fun kdfCk(ck: ByteArray?): Pair<ByteArray, ByteArray> {
        if(ck == null) throw Exception("CK came in null! Terminating")

        val mac = hmac(ck)
        val newCk = mac.doFinal(byteArrayOf(0x01))
        val mk = mac.doFinal(byteArrayOf(0x02))
        return Pair(newCk, mk)
    }

    fun encrypt(
        mk: ByteArray,
        plainText: ByteArray,
        ad: ByteArray,
    ): ByteArray {
        val len = 80
        return hkdf(
            ikm = mk,
            salt = ByteArray(len),
            info = context.getString(R.string.dr_encrypt_info).encodeToByteArray(),
            len = len,
        ).run {
            val key = this.sliceArray(0 until 32)
            val authKey = this.sliceArray(32 until 64)
            val iv = this.sliceArray(64 until 80)

            val cipherText = Cryptography.AesGcm.encrypt(
                key = SecretKeySpec(key, "AES"),
                iv = iv,
                plaintext = plainText,
            )
            val mac = hmac(authKey)
            mac.update(ad + cipherText)
            cipherText + mac.doFinal()
        }
    }

    fun hEncrypt(
        mk: ByteArray,
        plainText: ByteArray,
    ): ByteArray {
        val len = 80
        return hkdf(
            ikm = mk,
            salt = ByteArray(len),
            info = context.getString(R.string.dr_encrypt_info).encodeToByteArray(),
            len = len,
        ).run {
            val key = this.sliceArray(0 until 32)
            val authKey = this.sliceArray(32 until 64)
            val iv = this.sliceArray(64 until 80)

            val cipherText = Cryptography.AesGcm.encrypt(
                key = SecretKeySpec(key, "AES"),
                iv = iv,
                plaintext = plainText,
            )

            val mac = hmac(authKey)
            mac.update(cipherText)
            cipherText + mac.doFinal()
        }
    }

    fun decrypt(mk: ByteArray, cipherText: ByteArray, ad: ByteArray): ByteArray {
        val len = 80
        return hkdf(
            ikm = mk,
            salt = ByteArray(len),
            info = context.getString(R.string.dr_encrypt_info).encodeToByteArray(),
            len = len,
        ).run {
            val authKey = this.sliceArray(32 until 64)
            val plaintextCiphertext = cipherText.dropLast(MAC_LEN).toByteArray()

            val mac = hmac(authKey)
            mac.update(ad + plaintextCiphertext)

            val incomingMac = cipherText.takeLast(MAC_LEN).toByteArray()
            if(!incomingMac.contentEquals(mac.doFinal())) {
                throw Exception("Message failed authentication")
            }

            val key = this.sliceArray(0 until 32)
            val iv = this.sliceArray(64 until 80)
            Cryptography.AesGcm.decrypt(
                key = SecretKeySpec(key, "AES"),
                ciphertext = plaintextCiphertext,
                iv = iv,
            )
        }
    }

    fun hDecrypt(mk: ByteArray?, cipherText: ByteArray): ByteArray? {
        val len = 80
        if(mk == null) return null

        return hkdf(
            ikm = mk,
            salt = ByteArray(len),
            info = context.getString(R.string.dr_encrypt_info).encodeToByteArray(),
            len = len,
        ).run {
            val authKey = this.sliceArray(32 until 64)
            val mac = hmac(authKey)

            val plainCiphertext = cipherText.dropLast(MAC_LEN).toByteArray()
            mac.update(plainCiphertext)

            val incomingMac = cipherText.takeLast(MAC_LEN).toByteArray()
            if(!incomingMac.contentEquals(mac.doFinal())) {
                throw Exception("Message failed authentication")
            }

            val key = this.sliceArray(0 until 32)
            val iv = this.sliceArray(64 until 80)
            Cryptography.AesGcm.decrypt(
                key = SecretKeySpec(key, "AES"),
                ciphertext = plainCiphertext,
                iv = iv,
            )
        }
    }

    fun concat(ad: ByteArray, headers: ByteArray): ByteArray {
        return ad + headers
    }
}

