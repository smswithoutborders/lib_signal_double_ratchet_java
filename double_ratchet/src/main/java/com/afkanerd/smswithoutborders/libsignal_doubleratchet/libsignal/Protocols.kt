package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.content.Context
import android.util.Pair
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoUtils
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoUtils.hkdf
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoUtils.hmac
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.R
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityAES
import com.google.common.primitives.Bytes
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.SecureRandom
import java.security.Security

/**
 * This implementations are based on the signal protocols specifications.
 * 
 * This are based on the recommended algorithms and parameters for the encryption
 * and decryption.
 * 
 * The goal for this would be to transform it into library which can be used across
 * other SMS projects.
 * 
 * [...](https://signal.org/docs/specifications/doubleratchet/)
 */
open class Protocols(private val context: Context) {

    init {
        Security.removeProvider("BC")
        Security.addProvider(BouncyCastleProvider())
    }

    fun generateDH(): AsymmetricCipherKeyPair {
        val generator = X25519KeyPairGenerator()
        generator.init(X25519KeyGenerationParameters(SecureRandom()))
        return generator.generateKeyPair()
    }

    fun dh(keypair: AsymmetricCipherKeyPair, publicKey: CipherParameters): ByteArray {
        val sharedSecret = ByteArray(32)
        val agreement = X25519Agreement()
        agreement.init(keypair.private)
        agreement.calculateAgreement(publicKey, sharedSecret, 0)
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

            val cipherText = SecurityAES.encryptAES256CBC(plainText, key, iv)
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

            val cipherText = SecurityAES.encryptAES256CBC(plainText, key, iv)

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
            val cipherText = cipherText.dropLast(32).toByteArray()

            val mac = hmac(authKey)
            mac.update(ad + cipherText)

            val incomingMac = cipherText.takeLast(32).toByteArray()
            if(!incomingMac.contentEquals(mac.doFinal())) {
                throw Exception("Message failed authentication")
            }

            val key = this.sliceArray(0 until 32)
            val iv = this.sliceArray(64 until 80)
            SecurityAES.decryptAES256CBC(cipherText, key, iv)
        }
    }

    fun hDecrypt(mk: ByteArray, cipherText: ByteArray): ByteArray {
        val len = 80
        return hkdf(
            ikm = mk,
            salt = ByteArray(len),
            info = context.getString(R.string.dr_encrypt_info).encodeToByteArray(),
            len = len,
        ).run {
            val authKey = this.sliceArray(32 until 64)
            val cipherText = cipherText.dropLast(32).toByteArray()

            val mac = hmac(authKey)
            mac.update(cipherText)

            val incomingMac = cipherText.takeLast(32).toByteArray()
            if(!incomingMac.contentEquals(mac.doFinal())) {
                throw Exception("Message failed authentication")
            }

            val key = this.sliceArray(0 until 32)
            val iv = this.sliceArray(64 until 80)
            SecurityAES.decryptAES256CBC(cipherText, key, iv)
        }
    }

    fun concat(ad: ByteArray, headers: ByteArray): ByteArray {
        return ad + headers
    }
}

