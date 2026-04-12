package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.content.Context
import at.favre.lib.hkdf.HKDF
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols
import com.google.common.primitives.Bytes
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.CipherParameters
import java.security.GeneralSecurityException
import java.security.MessageDigest
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

    fun ByteArray.sha256(): ByteArray {
        return MessageDigest
            .getInstance("SHA-256")
            .digest(this)
    }



}
