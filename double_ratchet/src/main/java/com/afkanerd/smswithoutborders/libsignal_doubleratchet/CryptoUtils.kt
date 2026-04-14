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

    fun ByteArray.sha256(): ByteArray {
        return MessageDigest
            .getInstance("SHA-256")
            .digest(this)
    }



}
