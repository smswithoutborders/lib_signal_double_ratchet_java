package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import at.favre.lib.hkdf.HKDF
import com.google.common.primitives.Bytes
import java.security.GeneralSecurityException
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

}
