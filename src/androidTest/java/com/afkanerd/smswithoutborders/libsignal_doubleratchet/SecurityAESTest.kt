package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import androidx.test.filters.SmallTest
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import javax.crypto.SecretKey

@SmallTest
class SecurityAESTest {

    @Test
    fun aesTest() {
        val secretKey = SecurityAES.generateSecretKey(256)

        val input = CryptoHelpers.generateRandomBytes(277)
        val cipher = SecurityAES.encryptAES256CBC(input, secretKey.encoded, null)
        val output = SecurityAES.decryptAES256CBC(cipher, secretKey.encoded)

        assertArrayEquals(input, output)
    }
}