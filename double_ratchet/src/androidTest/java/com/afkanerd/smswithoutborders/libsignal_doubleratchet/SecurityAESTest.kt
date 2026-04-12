package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.content.Context
import androidx.test.espresso.internal.inject.InstrumentationContext
import androidx.test.filters.SmallTest
import androidx.test.platform.app.InstrumentationRegistry
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.generateRandomBytes
import org.junit.Assert.assertArrayEquals
import org.junit.Test

@SmallTest
class SecurityAESTest {
    var context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    @Test
    fun aesTest() {
        val secretKey = SecurityAES.generateSecretKey(256)
        val input = context.generateRandomBytes(277)
        val cipher = SecurityAES.encryptAES256CBC(input, secretKey.encoded, null)
        val output = SecurityAES.decryptAES256CBC(cipher, secretKey.encoded, null)

        assertArrayEquals(input, output)
    }
}