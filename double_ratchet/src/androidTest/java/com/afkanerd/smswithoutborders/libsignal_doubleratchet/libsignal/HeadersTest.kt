package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import androidx.test.filters.SmallTest
import junit.framework.TestCase.assertEquals
import org.junit.Test
import java.security.SecureRandom

@SmallTest
class HeadersTest {

    @Test fun headersTest() {
        val header = Headers(SecureRandom.getSeed(32), 0, 0)
        val header1 = Headers.deSerializeHeader(header.serialized)

        assertEquals(header, header1)
    }
}