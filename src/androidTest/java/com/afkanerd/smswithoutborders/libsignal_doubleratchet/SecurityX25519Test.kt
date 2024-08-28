package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import androidx.test.filters.SmallTest
import junit.framework.TestCase.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Test

@SmallTest
class SecurityX25519Test {

    @Test
    fun sharedSecret() {
        val alice = SecurityCurve25519()
        val bob = SecurityCurve25519()

        val alicePubKey = alice.generateKey()
        val bobPubKey = bob.generateKey()

        val aliceSharedSecret = alice.calculateSharedSecret(bobPubKey)
        val bobSharedSecret = bob.calculateSharedSecret(alicePubKey)

        assertArrayEquals(aliceSharedSecret, bobSharedSecret)
    }
}