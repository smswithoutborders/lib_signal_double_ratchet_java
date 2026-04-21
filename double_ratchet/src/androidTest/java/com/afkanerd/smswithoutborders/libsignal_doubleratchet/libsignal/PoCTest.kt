package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.content.Context
import androidx.test.filters.SmallTest
import androidx.test.platform.app.InstrumentationRegistry
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Test

@SmallTest
class PoCTest {

    var context: Context =
        InstrumentationRegistry.getInstrumentation().targetContext
    val protocol = Protocols(context)

    @Test
    fun zeroing() {
        val keypair = protocol.generateDH()
        val publicKey = X25519PublicKeyParameters(keypair.publicKey)

        publicKey.encoded.fill(0)
        val expected = ByteArray(32)
        assertArrayEquals(expected, publicKey.encoded)
    }
}