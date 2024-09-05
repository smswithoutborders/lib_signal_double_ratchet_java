package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import androidx.test.filters.SmallTest
import junit.framework.TestCase.assertEquals
import org.junit.Test
import java.security.SecureRandom

@SmallTest
class StateTest {

    @Test fun testStates() {
        val state = States()
        state.DHs = android.util.Pair(SecureRandom.getSeed(32),
            SecureRandom.getSeed(32))
        val serializedStates = state.serializedStates
        println("Encoded values: $serializedStates")
        val state1 = States(serializedStates)
        println(state1.serializedStates)

        assertEquals(state, state1)
    }
}