package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import androidx.test.filters.SmallTest
import junit.framework.TestCase.assertEquals
import kotlinx.serialization.json.Json
import org.junit.Test
import java.security.SecureRandom

@SmallTest
class StateTest {

    @Test fun testStates() {
        val state = States()
        state.DHs = android.util.Pair(SecureRandom.getSeed(32),
            SecureRandom.getSeed(32))
        val serializedStates = Json.encodeToString(state)
        val deserializedStates = Json.decodeFromString<States>(serializedStates)
        assertEquals(state, deserializedStates)
    }
}