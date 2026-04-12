package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.util.Pair
import androidx.test.filters.SmallTest
import junit.framework.TestCase.assertEquals
import kotlinx.serialization.json.Json
import org.junit.Test
import java.security.SecureRandom

@SmallTest
class StateTest {

    @Test fun testStates() {
        val state = States()
        val serializedStates = Json.encodeToString(state)
        val deserializedStates = Json.decodeFromString<States>(serializedStates)
        assertEquals(state, deserializedStates)
    }
}