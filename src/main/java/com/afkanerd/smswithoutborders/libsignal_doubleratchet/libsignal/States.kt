package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.util.Pair
import kotlinx.serialization.json.Json

data class States(
    @JvmField
    var DHs: Pair<ByteArray, ByteArray>? = null,

    @JvmField
    var DHr: ByteArray? = null,

    @JvmField
    var RK: ByteArray? = null,

    @JvmField
    var CKs: ByteArray? = null,

    @JvmField
    var CKr: ByteArray? = null,

    @JvmField
    var Ns: Int = 0,

    @JvmField
    var Nr: Int = 0,

    @JvmField
    var PN: Int = 0,

    @JvmField
    var DHRs: Pair<ByteArray, ByteArray>? = null,

    @JvmField
    var DHRr: ByteArray? = null,

    @JvmField
    var HKs: ByteArray? = null,

    @JvmField
    var HKr: ByteArray? = null,

    @JvmField
    var NHKs: ByteArray? = null,

    @JvmField
    var NHKr: ByteArray? = null,

    @JvmField
    var MKSKIPPED: MutableMap<Pair<ByteArray, Int>, ByteArray> = mutableMapOf()
) {
    fun serialize(): String {
        return Json.encodeToString(this)
    }

    companion object {
        fun deserialize(input: String): States {
            return Json.decodeFromString<States>(input)
        }
    }
}