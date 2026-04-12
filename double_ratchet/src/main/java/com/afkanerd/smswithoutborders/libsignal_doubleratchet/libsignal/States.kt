package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.util.Pair
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.CipherParameters
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey


data class States(
    var RK: ByteArray? = null,
    var CKs: ByteArray? = null,
    var CKr: ByteArray? = null,
    var Ns: UByte = 0u,
    var Nr: UByte = 0u,
    var PN: UByte = 0u,
    var DHRs: AsymmetricCipherKeyPair?,
    var DHRr: CipherParameters? = null,
    var HKs: ByteArray? = null,
    var HKr: ByteArray? = null,
    var NHKs: ByteArray? = null,
    var NHKr: ByteArray? = null,
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