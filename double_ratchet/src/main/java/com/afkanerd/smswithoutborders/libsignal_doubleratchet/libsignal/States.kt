package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.R.id.input
import android.util.Pair
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.encodeToStream
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.io.ByteArrayOutputStream
import java.lang.AutoCloseable
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
    var DHRs: Protocols.CloseableCurve15519KeyPair? = null,
    var DHRr: ByteArray? = null,
    var HKs: ByteArray? = null,
    var HKr: ByteArray? = null,
    var NHKs: ByteArray? = null,
    var NHKr: ByteArray? = null,
    var MKSKIPPED: MutableMap<Pair<ByteArray, Int>, ByteArray> = mutableMapOf()
) : AutoCloseable {
    @OptIn(ExperimentalSerializationApi::class)
    fun serialize(): ByteArray {
        val outputBuffer = ByteArrayOutputStream()
        Json.encodeToStream(this, outputBuffer)
        return outputBuffer.toByteArray()
    }

    private var isClosed = false
    override fun close() {
        if(isClosed) return
        RK?.let { it.fill(0); RK = null }
        CKs?.let { it.fill(0); CKs = null }
        CKr?.let { it.fill(0); CKr = null }
        HKs?.let { it.fill(0); HKs = null }
        HKr?.let { it.fill(0); HKr = null }
        NHKs?.let { it.fill(0); NHKs = null }
        NHKr?.let { it.fill(0); NHKr = null }

        DHRr?.let { it.fill(0); DHRr = null }

        val iterator = MKSKIPPED.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            entry.key.first.fill(0)
            entry.value.fill(0)
            iterator.remove()
        }
        MKSKIPPED.clear()

        Ns = 0u
        Nr = 0u
        PN = 0u
        isClosed = true
    }

    companion object {
        @OptIn(ExperimentalSerializationApi::class)
        fun deserialize(data: ByteArray): States {
            return Json.decodeFromStream<States>(data.inputStream())
        }
    }
}