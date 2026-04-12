package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import com.google.common.primitives.Bytes
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPair

class Headers(var dh: AsymmetricCipherKeyPair, pn: UByte, n: UByte) {
    var pn: UByte = 0u
    var n: UByte = 0u

    init {
        this.pn = pn
        this.n = n
    }

    val serialized: ByteArray
        get() {
            val pk = dh.public as X25519PublicKeyParameters
            return byteArrayOf(pn.toByte()) + byteArrayOf(n.toByte()) + pk.encoded
        }

    companion object {
        fun deserialize(header: ByteArray): Headers {
            val pn = header[0].toUByte()
            val n = header[1].toUByte()
            val pk = header.sliceArray(2 until header.size)
            return Headers(
                AsymmetricCipherKeyPair(
                    X25519PublicKeyParameters(pk, 0),
                    null
                ), pn, n)
        }
    }
}
