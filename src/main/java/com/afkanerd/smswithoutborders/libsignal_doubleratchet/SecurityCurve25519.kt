package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import com.github.netricecake.ecdh.Curve25519

class SecurityCurve25519 {
   val privateKey: ByteArray = Curve25519.generateRandomKey()

    fun generateKey(): ByteArray {
        return Curve25519.publicKey(this.privateKey)
    }

    fun calculateSharedSecret(publicKey: ByteArray): ByteArray {
        val sharedKey = Curve25519.sharedSecret(this.privateKey, publicKey)
        return CryptoHelpers.HKDF("HMACSHA256", sharedKey, null,
            "x25591_key_exchange".encodeToByteArray(), 32, 1)[0]
    }
}