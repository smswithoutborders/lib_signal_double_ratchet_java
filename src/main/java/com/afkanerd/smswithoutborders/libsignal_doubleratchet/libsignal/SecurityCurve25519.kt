package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.curve25519.Curve25519KeyPair


class SecurityCurve25519 {
    private val cipher: Curve25519 = Curve25519.getInstance(Curve25519.BEST)

    fun generateKey(): Curve25519KeyPair {
        return cipher.generateKeyPair()
    }

    fun calculateSharedSecret(keyPair: Curve25519KeyPair): ByteArray {
        return cipher.calculateAgreement(keyPair.publicKey, keyPair.privateKey)
    }
}