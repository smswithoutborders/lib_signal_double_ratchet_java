package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import com.github.netricecake.ecdh.Curve25519

class SecurityCurve25519(val privateKey: ByteArray = Curve25519.generateRandomKey()) {
    fun generateKey(): ByteArray {
        return Curve25519.publicKey(this.privateKey)
    }

    fun agreeWithAuthAndNonce(
        authenticationPublicKey: ByteArray,
        publicKey: ByteArray,
        salt: ByteArray,
        nonce1: ByteArray,
        nonce2: ByteArray,
        info: ByteArray,
    ): ByteArray {
        val handshakeSalt = nonce1 + nonce2
        val dh1 = Curve25519.sharedSecret(this.privateKey, authenticationPublicKey)
        val dh2 = Curve25519.sharedSecret(this.privateKey, publicKey)
        var ck = CryptoHelpers.HKDF(
            "HMACSHA256",
            handshakeSalt,
            salt,
            info,
            32,
            1
        )[0]
        ck = CryptoHelpers.HKDF(
            "HMACSHA256",
            dh1,
            ck,
            info,
            32,
            1
        )[0]
        return CryptoHelpers.HKDF(
            "HMACSHA256",
            dh2,
            ck,
            info,
            32,
            1
        )[0]
    }

    fun calculateSharedSecret(publicKey: ByteArray): ByteArray {
        val sharedKey = Curve25519.sharedSecret(this.privateKey, publicKey)
        return CryptoHelpers.HKDF("HMACSHA256", sharedKey, null,
            "x25591_key_exchange".encodeToByteArray(), 32, 1)[0]
    }

    fun getKeypair(): android.util.Pair<ByteArray, ByteArray> {
        return android.util.Pair(privateKey, generateKey())
    }
}