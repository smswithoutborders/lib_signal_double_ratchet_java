package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import com.github.netricecake.ecdh.Curve25519

class SecurityCurve25519(val privateKey: ByteArray = Curve25519.generateRandomKey()) {
    fun generateKey(): ByteArray {
        return Curve25519.publicKey(this.privateKey)
    }

    private fun agreeWithAuthAndNonceImpl(
        authenticationPublicKey: ByteArray?,
        authenticationPrivateKey: ByteArray?,
        publicKey: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        handshakeSalt: ByteArray,
        privateKey: ByteArray? = null,
    ): ByteArray {
        val privateKey = privateKey ?: this.privateKey
        val dh1 = if(authenticationPrivateKey == null)
            Curve25519.sharedSecret(privateKey, authenticationPublicKey)
        else
            Curve25519.sharedSecret(authenticationPrivateKey, publicKey)
        val dh2 = Curve25519.sharedSecret(privateKey, publicKey)
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

    fun agreeWithAuthAndNonce(
        authenticationPublicKey: ByteArray?,
        authenticationPrivateKey: ByteArray?,
        headerPrivateKey: ByteArray,
        nextHeaderPrivateKey: ByteArray,
        publicKey: ByteArray,
        headerPublicKey: ByteArray,
        nextHeaderPublicKey: ByteArray,
        salt: ByteArray,
        nonce1: ByteArray,
        nonce2: ByteArray,
        info: ByteArray,
    ): Triple<ByteArray, ByteArray, ByteArray> {
        val handshakeSalt = nonce1 + nonce2
        val headerInfo = "RelaySMS C2S DRHE v1".encodeToByteArray()

        val rootKey = agreeWithAuthAndNonceImpl(
            authenticationPublicKey = authenticationPublicKey,
            authenticationPrivateKey = authenticationPrivateKey,
            publicKey = publicKey,
            salt = salt,
            info = info,
            handshakeSalt = handshakeSalt,
        )

        val headerKey = agreeWithAuthAndNonceImpl(
            authenticationPublicKey = authenticationPublicKey,
            authenticationPrivateKey = authenticationPrivateKey,
            publicKey = headerPublicKey,
            salt = salt,
            info = headerInfo,
            handshakeSalt = handshakeSalt,
            privateKey = headerPrivateKey
        )

        val nextHeaderKey = agreeWithAuthAndNonceImpl(
            authenticationPublicKey = authenticationPublicKey,
            authenticationPrivateKey = authenticationPrivateKey,
            publicKey = nextHeaderPublicKey,
            salt = salt,
            info = headerInfo,
            handshakeSalt = handshakeSalt,
            privateKey = nextHeaderPrivateKey
        )

        return Triple(rootKey, headerKey, nextHeaderKey)
    }

    fun calculateSharedSecret(
        publicKey: ByteArray,
        salt: ByteArray? = null,
        info: ByteArray? = "x25591_key_exchange".encodeToByteArray(),
    ): ByteArray {
        val sharedKey = Curve25519.sharedSecret(this.privateKey, publicKey)
        return CryptoHelpers.HKDF(
            "HMACSHA256",
            sharedKey,
            salt,
            info,
            32,
            1
        )[0]
    }

    fun getKeypair(): android.util.Pair<ByteArray, ByteArray> {
        return android.util.Pair(privateKey, generateKey())
    }
}