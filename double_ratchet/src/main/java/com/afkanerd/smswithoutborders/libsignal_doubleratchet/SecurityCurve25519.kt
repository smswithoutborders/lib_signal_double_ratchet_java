package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.content.Context
import android.util.Pair
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.EphemeralKeyPair
import org.bouncycastle.math.ec.custom.djb.Curve25519


class SecurityCurve25519(context: Context) : Protocols(context) {

    private fun generateKey(
        ephemeralKeyPair: AsymmetricCipherKeyPair,
        authenticationPublicKey: CipherParameters,
        ephemeralPublicKey: CipherParameters,
        salt: ByteArray,
        info: ByteArray,
        handshakeSalt: ByteArray,
    ) {
        val dh1 = dh(ephemeralKeyPair, authenticationPublicKey)
        val dh2 = dh(ephemeralKeyPair, ephemeralPublicKey)
        return CryptoUtils.hkdf(
            handshakeSalt,
            salt,
            info,
            32,
        ).run {
            CryptoUtils.hkdf(
                dh1,
                this,
                info,
                32,
            ).run {
                CryptoUtils.hkdf(
                    dh2,
                    this,
                    info,
                    32,
                )
            }
        }
    }

    fun agreeWithAuthAndNonce(
        e: AsymmetricCipherKeyPair,
        s: CipherParameters,
        he: CipherParameters,
        hne: CipherParameters,
        salt: ByteArray,
        nonce1: ByteArray,
        nonce2: ByteArray,
        info: ByteArray,
        hInfo: ByteArray,
    ): Triple<ByteArray, ByteArray, ByteArray> {
        val handshakeSalt = nonce1 + nonce2
        val rootKey = generateKey(
            ephemeralKeyPair = ephemeralKeyPair,
            authenticationPublicKey = authenticationPublicKey,
            publicKey = TODO(),
            salt = TODO(),
            info = TODO(),
            handshakeSalt = TODO()
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
    ): ByteArray {
        return Curve25519.sharedSecret(this.privateKey, publicKey)
    }

    fun calculateSharedSecret(
        publicKey: ByteArray,
        salt: ByteArray? = null,
        info: ByteArray? = "x25591_key_exchange".encodeToByteArray(),
    ): ByteArray {
        val sharedKey = Curve25519.sharedSecret(this.privateKey, publicKey)
        return CryptoUtils.hkdf(
            "HMACSHA256",
            sharedKey,
            salt,
            info,
            32,
            1
        )[0]
    }

    fun getKeypair(): Pair<ByteArray, ByteArray> {
        return Pair(privateKey, generateKey())
    }
}