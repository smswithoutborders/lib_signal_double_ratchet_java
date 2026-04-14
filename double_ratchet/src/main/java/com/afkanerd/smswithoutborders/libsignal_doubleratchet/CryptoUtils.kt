package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.content.Context
import at.favre.lib.hkdf.HKDF
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols
import com.google.common.primitives.Bytes
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.EphemeralKeyPair
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

object CryptoUtils {
    fun hkdf(
        ikm: ByteArray,
        salt: ByteArray?,
        info: ByteArray?,
        len: Int,
    ): ByteArray {
        return HKDF.fromHmacSha512()
            .extractAndExpand(
                salt,
                ikm,
                info,
                len
            )
    }

    fun hmac(data: ByteArray?): Mac {
        val algorithm = "HmacSHA512"
        val output = Mac.getInstance(algorithm)
        val key: SecretKey = SecretKeySpec(data, algorithm)
        output.init(key)
        return output
    }

    fun generateKeysNK(
        context: Context,
        ephemeralKeyPair: AsymmetricCipherKeyPair,
        authenticationPublicKey: CipherParameters,
        ephemeralPublicKey: CipherParameters,
        salt: ByteArray,
        info: ByteArray,
    ): Triple<ByteArray, ByteArray, ByteArray> {
        val protocols = Protocols(context)

        val dh1 = protocols.dh(ephemeralKeyPair, authenticationPublicKey)
        val dh2 = protocols.dh(ephemeralKeyPair, ephemeralPublicKey)

        var hkdf1: ByteArray? = null
        var hkdf2: ByteArray? = null

        try {
            hkdf1 = hkdf(ikm = dh1, salt = salt, info = info, len = 32)
            hkdf2 = hkdf(ikm = dh2, salt = hkdf1, info = info, len = 96)

            return Triple(
                hkdf2.sliceArray(0 until 32),
                hkdf2.sliceArray(32 until 64),
                hkdf2.sliceArray(64 until 96),
            )
        } finally {
            dh1.fill(0)
            dh2.fill(0)
            hkdf1?.fill(0)
            hkdf2?.fill(0)
            // The sliceArray copies inside Triple are intentionally not zeroed —
            // they are the return value and owned by the caller
        }
    }
    fun generateKeysNKServer(
        context: Context,
        authenticationKeypair: AsymmetricCipherKeyPair,
        ephemeralKeyPair: AsymmetricCipherKeyPair,
        ephemeralPublicKey: CipherParameters,
        salt: ByteArray,
        info: ByteArray,
    ): Triple<ByteArray, ByteArray, ByteArray> {
        val protocols = Protocols(context)
        val dh1 = protocols.dh(authenticationKeypair, ephemeralPublicKey)
        val dh2 = protocols.dh(ephemeralKeyPair, ephemeralPublicKey)

        var hkdf1: ByteArray? = null
        var hkdf2: ByteArray? = null

        try {
            hkdf1 = hkdf( ikm = dh1, salt = salt, info = info, len = 32, )
            hkdf2 = hkdf( ikm = dh2, salt = hkdf1, info = info, len = 96, )

            return Triple(
                hkdf2.sliceArray(0 until 32),
                hkdf2.sliceArray(32 until 64),
                hkdf2.sliceArray(64 until 96),
            )
        } finally {
            dh1.fill(0)
            dh2.fill(0)
            hkdf1?.fill(0)
            hkdf2?.fill(0)
        }
    }

    data class NoiseIKKey(
        val keys: Triple<ByteArray, ByteArray, ByteArray>,
        val h: ByteArray
    )

    fun generateKeysIK(
        context: Context,
        ephemeralKeyPair: AsymmetricCipherKeyPair,
        authenticationPublicKey: CipherParameters,
        staticKeyPair: AsymmetricCipherKeyPair,
        info: ByteArray,
        headerInfo: ByteArray,
    ) : NoiseIKKey {
        val protocols = Protocols(context)

        var h = "Noise_IK_25519_AESGCM_SHA256".encodeToByteArray().sha256()
        var ck = h

        h = (h + (authenticationPublicKey as X25519PublicKeyParameters).encoded).sha256()
        h = (h + (ephemeralKeyPair.public as X25519PublicKeyParameters).encoded).sha256()

        val dhEs = protocols.dh(ephemeralKeyPair, authenticationPublicKey)
        val dhSs = protocols.dh(staticKeyPair, authenticationPublicKey)

        // Named references so we can zero them
        var hkdf1: ByteArray? = null
        var hkdf2: ByteArray? = null
        var hkdf3: ByteArray? = null
        var k: ByteArray? = null
        var csPkEnc: ByteArray? = null
        var ciphertext: ByteArray? = null

        try {
            hkdf1 = hkdf(ikm = dhEs, salt = ck, info = info, len = 2)
            ck = hkdf1.sliceArray(0 until 32)
            k = hkdf1.sliceArray(32 until 64)

            csPkEnc = Cryptography.AesGcm.encrypt(
                SecretKeySpec(k, "AES"),
                (staticKeyPair.public as X25519PublicKeyParameters).encoded,
                h
            )
            h = (h + csPkEnc).sha256()

            hkdf2 = hkdf(ikm = dhSs, salt = ck, info = info, len = 2)
            ck = hkdf2.sliceArray(0 until 32)
            k.fill(0) // zero previous k before reassigning
            k = hkdf2.sliceArray(32 until 64)

            ciphertext = Cryptography.AesGcm.encrypt(
                SecretKeySpec(k, "AES"),
                "".encodeToByteArray(),
                h
            )
            h = (h + ciphertext).sha256()

            hkdf3 = hkdf(ikm = dhSs, salt = ck, info = headerInfo, len = 3)

            return NoiseIKKey(
                Triple(
                    hkdf3.sliceArray(0 until 32),
                    hkdf3.sliceArray(32 until 64),
                    hkdf3.sliceArray(64 until 96),
                ),
                h
            )
        } finally {
            // Zero everything sensitive regardless of success or exception
            dhEs.fill(0)
            dhSs.fill(0)
            ck.fill(0)
            k?.fill(0)
            hkdf1?.fill(0)
            hkdf2?.fill(0)
            hkdf3?.fill(0)
            // csPkEnc and ciphertext are non-secret ciphertext, but zero anyway
            csPkEnc?.fill(0)
            ciphertext?.fill(0)
        }
    }

    fun generateKeysIKForwardSecrecy(
        context: Context,
        h: ByteArray,
        ck: ByteArray,
        ephemeralKeyPair: AsymmetricCipherKeyPair,
        ephemeralResponderPublicKey: CipherParameters,
        authenticationPublicKey: CipherParameters,
        info: ByteArray,
        headerInfo: ByteArray,
    ) : NoiseIKKey {
        val protocols = Protocols(context)

        // Shadowed vars — use local mutable copies so we can zero them
        // Note: the incoming h and ck are owned by the caller; don't zero them here
        var localH = (h + (ephemeralResponderPublicKey as X25519PublicKeyParameters).encoded).sha256()
        var localCk = ck.copyOf() // defensive copy — we'll mutate and zero this

        val dhEe = protocols.dh(ephemeralKeyPair, ephemeralResponderPublicKey)
        val dhSe = protocols.dh(ephemeralKeyPair, authenticationPublicKey)

        var hkdf1: ByteArray? = null
        var hkdf2: ByteArray? = null
        var hkdf3: ByteArray? = null
        var k: ByteArray? = null
        var ciphertext1: ByteArray? = null
        var ciphertext2: ByteArray? = null

        try {
            hkdf1 = hkdf(ikm = dhEe, salt = localCk, info = info, len = 2)
            localCk.fill(0)
            localCk = hkdf1.sliceArray(0 until 32)
            k = hkdf1.sliceArray(32 until 64)

            ciphertext1 = Cryptography.AesGcm.encrypt(
                SecretKeySpec(k, "AES"),
                "".encodeToByteArray(),
                localH
            )
            localH = (localH + ciphertext1).sha256()

            hkdf2 = hkdf(ikm = dhSe, salt = localCk, info = info, len = 2)
            localCk.fill(0)
            localCk = hkdf2.sliceArray(0 until 32)
            k.fill(0) // zero previous k before reassign
            k = hkdf2.sliceArray(32 until 64)

            ciphertext2 = Cryptography.AesGcm.encrypt(
                SecretKeySpec(k, "AES"),
                "".encodeToByteArray(),
                localH
            )
            localH = (localH + ciphertext2).sha256()

            hkdf3 = hkdf(
                ikm = "".encodeToByteArray(),
                salt = localCk,
                info = headerInfo,
                len = 3
            )

            return NoiseIKKey(
                Triple(
                    hkdf3.sliceArray(0 until 32),
                    hkdf3.sliceArray(32 until 64),
                    hkdf3.sliceArray(64 until 96),
                ),
                localH
            )
        } finally {
            dhEe.fill(0)
            dhSe.fill(0)
            localCk.fill(0)
            k?.fill(0)
            hkdf1?.fill(0)
            hkdf2?.fill(0)
            hkdf3?.fill(0)
            ciphertext1?.fill(0)
            ciphertext2?.fill(0)
            // Do NOT zero localH — it's returned inside NoiseIKKey
            // Do NOT zero the caller's h and ck — we don't own them
        }
    }
    fun ByteArray.sha256(): ByteArray {
        return MessageDigest
            .getInstance("SHA-256")
            .digest(this)
    }



}
