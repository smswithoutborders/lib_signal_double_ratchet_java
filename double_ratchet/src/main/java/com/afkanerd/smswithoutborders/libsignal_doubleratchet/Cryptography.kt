package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.content.Context
import androidx.datastore.core.Closeable
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoUtils.hkdf
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoUtils.sha256
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

object Cryptography {

    data class NoiseNKKeys(
        val rk: ByteArray,
        val hk: ByteArray,
        val nhk: ByteArray,
    ): Closeable {
        private var zeroed = false

        override fun close() {
            if(!zeroed) {
                rk.fill(0)
                hk.fill(0)
                nhk.fill(0)
                zeroed = true
            }
        }

        inline fun <T> use(block: (NoiseNKKeys) -> T): T {
            try {
                return block(this)
            } finally {
                close()
            }
        }

        // Prevent accidental logging/serialization of key material
        override fun toString() = "NoiseNKKeys([REDACTED])"
    }

    fun generateKeysNK(
        context: Context,
        ephemeralKeyPair: Protocols.CloseableCurve15519KeyPair,
        authenticationPublicKey: ByteArray,
        ephemeralPublicKey: ByteArray,
        salt: ByteArray,
        info: ByteArray,
    ): NoiseNKKeys {
        val protocols = Protocols(context)

        val dh1 = protocols.dh(ephemeralKeyPair, authenticationPublicKey)
        val dh2 = protocols.dh(ephemeralKeyPair, ephemeralPublicKey)

        var hkdf1: ByteArray? = null
        var hkdf2: ByteArray? = null

        try {
            hkdf1 = hkdf(ikm = dh1, salt = salt, info = info, len = 32)
            hkdf2 = hkdf(ikm = dh2, salt = hkdf1, info = info, len = 96)

            return NoiseNKKeys(
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
        authenticationKeypair: Protocols.CloseableCurve15519KeyPair,
        ephemeralKeyPair: Protocols.CloseableCurve15519KeyPair,
        ephemeralPublicKey: ByteArray,
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

    data class NoiseIKKeys(
        val rk: ByteArray,
        val hk: ByteArray,
        val nhk: ByteArray,
        val ck: ByteArray? = null,
        val h: ByteArray? = null,
    ): Closeable {
        private var zeroed = false

        override fun close() {
            if(!zeroed) {
                rk.fill(0)
                hk.fill(0)
                nhk.fill(0)
                ck?.fill(0)
                h?.fill(0)
                zeroed = true
            }
        }

        inline fun <T> use(block: (NoiseIKKeys) -> T): T {
            try {
                return block(this)
            } finally {
                close()
            }
        }

        // Prevent accidental logging/serialization of key material
        override fun toString() = "NoiseIKKeys([REDACTED])"
    }

    fun generateKeysIK(
        context: Context,
        ephemeralKeyPair: Protocols.CloseableCurve15519KeyPair,
        authenticationPublicKey: ByteArray,
        staticKeyPair: Protocols.CloseableCurve15519KeyPair,
        info: ByteArray,
        headerInfo: ByteArray,
    ) : NoiseIKKeys {
        val protocols = Protocols(context)

        var h = "Noise_IK_25519_AESGCM_SHA256".encodeToByteArray().sha256()
        var ck = h

        h = (h + (authenticationPublicKey as X25519PublicKeyParameters).encoded).sha256()
        h = (h + ephemeralKeyPair.publicKey).sha256()

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

            csPkEnc = AesGcm.encrypt(
                SecretKeySpec(k, "AES"),
                staticKeyPair.publicKey,
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

            return NoiseIKKeys(
                hkdf3.sliceArray(0 until 32),
                hkdf3.sliceArray(32 until 64),
                hkdf3.sliceArray(64 until 96),
                ck,
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
        ephemeralKeyPair: Protocols.CloseableCurve15519KeyPair,
        ephemeralResponderPublicKey: ByteArray,
        authenticationPublicKey: ByteArray,
        info: ByteArray,
        headerInfo: ByteArray,
    ) : NoiseIKKeys {
        val protocols = Protocols(context)

        // Shadowed vars — use local mutable copies so we can zero them
        // Note: the incoming h and ck are owned by the caller; don't zero them here
        var localH = h + ephemeralResponderPublicKey.sha256()
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

            ciphertext1 = AesGcm.encrypt(
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

            ciphertext2 = AesGcm.encrypt(
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

            return NoiseIKKeys(
                hkdf3.sliceArray(0 until 32),
                hkdf3.sliceArray(32 until 64),
                hkdf3.sliceArray(64 until 96),
                h = localH
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

    object AesGcm {
        private const val ALGORITHM = "AES/GCM/NoPadding"
        private const val KEY_SIZE_BITS = 256
        private const val IV_SIZE_BYTES = 12   // 96-bit IV recommended for GCM
        private const val TAG_SIZE_BITS = 128  // authentication tag length

        data class CipherResult(
            val ciphertext: ByteArray,  // encrypted data (includes appended GCM auth tag)
            val iv: ByteArray           // IV — must be stored alongside ciphertext for decryption
        )


        /**
         * Encrypts [plaintext] with AES-256-GCM.
         *
         * @param key           AES secret key (128, 192, or 256-bit)
         * @param plaintext     Data to encrypt
         * @param associatedData  AAD: authenticated but NOT encrypted (e.g. headers, context).
         *                        Pass null if not needed.
         * @return CipherResult containing the ciphertext+tag and the IV used.
         */
        fun encrypt(
            key: SecretKey,
            plaintext: ByteArray,
            iv: ByteArray? = null,
            associatedData: ByteArray? = null
        ): ByteArray {
            val iv1 = iv ?: ByteArray(IV_SIZE_BYTES).also { SecureRandom().nextBytes(it) }
            val spec = GCMParameterSpec(TAG_SIZE_BITS, iv1)

            val cipher = Cipher.getInstance(ALGORITHM)
            cipher.init(Cipher.ENCRYPT_MODE, key, spec)
            associatedData?.let { cipher.updateAAD(it) }

            val ciphertext = cipher.doFinal(plaintext)
            return if(iv != null) ciphertext else iv1 + ciphertext
        }

        /**
         * Decrypts and authenticates output from [encrypt].
         * Throws [javax.crypto.AEADBadTagException] if the tag or AAD doesn't match.
         *
         * @param key           Same AES key used during encryption
         * @param ciphertext    Encrypted bytes (ciphertext + appended GCM tag)
         * @param iv            IV from the corresponding [CipherResult]
         * @param associatedData  Must be identical to the AAD used during encryption
         */
        fun decrypt(
            key: SecretKey,
            ciphertext: ByteArray,
            iv: ByteArray,
            associatedData: ByteArray? = null
        ): ByteArray {
            val spec = GCMParameterSpec(TAG_SIZE_BITS, iv)

            val cipher = Cipher.getInstance(ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            associatedData?.let { cipher.updateAAD(it) }

            return cipher.doFinal(ciphertext)
        }
    }
}