package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom

object Cryptography {

    object AesGcm {
        private const val ALGORITHM = "AES/GCM/NoPadding"
        private const val KEY_SIZE_BITS = 256
        private const val IV_SIZE_BYTES = 12   // 96-bit IV recommended for GCM
        private const val TAG_SIZE_BITS = 128  // authentication tag length

        data class CipherResult(
            val ciphertext: ByteArray,  // encrypted data (includes appended GCM auth tag)
            val iv: ByteArray           // IV — must be stored alongside ciphertext for decryption
        )

        fun generateKey(): SecretKey {
            val keygen = KeyGenerator.getInstance("AES")
            keygen.init(KEY_SIZE_BITS, SecureRandom())
            return keygen.generateKey()
        }

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
            associatedData: ByteArray? = null
        ): ByteArray {
            val iv = ByteArray(IV_SIZE_BYTES).also { SecureRandom().nextBytes(it) }
            val spec = GCMParameterSpec(TAG_SIZE_BITS, iv)

            val cipher = Cipher.getInstance(ALGORITHM)
            cipher.init(Cipher.ENCRYPT_MODE, key, spec)
            associatedData?.let { cipher.updateAAD(it) }

            val ciphertext = cipher.doFinal(plaintext)
            return iv + ciphertext
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