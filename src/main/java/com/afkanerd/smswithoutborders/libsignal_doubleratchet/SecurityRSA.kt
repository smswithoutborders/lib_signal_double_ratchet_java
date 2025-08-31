package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

object SecurityRSA {
    var defaultEncryptionDigest: MGF1ParameterSpec? = MGF1ParameterSpec.SHA256
    var defaultDecryptionDigest: MGF1ParameterSpec? = MGF1ParameterSpec.SHA1

    var encryptionDigestParam: OAEPParameterSpec = OAEPParameterSpec(
        "SHA-256", "MGF1", defaultEncryptionDigest,
        PSource.PSpecified.DEFAULT
    )
    var decryptionDigestParam: OAEPParameterSpec = OAEPParameterSpec(
        "SHA-256", "MGF1", defaultDecryptionDigest,
        PSource.PSpecified.DEFAULT
    )

    @JvmStatic
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidAlgorithmParameterException::class
    )
    fun generateKeyPair(keystoreAlias: String, keySize: Int = 2048): PublicKey? {
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
        )
        kpg.initialize(
            KeyGenParameterSpec.Builder(
                keystoreAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(keySize)
                .setDigests(
                    KeyProperties.DIGEST_SHA1, KeyProperties.DIGEST_SHA256,
                    KeyProperties.DIGEST_SHA512
                )
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .build()
        )
        return kpg.generateKeyPair().public
    }

    @JvmStatic
    @Throws(
        NoSuchPaddingException::class,
        NoSuchAlgorithmException::class,
        IllegalBlockSizeException::class,
        BadPaddingException::class,
        InvalidKeyException::class,
        InvalidAlgorithmParameterException::class
    )
    fun decrypt(privateKey: PrivateKey?, data: ByteArray?): ByteArray? {
        val cipher = Cipher.getInstance("RSA/ECB/" + KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        //        cipher.init(Cipher.DECRYPT_MODE, privateKey, decryptionDigestParam);
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(data)
    }

    @JvmStatic
    @Throws(
        NoSuchPaddingException::class,
        NoSuchAlgorithmException::class,
        IllegalBlockSizeException::class,
        BadPaddingException::class,
        InvalidKeyException::class,
        InvalidAlgorithmParameterException::class
    )
    fun encrypt(publicKey: PublicKey?, data: ByteArray?): ByteArray? {
        val cipher = Cipher.getInstance("RSA/ECB/" + KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        //        cipher.init(Cipher.ENCRYPT_MODE, publicKey, encryptionDigestParam);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(data)
    }
}
