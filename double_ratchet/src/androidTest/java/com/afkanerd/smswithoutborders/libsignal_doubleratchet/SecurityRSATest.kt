package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityRSA.decrypt
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityRSA.encrypt
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityRSA.generateKeyPair
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.getKeypairFromKeystore
import org.junit.Assert
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyPair
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException
import java.security.UnrecoverableEntryException
import java.security.cert.CertificateException
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException


@RunWith(AndroidJUnit4::class)
class SecurityRSATest {
    var context: Context = InstrumentationRegistry.getInstrumentation().context
    var keystoreAlias: String = "keystoreAlias"

    @Test
    fun testCanStoreAndEncrypt() {
        val publicKey = generateKeyPair(keystoreAlias, 2048)
        val keyPair = context.getKeypairFromKeystore(keystoreAlias)

        val secretKey = SecurityAES.generateSecretKey(256)
        val cipherText = encrypt(keyPair?.public, secretKey.encoded)
        val plainText = decrypt(keyPair?.private, cipherText)
        Assert.assertArrayEquals(secretKey?.encoded, plainText)
    }
}
