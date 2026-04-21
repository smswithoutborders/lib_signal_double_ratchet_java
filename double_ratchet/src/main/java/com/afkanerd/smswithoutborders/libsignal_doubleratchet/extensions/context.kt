package com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions

import android.content.Context
import android.util.Base64
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.google.gson.Gson
import kotlinx.coroutines.flow.first
import java.io.IOException
import java.security.KeyPair
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.UnrecoverableEntryException
import java.security.cert.CertificateException
import javax.crypto.spec.SecretKeySpec

val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "secure_comms")

@Throws(
    KeyStoreException::class,
    CertificateException::class,
    IOException::class,
    NoSuchAlgorithmException::class,
    UnrecoverableEntryException::class
)
fun Context.getKeypairFromKeystore(keystoreAlias: String): KeyPair? {
    val keyStore = KeyStore.getInstance("AndroidKeyStore")
    keyStore.load(null)

    val entry = keyStore.getEntry(keystoreAlias, null)
    if (entry is KeyStore.PrivateKeyEntry) {
        val privateKey = entry.privateKey
        val publicKey = keyStore.getCertificate(keystoreAlias).publicKey
        return KeyPair(publicKey, privateKey)
    }
    return null
}

data class SavedBinaryData(
    val key: ByteArray,
    val algorithm: String,
    val data: ByteArray,
)

/**
 *  Would overwrite anything with the same Keystore Alias
 */

fun Context.generateRandomBytes(length: Int): ByteArray {
    val random = SecureRandom()
    val bytes = ByteArray(length)
    random.nextBytes(bytes)
    return bytes
}

