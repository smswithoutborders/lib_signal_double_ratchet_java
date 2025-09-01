package com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions

import android.content.Context
import android.util.Base64
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityRSA
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import java.io.IOException
import java.security.KeyPair
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableEntryException
import java.security.cert.CertificateException

val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "secure_comms")

fun Context.getKeypairValues(address: String): Flow<Set<String>?> {
    val keyValue = stringSetPreferencesKey(address)
    return dataStore.data.map { it[keyValue] }
}

suspend fun Context.setKeypairValues(
    address: String,
    publicKey: ByteArray,
    privateKey: ByteArray,
) {
    val encryptionPublicKey = SecurityRSA.generateKeyPair(address)

    val keyValue = stringSetPreferencesKey(address)
    dataStore.edit { secureComms->
        secureComms[keyValue] = setOf(
            Base64.encodeToString(publicKey.run {
                SecurityRSA.encrypt(encryptionPublicKey, publicKey)
            }, Base64.DEFAULT),
            Base64.encodeToString(privateKey.run {
                SecurityRSA.encrypt(encryptionPublicKey, privateKey)
            }, Base64.DEFAULT),
        )
    }
}

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
