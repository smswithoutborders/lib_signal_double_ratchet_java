package com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions

import android.content.Context
import android.util.Base64
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityAES
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityRSA
import com.google.gson.Gson
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.IOException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableEntryException
import java.security.cert.CertificateException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "secure_comms")

/**
 * Pair<PublicKey, PrivateKey>
 */
suspend fun Context.getKeypairValues(address: String): Pair<ByteArray?, ByteArray?> {
    val keyValue = stringSetPreferencesKey(address + "_keypair")
    val keypairSet = dataStore.data.first()[keyValue]
    val encryptionPublicKey = getKeypairFromKeystore(address)

    val publicKey = SecurityRSA.decrypt(
        encryptionPublicKey?.private,
        Base64.decode(keypairSet?.elementAt(0), Base64.DEFAULT)
    )
    val privateKey = SecurityRSA.decrypt(
        encryptionPublicKey?.private,
        Base64.decode(keypairSet?.elementAt(1), Base64.DEFAULT)
    )
    return Pair(publicKey, privateKey)
}

suspend fun Context.setKeypairValues(
    address: String,
    publicKey: ByteArray,
    privateKey: ByteArray,
) {
    val encryptionPublicKey = SecurityRSA.generateKeyPair(address)

    val keyValue = stringSetPreferencesKey(address + "_keypair")
    dataStore.edit { secureComms->
        secureComms[keyValue] = setOf(
            Base64.encodeToString(publicKey.run {
                SecurityRSA.encrypt(encryptionPublicKey, this)
            }, Base64.DEFAULT),
            Base64.encodeToString(privateKey.run {
                SecurityRSA.encrypt(encryptionPublicKey, this)
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

data class SavedBinaryData(
    val key: ByteArray,
    val algorithm: String,
    val data: ByteArray,
)

/**
 *  Would overwrite anything with the same Keystore Alias
 */
@Throws
suspend fun Context.saveBinaryDataEncrypted(
    keystoreAlias: String,
    data: ByteArray,
) : Boolean {
    val keyValue = stringPreferencesKey(keystoreAlias)

    val aesGcmKey = SecurityAES.generateSecretKey(256)
    val data = SecurityAES.encryptAESGCM(data, aesGcmKey)

//    val encryptionPublicKey = getKeypairFromKeystore(keystoreAlias)?.public
//        ?: SecurityRSA.generateKeyPair(keystoreAlias)

    var saved = false
    dataStore.edit { secureComms->
        try {
            val encryptionPublicKey = SecurityRSA.generateKeyPair(keystoreAlias)
            SecurityRSA.encrypt(encryptionPublicKey, aesGcmKey.encoded)?.let { key ->
                secureComms[keyValue] = Gson().toJson(
                    SavedBinaryData(
                        key = key,
                        algorithm = aesGcmKey.algorithm,
                        data = data
                    )
                )
                saved = true
            }
        } catch(e: Exception) {
            throw e
        }
    }
    return saved
}

@Throws
suspend fun Context.getEncryptedBinaryData(keystoreAlias: String): ByteArray? {
    val keyValue = stringPreferencesKey(keystoreAlias)
    val data = dataStore.data.first()[keyValue]
    if(data == null) return null

    val savedBinaryData = Gson().fromJson(data, SavedBinaryData::class.java)

    return try {
        val encryptionPublicKey = getKeypairFromKeystore(keystoreAlias)
        SecurityRSA.decrypt(encryptionPublicKey?.private, savedBinaryData.key)
            ?.run {
                SecurityAES.decryptAESGCM(savedBinaryData.data,
                    SecretKeySpec(this, savedBinaryData.algorithm)
                )
            }
    } catch(e: Exception) {
        throw e
    }
}
