package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.content.Context
import android.util.Base64
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.dataStore
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.getKeypairFromKeystore
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.getKeypairValues
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.setKeypairValues
import com.google.gson.Gson
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.Serializable

object EncryptionController {

    @Serializable
    enum class SecureRequestMode {
        REQUEST_NONE,
        REQUEST_REQUESTED,
        REQUEST_RECEIVED,
        REQUEST_ACCEPTED,
    }

    private enum class PublicKeyRequestType(val code: Byte) {
        TYPE_REQUEST(0x01.toByte()),
        TYPE_ACCEPT(0x02.toByte());

        companion object {
            fun fromCode(code: Byte): PublicKeyRequestType? =
                entries.find { it.code == code } // Kotlin 1.9+, use values() before that
        }
    }

    private fun extractRequestPublicKey( publicKey: ByteArray) : ByteArray {
        val lenPubKey = publicKey[1].toInt()
        return publicKey.drop(2).toByteArray()
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    private fun formatRequestPublicKey(
        publicKey: ByteArray,
        type: PublicKeyRequestType
    ) : ByteArray {
        val mn = ubyteArrayOf(type.code.toUByte())
        val lenPubKey = ubyteArrayOf(publicKey.size.toUByte())

        return (mn + lenPubKey).toByteArray() + publicKey
    }

    suspend fun sendRequest(
        context: Context,
        address: String,
        mode: SecureRequestMode,
    ): ByteArray {
        try {
            val publicKey = generateIdentityPublicKeys(context, address)

            var type: PublicKeyRequestType? = null
            val mode = when(mode) {
                SecureRequestMode.REQUEST_RECEIVED -> {
                    type = PublicKeyRequestType.TYPE_ACCEPT
                    SecureRequestMode.REQUEST_ACCEPTED
                }
                else -> {
                    type = PublicKeyRequestType.TYPE_REQUEST
                    SecureRequestMode.REQUEST_REQUESTED
                }
            }

            context.setEncryptionModeStates(address, mode)
            return formatRequestPublicKey(publicKey, type)
        } catch (e: Exception) {
            throw e
        }
    }

    suspend fun receiveRequest(
        context: Context,
        address: String,
        publicKey: ByteArray,
    ) : ByteArray? {
        PublicKeyRequestType.fromCode(publicKey[0])?.let { type ->
            val publicKey = extractRequestPublicKey(publicKey)
            try {
                var sharedKey: ByteArray? = null
                val mode = when(type) {
                    PublicKeyRequestType.TYPE_REQUEST -> {
                        SecureRequestMode.REQUEST_RECEIVED
                    }
                    PublicKeyRequestType.TYPE_ACCEPT -> {
                        sharedKey = context.calculateSharedSecret(address, publicKey)
                        SecureRequestMode.REQUEST_ACCEPTED
                    }
                }
                context.setEncryptionModeStates(
                    address,
                    mode,
                    publicKey,
                    sharedKey
                )
            } catch (e: Exception) {
                throw e
            }
            return publicKey
        }

        return null
    }

    @Throws
    private suspend fun generateIdentityPublicKeys(
        context: Context,
        address: String
    ): ByteArray {
        try {
            val libSigCurve25519 = SecurityCurve25519()
            val publicKey = libSigCurve25519.generateKey()
            context.setKeypairValues(address, publicKey, libSigCurve25519.privateKey)
            return publicKey
        } catch (e: Exception) {
            throw e
        }
    }
}

private suspend fun Context.calculateSharedSecret(
    address: String,
    publicKey: ByteArray
): ByteArray? {
    val keypair = getKeypairValues(address) //public private
    keypair.second?.let { privateKey ->
        val libSigCurve25519 = SecurityCurve25519(privateKey)
        return libSigCurve25519.calculateSharedSecret(publicKey)
    }
    return null
}

data class SavedEncryptedModes(
    var mode: EncryptionController.SecureRequestMode,
    var publicKey: String? = null,
    var sharedKey: String? = null
)

private suspend fun Context.setEncryptionModeStates(
    address: String,
    mode: EncryptionController.SecureRequestMode,
    publicKey: ByteArray? = null,
    sharedKey: ByteArray? = null,
) {
    val keyValue = stringPreferencesKey(address + "_mode_states")
    dataStore.edit { secureComms ->
        // Make a mutable copy of existing state
        val currentState = secureComms[keyValue] ?: ""
        val savedEncryptedModes = if(currentState.isNotEmpty()) Gson()
            .fromJson(currentState, SavedEncryptedModes::class.java)
            .apply { this.mode = mode }
        else SavedEncryptedModes(mode = mode)

        publicKey?.let { publicKey ->
            savedEncryptedModes.publicKey =
                Base64.encodeToString(publicKey, Base64.DEFAULT)
        }
        sharedKey?.let {
            getKeypairFromKeystore(address)?.let { keypair ->
                savedEncryptedModes.sharedKey = Base64.encodeToString(
                    SecurityRSA.encrypt(keypair.public, it),
                    Base64.DEFAULT
                )
            }
        }

        secureComms[keyValue] = Gson().toJson(savedEncryptedModes)
    }
}

fun Context.getEncryptionModeStates(address: String): Flow<String?> {
    val keyValue = stringPreferencesKey(address + "_mode_states")
    return dataStore.data.map { it[keyValue] }
}
