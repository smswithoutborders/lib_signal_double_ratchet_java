package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.dataStore
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.setKeypairValues
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.Serializable
import java.nio.ByteBuffer
import java.nio.ByteOrder

object EncryptionController {

    @Serializable
    enum class SecureRequestMode {
        REQUEST_SENT,
        REQUEST_RECEIVED,
        REQUEST_ACCEPTED,
    }

    @Serializable
    enum class SecureRequestType(val code: Byte) {
        TYPE_REQUEST(0x01),
        TYPE_ACCEPT(0x02);

        companion object {
            fun fromCode(code: Byte): SecureRequestType? =
                entries.find { it.code == code } // Kotlin 1.9+, use values() before that
        }
    }


    suspend fun encrypt() {
        TODO("Implement encrypt")
    }

    suspend fun decrypt() {
        TODO("Implement decrypt")
    }

    suspend fun sendRequest(
        context: Context,
        address: String,
        type: SecureRequestType
    ): ByteArray {
        try {
            val publicKey = generateIdentityPublicKeys(context, address)
            context.setEncryptionState(address, SecureRequestMode.REQUEST_SENT)
            return formatRequestPublicKey(publicKey, type)
        } catch (e: Exception) {
            throw e
        }
    }

    private fun formatRequestPublicKey(
        publicKey: ByteArray,
        type: SecureRequestType
    ) : ByteArray {
        val mn: ByteArray = byteArrayOf(type.code)
        val lenPubKey = ByteArray(4)
        ByteBuffer.wrap(lenPubKey)
            .order(ByteOrder.LITTLE_ENDIAN).putInt(publicKey.size)

        return mn + lenPubKey + publicKey
    }

    suspend fun receiveRequest(context: Context, address: String) {
        try {
            context.setEncryptionState(address, SecureRequestMode.REQUEST_RECEIVED)
        } catch (e: Exception) {
            throw e
        }
    }

    private suspend fun acceptRequest(context: Context, address: String) {
        try {
            context.setEncryptionState(address, SecureRequestMode.REQUEST_ACCEPTED)
        } catch (e: Exception) {
            throw e
        }
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

private suspend fun Context.setEncryptionState(
    address: String,
    state: EncryptionController.SecureRequestMode
) {
    val keyValue = stringPreferencesKey(address)
    dataStore.edit { secureComms->
        secureComms[keyValue] = state.name
    }
}

fun Context.getEncryptedState(address: String): Flow<String?> {
    val keyValue = stringPreferencesKey(address)
    return dataStore.data.map { it[keyValue] }
}
