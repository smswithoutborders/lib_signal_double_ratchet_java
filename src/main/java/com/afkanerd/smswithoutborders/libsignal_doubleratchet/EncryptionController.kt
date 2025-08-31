package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.dataStore
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.setKeypairValues
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.serialization.Serializable

object EncryptionController {

    @Serializable
    enum class EncryptionMode {
        REQUEST_SENT,
        REQUEST_RECEIVED,
        REQUEST_ACCEPTED,
    }

    suspend fun sendRequest(context: Context, address: String): ByteArray {
        try {
            val publicKey = generateIdentityPublicKeys(context, address)
            context.setEncryptionState(address, EncryptionMode.REQUEST_SENT)
            return publicKey
        } catch (e: Exception) {
            throw e
        }
    }

    suspend fun receiveRequest(context: Context, address: String) {
        try {
            context.setEncryptionState(address, EncryptionMode.REQUEST_RECEIVED)
        } catch (e: Exception) {
            throw e
        }
    }

    private suspend fun acceptRequest(context: Context, address: String) {
        try {
            context.setEncryptionState(address, EncryptionMode.REQUEST_ACCEPTED)
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
    state: EncryptionController.EncryptionMode
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
