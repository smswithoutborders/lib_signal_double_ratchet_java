package com.afkanerd.smswithoutborders.libsignal_doubleratchet

import android.content.Context
import android.util.Base64
import android.widget.Toast
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.dataStore
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.getEncryptedBinaryData
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.getKeypairValues
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.saveBinaryDataEncrypted
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.extensions.setKeypairValues
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Headers
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Ratchets
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.States
import com.google.gson.Gson
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable

object EncryptionController {

    @Serializable
    enum class SecureRequestMode {
        REQUEST_NONE,
        REQUEST_REQUESTED,
        REQUEST_RECEIVED,
        REQUEST_ACCEPTED,
    }

    private enum class MessageRequestType(val code: Byte) {
        TYPE_REQUEST(0x01.toByte()),
        TYPE_ACCEPT(0x02.toByte()),
        TYPE_MESSAGE(0x03.toByte());

        companion object {
            fun fromCode(code: Byte): MessageRequestType? =
                entries.find { it.code == code } // Kotlin 1.9+, use values() before that
        }
    }

    private fun extractRequestPublicKey( publicKey: ByteArray) : ByteArray {
        val lenPubKey = publicKey[1].toInt()
        return publicKey.drop(2).toByteArray()
    }

    private fun extractMessage(data: ByteArray) : Pair<Headers, ByteArray> {
        val lenHeader = data[1].toInt()
        val lenMessage = data[2].toInt()
        val header = data.copyOfRange(3, 3 + lenHeader)
        val message = data.copyOfRange(3 + lenHeader, (3 + lenHeader + lenMessage))
        return Pair(Headers.deSerializeHeader(header), message)
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    private fun formatRequestPublicKey(
        publicKey: ByteArray,
        type: MessageRequestType
    ) : ByteArray {
        val mn = ubyteArrayOf(type.code.toUByte())
        val lenPubKey = ubyteArrayOf(publicKey.size.toUByte())

        return (mn + lenPubKey).toByteArray() + publicKey
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    private fun formatMessage(
        header: Headers,
        cipherText: ByteArray
    ) : ByteArray {
        val mn = ubyteArrayOf(MessageRequestType.TYPE_MESSAGE.code.toUByte())
        val lenHeader = ubyteArrayOf(header.serialized.size.toUByte())
        val lenMessage = ubyteArrayOf(cipherText.size.toUByte())

        return (mn + lenHeader + lenMessage).toByteArray() + header.serialized + cipherText
    }

    suspend fun sendRequest(
        context: Context,
        address: String,
        mode: SecureRequestMode,
    ): ByteArray {
        try {
            val publicKey = generateIdentityPublicKeys(context, address)

            var type: MessageRequestType? = null
            val mode = when(mode) {
                SecureRequestMode.REQUEST_RECEIVED -> {
                    type = MessageRequestType.TYPE_ACCEPT
                    SecureRequestMode.REQUEST_ACCEPTED
                }
                else -> {
                    type = MessageRequestType.TYPE_REQUEST
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
        MessageRequestType.fromCode(publicKey[0])?.let { type ->
            val publicKey = extractRequestPublicKey(publicKey)
            try {
                val mode = when(type) {
                    MessageRequestType.TYPE_REQUEST -> {
                        SecureRequestMode.REQUEST_RECEIVED
                    }
                    MessageRequestType.TYPE_ACCEPT -> {
                        context.removeEncryptionRatchetStates(address)
                        SecureRequestMode.REQUEST_ACCEPTED
                    }
                    else -> return null
                }
                context.setEncryptionModeStates(
                    address,
                    mode,
                    publicKey,
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

    @Throws
    suspend fun decrypt(
        context: Context,
        address: String,
        text: String
    ): String? {

        val data = Base64.decode(text, Base64.DEFAULT)
        if(MessageRequestType.fromCode(data[0]) != MessageRequestType.TYPE_MESSAGE)
            return null

        val payload = try { extractMessage(data) } catch(e: Exception) {
            throw e
        }

        val modeStates = context.getEncryptionModeStatesSync(address)
        val publicKey = Gson().fromJson(modeStates,
            SavedEncryptedModes::class.java).publicKey

        if(publicKey == null) {
            CoroutineScope(Dispatchers.Main).launch {
                Toast.makeText(
                    context,
                    context.getString(R.string.missing_public_key),
                    Toast.LENGTH_LONG).show()
            }
            return null
        }

        val publicKeyBytes = Base64.decode(publicKey, Base64.DEFAULT)

        val keystore = address + "_ratchet_state"
        val currentState = context.getEncryptedBinaryData(keystore)

        var state: States?
        if(currentState == null) {
            state = States()
            val sk = context.calculateSharedSecret(address, publicKeyBytes)
            val keypair = context.getKeypairValues(address) //public private

            Ratchets.ratchetInitBob(
                state,
                sk,
                android.util.Pair(keypair.second, keypair.first)
            )
        }
        else state = States(String(currentState))

        val keypair = context.getKeypairValues(address)
        var decryptedText: String?
        try {
            decryptedText = String(Ratchets.ratchetDecrypt(
                state,
                payload.first,
                payload.second,
                keypair.first
            ))
            context.saveBinaryDataEncrypted(keystore,
                state.serializedStates.encodeToByteArray())
        } catch(e: Exception) {
            throw e
        }
        return decryptedText
    }

    @Throws
    suspend fun encrypt(
        context: Context,
        address: String,
        text: String
    ) : String? {
        val modeStates = context.getEncryptionModeStatesSync(address)
        val publicKey = Gson().fromJson(modeStates,
            SavedEncryptedModes::class.java).publicKey

        if(publicKey == null) {
            CoroutineScope(Dispatchers.Main).launch {
                Toast.makeText(
                    context,
                    context.getString(R.string.missing_public_key),
                    Toast.LENGTH_LONG).show()
            }
            return null
        }

        val publicKeyBytes = Base64.decode(publicKey, Base64.DEFAULT)

        val keystore = address + "_ratchet_state"
        val currentState = context.getEncryptedBinaryData(keystore)

        var state: States?
        if(currentState == null) {
            state = States()
            val sk = context.calculateSharedSecret(address, publicKeyBytes)
            Ratchets.ratchetInitAlice(state, sk, publicKeyBytes)
        }
        else state = States(String(currentState))

        val ratchetOutput = Ratchets.ratchetEncrypt(state,
            text.encodeToByteArray(), publicKeyBytes)

        return try {
            val message = formatMessage(
                ratchetOutput.first,
                ratchetOutput.second
            )
            context.saveBinaryDataEncrypted(keystore,
                state.serializedStates.encodeToByteArray())
            Base64.encodeToString(message, Base64.DEFAULT)
        } catch(e: Exception) {
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
)

private suspend fun Context.setEncryptionModeStates(
    address: String,
    mode: EncryptionController.SecureRequestMode,
    publicKey: ByteArray? = null,
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

        secureComms[keyValue] = Gson().toJson(savedEncryptedModes)
    }
}

private suspend fun Context.removeEncryptionRatchetStates(address: String) {
    val keyValue = stringPreferencesKey(address + "_ratchet_state")
    dataStore.edit { secureComms ->
        secureComms.remove(keyValue)
        withContext(Dispatchers.Main) {
            Toast.makeText(
                this@removeEncryptionRatchetStates,
                getString(R.string.ratchet_states_removed),
                Toast.LENGTH_LONG).show()
        }
    }
}

suspend fun Context.removeEncryptionModeStates(address: String) {
    val keyValue = stringPreferencesKey(address + "_mode_states")
    dataStore.edit { secureComms ->
        secureComms.remove(keyValue)
    }
}

suspend fun Context.getEncryptionModeStatesSync(address: String): String? {
    val keyValue = stringPreferencesKey(address + "_mode_states")
    return dataStore.data.first()[keyValue]
}

fun Context.getEncryptionModeStates(address: String): Flow<String?> {
    val keyValue = stringPreferencesKey(address + "_mode_states")
    return dataStore.data.map { it[keyValue] }
}
