package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.util.Pair
import androidx.core.util.component1
import androidx.core.util.component2
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols.CONCAT_HE
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols.DECRYPT
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols.ENCRYPT
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols.GENERATE_DH
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols.HDECRYPT
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols.HENCRYPT
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols.KDF_CK
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal.Protocols.KDF_RK_HE

object RatchetsHE {

    const val MAX_SKIP: Int = 100

    fun ratchetInitAlice(
        state: States,
        SK: ByteArray,
        bobDhPublicKey: ByteArray,
        sharedHka: ByteArray,
        sharedNhkb: ByteArray,
    ) {
        state.DHRs = GENERATE_DH()
        state.DHRr = bobDhPublicKey

        val kdfRkHEOutputs = KDF_RK_HE(SK,
            Protocols.DH_HE(
                state.DHRs,
                state.DHRr,
                Protocols.KDF_RK_HE_INFO
            )
        )
        state.RK = kdfRkHEOutputs[0]
        state.CKs = kdfRkHEOutputs[1]
        state.NHKs = kdfRkHEOutputs[2]

        state.CKr = null
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = mutableMapOf()
        state.HKs = sharedHka
        state.HKr = null
        state.NHKr = sharedNhkb
    }

    fun ratchetInitBob(
        state: States,
        SK: ByteArray,
        bobDhPublicKeypair: Pair<ByteArray, ByteArray>,
        sharedHka: ByteArray,
        sharedNhkb: ByteArray,
    ) {
        state.DHRs = bobDhPublicKeypair
        state.DHRr = null
        state.RK = SK
        state.CKs = null
        state.CKr = null
        state.Ns = 0
        state.Nr = 0
        state.PN = 0
        state.MKSKIPPED = mutableMapOf()
        state.HKs = null
        state.NHKs = sharedNhkb
        state.HKr = null
        state.NHKr = sharedHka
    }

    fun ratchetEncrypt(
        state: States,
        plaintext: ByteArray,
        AD: ByteArray,
    ) : Pair<ByteArray, ByteArray> {
        val kdfCk = KDF_CK(state.CKs)
        state.CKs = kdfCk.first
        val mk = kdfCk.second
        val header = Headers(state.DHRs, state.PN, state.Ns)
        val encHeader = HENCRYPT(state.HKs, header.serialized)
        state.Ns += 1
        return Pair(encHeader,
            ENCRYPT(mk, plaintext, CONCAT_HE(AD, encHeader)))
    }

    fun ratchetDecrypt(
        state: States,
        encHeader: ByteArray,
        cipherText: ByteArray,
        AD: ByteArray,
    ): ByteArray {
        val plaintext = trySkippedMessageKeys(state, encHeader, cipherText, AD)
        if(plaintext != null)
            return plaintext

        val (header, dhRatchet) = decryptHeader(state, encHeader)
        if(dhRatchet) {
            skipMessageKeys(state, header.PN)
            DHRatchetHE(state, header)
        }

        skipMessageKeys(state, header.N)
        val kdfCk = KDF_CK(state.CKr)
        state.CKr = kdfCk.first
        val mk = kdfCk.second
        state.Nr += 1
        return DECRYPT(mk, cipherText, CONCAT_HE(AD, encHeader))
    }

    private fun skipMessageKeys(
        state: States,
        until: Int,
    ) {
        if(state.Nr + MAX_SKIP < until)
            throw Exception("MAX_SKIP Exceeded")

        state.CKr?.let{
            while(state.Nr < until) {
                val kdfCk = KDF_CK(state.CKr)
                state.CKr = kdfCk.first
                val mk = kdfCk.second
                state.MKSKIPPED[Pair(state.HKr, state.Nr)] = mk
                state.Nr += 1
            }
        }
    }

    private fun trySkippedMessageKeys(
        state: States,
        encHeader: ByteArray,
        ciphertext: ByteArray,
        AD: ByteArray
    ) : ByteArray? {
        state.MKSKIPPED.forEach {
            val hk = it.key.first
            val n = it.key.second
            val mk = it.value

            val header = HDECRYPT(hk, encHeader).run {
                Headers.deSerializeHeader(this)
            }
            if(header != null && header.N == n) {
                state.MKSKIPPED.remove(it.key)
                return DECRYPT(mk, ciphertext, CONCAT_HE(AD, encHeader))
            }
        }

        return null
    }

    private fun decryptHeader(
        state: States,
        encHeader: ByteArray
    ) : Pair<Headers, Boolean> {
        var header: Headers? = null
        try {
            header = HDECRYPT(state.HKr, encHeader).run {
                Headers.deSerializeHeader(this)
            }
        } catch(e: Exception) {
            e.printStackTrace()
        }

        header?.let {
            return Pair(header, false)
        }

        header = HDECRYPT(state.NHKr, encHeader).run {
            Headers.deSerializeHeader(this)
        }
        header?.let {
            return Pair(header, true)
        }
        throw Exception("Generic error decrypting header...")
    }

    private fun DHRatchetHE(
        state: States,
        header: Headers
    ) {
        state.PN = state.Ns
        state.Ns = 0
        state.Nr = 0
        state.HKs = state.NHKs
        state.HKr = state.NHKr
        state.DHRr = header.dh

        var kdfRkHEOutputs = KDF_RK_HE(state.RK,
            Protocols.DH_HE(
                state.DHRs,
                state.DHRr,
                Protocols.KDF_RK_HE_INFO
            )
        )
        state.RK = kdfRkHEOutputs[0]
        state.CKr = kdfRkHEOutputs[1]
        state.NHKr = kdfRkHEOutputs[2]

        state.DHRs = GENERATE_DH()

        kdfRkHEOutputs = KDF_RK_HE(state.RK,
            Protocols.DH_HE(
                state.DHRs,
                state.DHRr,
                Protocols.KDF_RK_HE_INFO
            )
        )
        state.RK = kdfRkHEOutputs[0]
        state.CKs = kdfRkHEOutputs[1]
        state.NHKs = kdfRkHEOutputs[2]
    }
}