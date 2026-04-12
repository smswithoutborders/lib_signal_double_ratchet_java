package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal

import android.content.Context
import android.util.Pair
import androidx.core.util.component1
import androidx.core.util.component2
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.R
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

class RatchetPayload(
    val header: ByteArray,
    val cipherText: ByteArray,
)

class RatchetsHE(context: Context) : Protocols(context){
    val MAX_SKIP = 255

    /**
     * @param state
     * @param sk
     * @param bobDhPublicKey
     * @param sharedHka Alice's shared header key
     * @param sharedNHka Alice's next shared header key
     */
    fun ratchetInitAlice(
        state: States,
        sk: ByteArray,
        bobDhPublicKey: CipherParameters,
        sharedHka: ByteArray,
        sharedNHka: ByteArray,
    ) {
        state.DHRs = generateDH()
        state.DHRr = bobDhPublicKey

        kdfRk(
            rk = sk, dh( state.DHRs!!, state.DHRr!!)
        ).let {
            state.RK = it.first
            state.CKs = it.second
            state.NHKs = it.third
        }

        state.CKr = null
        state.Ns = 0u
        state.Nr = 0u
        state.PN = 0u
        state.MKSKIPPED = mutableMapOf()
        state.HKs = sharedHka
        state.HKr = null
        state.NHKr = sharedNHka
    }

    fun ratchetInitBob(
        state: States,
        sk: ByteArray,
        bobDhPublicKeypair: AsymmetricCipherKeyPair,
        sharedHka: ByteArray,
        sharedNHka: ByteArray,
    ) {
        state.DHRs = bobDhPublicKeypair
        state.DHRr = null
        state.RK = sk
        state.CKs = null
        state.CKr = null
        state.Ns = 0u
        state.Nr = 0u
        state.PN = 0u
        state.MKSKIPPED = mutableMapOf()
        state.HKs = null
        state.NHKs = sharedNHka
        state.HKr = null
        state.NHKr = sharedHka
    }

    fun ratchetEncrypt(
        state: States,
        plaintext: ByteArray,
        ad: ByteArray,
    ) : RatchetPayload {
        val (ck, mk) = kdfCk(state.CKs)
        state.CKs = ck
        val header = Headers(state.DHRs!!, state.PN, state.Ns)
        val encHeader = hEncrypt(state.HKs!!, header.serialized)
        state.Ns++
        return RatchetPayload(
            header = encHeader,
            cipherText = encrypt(mk, plaintext, concat(ad, encHeader))
        )
    }

    fun ratchetDecrypt(
        state: States,
        encHeader: ByteArray,
        cipherText: ByteArray,
        ad: ByteArray,
    ): ByteArray {
        val plaintext = trySkippedMessageKeys(state, encHeader, cipherText, ad)
        if(plaintext != null)
            return plaintext

        val (header, dhRatchet) = decryptHeader(state, encHeader)
        if(dhRatchet) {
            skipMessageKeys(state, header.pn.toInt())
            dhRatchet(state, header)
        }

        skipMessageKeys(state, header.n.toInt())
        val kdfCk = kdfCk(state.CKr)
        state.CKr = kdfCk.first
        val mk = kdfCk.second
        state.Nr++
        return decrypt(mk, cipherText, concat(ad, encHeader))
    }

    private fun skipMessageKeys(
        state: States,
        until: Int,
    ) {
        if(state.Nr.toInt() + MAX_SKIP < until)
            throw Exception("MAX SKIP Exceeded")

        state.CKr?.let{
            while(state.Nr.toInt() < until) {
                val kdfCk = kdfCk(state.CKr)
                state.CKr = kdfCk.first
                val mk = kdfCk.second
                state.MKSKIPPED[Pair(state.HKr, state.Nr.toInt())] = mk
                state.Nr++
            }
        }
    }

    private fun trySkippedMessageKeys(
        state: States,
        encHeader: ByteArray,
        ciphertext: ByteArray,
        ad: ByteArray
    ) : ByteArray? {
        state.MKSKIPPED.forEach {
            val (hk, n) = it.key
            val mk = it.value

            val header = hDecrypt(hk, encHeader).run {
                Headers.deserialize(this)
            }
            if(header.n.toInt() == n) {
                state.MKSKIPPED.remove(it.key)
                return decrypt(mk, ciphertext, concat(ad, encHeader))
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
            header = hDecrypt(state.HKr!!, encHeader).run {
                Headers.deserialize(this)
            }
        } catch(e: Exception) {
            e.printStackTrace()
        }

        header?.let {
            return Pair(header, false)
        }

        header = hDecrypt(state.NHKr!!, encHeader).run {
            Headers.deserialize(this)
        }

        return Pair(header, true)
    }

    private fun dhRatchet(state: States, header: Headers) {
        state.PN = state.Ns
        state.Ns = 0u
        state.Nr = 0u
        state.HKs = state.NHKs
        state.HKr = state.NHKr
        state.DHRr = header.dh.public

        kdfRk(state.RK!!,
            dh(
                state.DHRs!!,
                state.DHRr!!,
            )
        ).let {
            state.RK = it.first
            state.CKr = it.second
            state.NHKr = it.third
        }

        state.DHRs = generateDH()

        kdfRk(state.RK!!,
            dh(
                state.DHRs!!,
                state.DHRr!!,
            )
        ).let {
            state.RK = it.first
            state.CKs = it.second
            state.NHKs = it.third
        }
    }
}