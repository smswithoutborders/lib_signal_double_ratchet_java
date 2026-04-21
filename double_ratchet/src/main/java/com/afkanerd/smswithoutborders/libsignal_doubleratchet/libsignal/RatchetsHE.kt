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
        bobKeypair: CloseableCurve15519KeyPair,
        sharedHka: ByteArray,
        sharedNHka: ByteArray,
    ) {
        state.DHRs = bobKeypair
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
        try {
            state.CKs = ck
            val header = Headers(state.DHRs!!, state.PN, state.Ns)
            val encHeader = hEncrypt(state.HKs!!, header.serialized)
            state.Ns++
            return RatchetPayload(
                header = encHeader,
                cipherText = encrypt(mk, plaintext, concat(ad, encHeader))
            )
        } finally {
            ck.fill(0)
            mk.fill(0)
        }
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

        val (ck, mk) = kdfCk(state.CKr)
        try {
            state.CKr = ck
            state.Nr++
            return decrypt(mk, cipherText, concat(ad, encHeader))
        } finally {
            ck.fill(0)
            mk.fill(0)
        }
    }

    private fun skipMessageKeys(
        state: States,
        until: Int,
    ) {
        if(state.Nr.toInt() + MAX_SKIP < until)
            throw Exception("MAX SKIP Exceeded")

        state.CKr?.let{
            while(state.Nr.toInt() < until) {
                val (ck, mk) = kdfCk(state.CKr)
                try {
                    state.CKr = ck
                    val mk = mk
                    state.MKSKIPPED[Pair(state.HKr, state.Nr.toInt())] = mk
                    state.Nr++
                } finally {
                    ck.fill(0)
                    mk.fill(0)
                }
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

            try {
                val header = hDecrypt(hk, encHeader)?.run {
                    Headers.deserialize(this)
                }
                if(header != null && header.n.toInt() == n) {
                    state.MKSKIPPED.remove(it.key)
                    return decrypt(mk, ciphertext, concat(ad, encHeader))
                }
            } finally {
                hk.fill(0)
                mk.fill(0)
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
            header = hDecrypt(state.HKr, encHeader)?.run {
                Headers.deserialize(this)
            }
        } catch(e: Exception) {
            e.printStackTrace()
        }

        header?.let {
            return Pair(header, false)
        }

        header = hDecrypt(state.NHKr!!, encHeader)?.run {
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
        state.DHRr = X25519PublicKeyParameters(header.dh.publicKey)

        val (rk, ck, nhk) = kdfRk(state.RK!!,
            dh(
                state.DHRs!!,
                state.DHRr!!,
            )
        )
        try {
            state.RK = rk.copyOf()
            state.CKr = ck.copyOf()
            state.NHKr = nhk.copyOf()
        } finally {
            rk.fill(0)
            ck.fill(0)
            nhk.fill(0)
        }

        state.DHRs = generateDH()

        val (rk1, ck1, nhk1) = kdfRk(state.RK!!,
            dh(
                state.DHRs!!,
                state.DHRr!!,
            )
        )
        try {
            state.RK = rk1.copyOf()
            state.CKs = ck1.copyOf()
            state.NHKs = nhk1.copyOf()
        } finally {
            rk1.fill(0)
            ck1.fill(0)
            nhk1.fill(0)
        }
    }
}