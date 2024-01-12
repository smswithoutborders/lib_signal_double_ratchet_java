package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import android.content.Context;
import android.util.Pair;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

public class Ratchets {
    public final int MAX_SKIP = 20;
    public void ratchetInitAlice(String keystoreAlias, States state, byte[] SK,
                                 PublicKey dhPublicKeyBob) throws GeneralSecurityException, IOException, InterruptedException {
        state.DHs = Protocols.GENERATE_DH(keystoreAlias);
        state.DHr = dhPublicKeyBob;
        Pair<byte[], byte[]> kdfRkOutput = Protocols.KDF_RK(SK, Protocols.DH(state.DHs, state.DHr));
        state.RK = kdfRkOutput.first;
        state.CKs = kdfRkOutput.second;
    }

    public void ratchetInitBob(States state, byte[] SK, KeyPair dhKeyPairBob) {
        state.DHs = dhKeyPairBob;
        state.RK = SK;
    }

    public EncryptPayload ratchetEncrypt(States state, byte[] plainText, byte[] AD) throws Throwable {
        Pair<byte[], byte[]> kdfCkOutput = Protocols.KDF_CK(state.CKs);
        state.CKs = kdfCkOutput.first;
        byte[] mk = kdfCkOutput.second;
        Headers header = Protocols.HEADER(state.DHs, state.PN, state.Ns);
        state.Ns += 1;

        byte[] cipherText = Protocols.ENCRYPT(mk, plainText, Protocols.CONCAT(AD, header));
        return new EncryptPayload(header, cipherText);
    }

    public byte[] ratchetDecrypt(String keystoreAlias, States state, Headers header,
                                 byte[] cipherText, byte[] AD) throws Throwable {
        byte[] plainText = trySkipMessageKeys(state, header, cipherText, AD);
        if(plainText != null)
            return plainText;

        if(state.DHr == null ||
                !Arrays.equals(header.dh.getEncoded(), state.DHr.getEncoded())) {
            skipMessageKeys(state, header.PN);
            DHRatchet(keystoreAlias, state, header);
        }
        Pair<byte[], byte[]> kdfCkOutput = Protocols.KDF_CK(state.CKr);
        state.CKr = kdfCkOutput.first;
        byte[] mk = kdfCkOutput.second;
        state.Nr += 1;
        return Protocols.DECRYPT(mk, cipherText, AD);
    }

    private void DHRatchet(String keystoreAlias,
                           States state, Headers header) throws GeneralSecurityException, IOException, InterruptedException {
        state.PN = state.Ns;
        state.Ns = 0;
        state.Nr = 0;
        state.DHr = header.dh;

        Pair<byte[], byte[]> kdfRkOutput = Protocols.KDF_RK(state.RK, Protocols.DH(state.DHs, state.DHr));
        state.RK = kdfRkOutput.first;
        state.CKr = kdfRkOutput.second;

        state.DHs = Protocols.GENERATE_DH(keystoreAlias);

        kdfRkOutput = Protocols.KDF_RK(state.RK, Protocols.DH(state.DHs, state.DHr));
        state.RK = kdfRkOutput.first;
        state.CKs = kdfRkOutput.second;
    }

    private byte[] trySkipMessageKeys(States state, Headers header, byte[] cipherText, byte[] AD) throws Throwable {
        Pair<PublicKey, Integer> mkSkippedKeys = new Pair<>(header.dh, header.N);
        if(state.MKSKIPPED.containsKey(mkSkippedKeys)){
            byte[] mk = state.MKSKIPPED.get(mkSkippedKeys);
            state.MKSKIPPED.remove(mkSkippedKeys);
            return Protocols.DECRYPT(mk, cipherText, Protocols.CONCAT(AD, header));
        }
        return null;
    }

    private void skipMessageKeys(States state, int until) throws Exception {
        if((state.Nr + MAX_SKIP) < until) {
            throw new Exception("Nr+Max_Skip < until");
        }

        if(state.CKr != null) {
            while(state.Nr < until) {
                Pair<byte[], byte[]> kdfCkOutput = Protocols.KDF_CK(state.CKr);
                state.MKSKIPPED.put(new Pair<>(state.DHr, state.Nr), kdfCkOutput.second);
                state.Nr +=1;
            }
        }
    }

    public static class EncryptPayload {
        public Headers header;
        public byte[] cipherText;

        public EncryptPayload(Headers header, byte[] cipherText) {
            this.header = header;
            this.cipherText = cipherText;
        }
    }

}
