package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import android.util.Pair;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class Ratchets {
    public static final int MAX_SKIP = 100;

    /**
     *
     * @param state
     * @param SK
     * @param dhPublicKeyBob
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws InterruptedException
     */
    public static void ratchetInitAlice(States state,
                                          byte[] SK,
                                          byte[] dhPublicKeyBob) throws GeneralSecurityException, IOException, InterruptedException {
        state.DHs = Protocols.GENERATE_DH();
        state.DHr = dhPublicKeyBob;
        byte[] dh_out = Protocols.DH(state.DHs, state.DHr);
        Pair<byte[], byte[]> kdfRkOutput = Protocols.KDF_RK(SK, dh_out);
        state.RK = kdfRkOutput.first;
        state.CKs = kdfRkOutput.second;
    }

    public static void ratchetInitBob(States state, byte[] SK, Pair<byte[], byte[]> dhKeyPairBob) {
        state.DHs = dhKeyPairBob;
        state.RK = SK;
    }

    public static Pair<Headers, byte[]> ratchetEncrypt(States state, byte[] plainText, byte[] AD) throws Throwable {
        Pair<byte[], byte[]> kdfCkOutput = Protocols.KDF_CK(state.CKs);
        state.CKs = kdfCkOutput.first;
        byte[] mk = kdfCkOutput.second;
        Headers header = new Headers(state.DHs, state.PN, state.Ns);
        state.Ns += 1;

        byte[] cipherText = Protocols.ENCRYPT(mk, plainText, Protocols.CONCAT(AD, header));
        return new Pair<>(header, cipherText);
    }

    /**
     *
     * @param state
     * @param header
     * @param cipherText
     * @param AD
     * @return
     * @throws Throwable
     */
    public static byte[] ratchetDecrypt(States state,
                                        Headers header,
                                        byte[] cipherText,
                                        byte[] AD) throws Throwable {
        byte[] plainText = trySkippedMessageKeys(state, header, cipherText, AD);
        if(plainText != null)
            return plainText;

        if(state.DHr == null || !Arrays.equals(header.dh, state.DHr)) {
            skipMessageKeys(state, header.PN);
            DHRatchet(state, header);
        }
        skipMessageKeys(state, header.N);
        Pair<byte[], byte[]> kdfCkOutput = Protocols.KDF_CK(state.CKr);
        state.CKr = kdfCkOutput.first;
        byte[] mk = kdfCkOutput.second;
        state.Nr += 1;
        return Protocols.DECRYPT(mk, cipherText, Protocols.CONCAT(AD, header));
    }

    private static void DHRatchet(States state, Headers header) throws GeneralSecurityException, IOException, InterruptedException {
        state.PN = state.Ns;
        state.Ns = 0;
        state.Nr = 0;
        state.DHr = header.dh;
        byte[] dh_out = Protocols.DH(state.DHs, state.DHr);
        Pair<byte[], byte[]> kdfRkOutput = Protocols.KDF_RK(state.RK, dh_out);
        state.RK = kdfRkOutput.first;
        state.CKr = kdfRkOutput.second;

        state.DHs = Protocols.GENERATE_DH();
        kdfRkOutput = Protocols.KDF_RK(state.RK, Protocols.DH(state.DHs, state.DHr));
        state.RK = kdfRkOutput.first;
        state.CKs = kdfRkOutput.second;
    }

    private static byte[] trySkippedMessageKeys(States state, Headers header, byte[] cipherText, byte[] AD) throws Throwable {
        Pair<byte[], Integer> mkSkippedKeys = new Pair<>(header.dh, header.N);
        if(state.MKSKIPPED.containsKey(mkSkippedKeys)){
            byte[] mk = state.MKSKIPPED.get(mkSkippedKeys);
            state.MKSKIPPED.remove(mkSkippedKeys);
            return Protocols.DECRYPT(mk, cipherText, Protocols.CONCAT(AD, header));
        }
        return null;
    }

    private static void skipMessageKeys(States state, int until) throws Exception {
        if((state.Nr + MAX_SKIP) < until) {
            throw new Exception("MAX skip exceeded");
        }

        if(state.CKr != null) {
            while(state.Nr < until) {
                Pair<byte[], byte[]> kdfCkOutput = Protocols.KDF_CK(state.CKr);
                state.CKr = kdfCkOutput.first;
                byte[] mk = kdfCkOutput.second;
                state.MKSKIPPED.put(new Pair<>(state.DHr, state.Nr), mk);
                state.Nr +=1;
            }
        }
    }

}
