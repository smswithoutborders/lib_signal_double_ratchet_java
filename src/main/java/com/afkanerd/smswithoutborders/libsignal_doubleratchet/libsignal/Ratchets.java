package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import android.os.Build;
import android.util.Base64;
import android.util.Log;
import android.util.Pair;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

public class Ratchets {
    public static final int MAX_SKIP = 20;
    /**
     *
     * @param keystoreAlias
     * @param state
     * @param SK
     * @param dhPublicKeyBob
     * @return Returns the privateKeyCipher for storage. To help support Android SDK <34.
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws InterruptedException
     */
    public static byte[] ratchetInitAlice(String keystoreAlias, States state, byte[] SK,
                                 PublicKey dhPublicKeyBob) throws GeneralSecurityException, IOException, InterruptedException {
        Pair<KeyPair, byte[]> output = Protocols.GENERATE_DH(keystoreAlias);
        state.DHs = output.first;
        state.DHr = dhPublicKeyBob;
        byte[] dh_out = Protocols.DH(state.DHs, state.DHr);
        Pair<byte[], byte[]> kdfRkOutput = Protocols.KDF_RK(SK, dh_out);
        state.RK = kdfRkOutput.first;
        state.CKs = kdfRkOutput.second;

        return output.second;
    }

    public static States ratchetInitBob(States state, byte[] SK, KeyPair dhKeyPairBob) {
        state.DHs = dhKeyPairBob;
        state.RK = SK;
        return state;
    }

    public static Pair<Headers, byte[]> ratchetEncrypt(States state, byte[] plainText, byte[] AD) throws Throwable {
        Pair<byte[], byte[]> kdfCkOutput = Protocols.KDF_CK(state.CKs);
        state.CKs = kdfCkOutput.first;
        byte[] mk = kdfCkOutput.second;
        Headers header = Protocols.HEADER(state.DHs, state.PN, state.Ns);
        state.Ns += 1;

        byte[] cipherText = Protocols.ENCRYPT(mk, plainText, Protocols.CONCAT(AD, header));
        return new Pair<>(header, cipherText);
    }

    /**
     *
     * @param keystoreAlias
     * @param state
     * @param header
     * @param cipherText
     * @param AD
     * @return Pair of (byte[], byte[]): first = decryptedContent, second=privateKeyCipher, should be stored.
     * This helps supports Android SDK <34, because ECDH not yet supported in Android keystore below 34.
     * @throws Throwable
     */
    public static Pair<byte[], byte[]> ratchetDecrypt(String keystoreAlias, States state, Headers header,
                                 byte[] cipherText, byte[] AD) throws Throwable {
        byte[] plainText = trySkippedMessageKeys(state, header, cipherText, AD);
        if(plainText != null)
            return new Pair<>(plainText, null);

        byte[] privateKeyCipher = null;
        if(state.DHr == null ||
                !Arrays.equals(header.dh.getEncoded(), state.DHr.getEncoded())) {
            skipMessageKeys(state, header.PN);
            privateKeyCipher = DHRatchet(keystoreAlias, state, header);
        }
        skipMessageKeys(state, header.N);
//        if(header.N > 0)
//            Log.d(Ratchets.class.getName(), "Skipped state: " + state.getSerializedStates());
        Pair<byte[], byte[]> kdfCkOutput = Protocols.KDF_CK(state.CKr);
        state.CKr = kdfCkOutput.first;
        byte[] mk = kdfCkOutput.second;
        state.Nr += 1;
        return new Pair<>(Protocols.DECRYPT(mk, cipherText, Protocols.CONCAT(AD, header)),
                privateKeyCipher);
    }

    private static byte[] DHRatchet(String keystoreAlias,
                           States state, Headers header) throws GeneralSecurityException, IOException, InterruptedException {
        state.PN = state.Ns;
        state.Ns = 0;
        state.Nr = 0;
        state.DHr = header.dh;
        byte[] dh_out = Protocols.DH(state.DHs, state.DHr);
        Pair<byte[], byte[]> kdfRkOutput = Protocols.KDF_RK(state.RK, dh_out);
        state.RK = kdfRkOutput.first;
        state.CKr = kdfRkOutput.second;

        Pair<KeyPair, byte[]> output = Protocols.GENERATE_DH(keystoreAlias);
        state.DHs = output.first;

        kdfRkOutput = Protocols.KDF_RK(state.RK, Protocols.DH(state.DHs, state.DHr));
        state.RK = kdfRkOutput.first;
        state.CKs = kdfRkOutput.second;

        return output.second;
    }

    private static byte[] trySkippedMessageKeys(States state, Headers header, byte[] cipherText, byte[] AD) throws Throwable {
        Pair<PublicKey, Integer> mkSkippedKeys = new Pair<>(header.dh, header.N);
        if(state.MKSKIPPED.containsKey(mkSkippedKeys)){
            byte[] mk = state.MKSKIPPED.get(mkSkippedKeys);
            state.MKSKIPPED.remove(mkSkippedKeys);
            return Protocols.DECRYPT(mk, cipherText, Protocols.CONCAT(AD, header));
        }
        return null;
    }

    private static void skipMessageKeys(States state, int until) throws Exception {
        if((state.Nr + MAX_SKIP) < until) {
            throw new Exception("Nr+Max_Skip < until");
        }

        if(state.CKr != null) {
            while(state.Nr < until) {
                Log.d(Ratchets.class.getName(), "Yes skipped messages found! " + until);
                Pair<byte[], byte[]> kdfCkOutput = Protocols.KDF_CK(state.CKr);
                state.CKr = kdfCkOutput.first;
                byte[] mk = kdfCkOutput.second;
                state.MKSKIPPED.put(new Pair<>(state.DHr, state.Nr), mk);
                state.Nr +=1;
            }
        }
    }

}
