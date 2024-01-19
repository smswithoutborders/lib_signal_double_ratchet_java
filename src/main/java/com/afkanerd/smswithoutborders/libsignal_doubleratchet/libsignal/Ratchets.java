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
    public static Pair<States, byte[]> ratchetInitAlice(String keystoreAlias, States state, byte[] SK,
                                 PublicKey dhPublicKeyBob) throws GeneralSecurityException, IOException, InterruptedException {
        Pair<KeyPair, byte[]> output = Protocols.GENERATE_DH(keystoreAlias);
        state.DHs = output.first;
        state.DHr = dhPublicKeyBob;
        byte[] dh_out = Protocols.DH(state.DHs, state.DHr);
        Log.d(Ratchets.class.getName(), "Alice DH Out: " +
                Base64.encodeToString(dh_out, Base64.DEFAULT));
        Log.d(Ratchets.class.getName(), "Alice SK: " +
                Base64.encodeToString(SK, Base64.DEFAULT));
        Pair<byte[], byte[]> kdfRkOutput = Protocols.KDF_RK(SK, dh_out);
        state.RK = kdfRkOutput.first;
        state.CKs = kdfRkOutput.second;
//        Log.d(Ratchets.class.getName(), "Alice DHs: " +
//                Base64.encodeToString(state.DHs.getPublic().getEncoded(), Base64.DEFAULT));
//        Log.d(Ratchets.class.getName(), "Alice DHr: " +
//                Base64.encodeToString(state.DHr.getEncoded(), Base64.DEFAULT));
        return new Pair<>(state, output.second);
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

//        byte[] concatADHeader = Protocols.CONCAT(AD, header);
        byte[] cipherText = Protocols.ENCRYPT(mk, plainText, Protocols.CONCAT(AD, header));
        Log.d(Ratchets.class.getName(), "Alice CKs: " +
                Base64.encodeToString(state.CKs, Base64.DEFAULT));
        Log.d(Ratchets.class.getName(), "Encrypt mk: " +
                Base64.encodeToString(mk, Base64.DEFAULT));
        return new Pair<>(header, cipherText);
    }

    public static byte[] ratchetDecrypt(String keystoreAlias, States state, Headers header,
                                 byte[] cipherText, byte[] AD) throws Throwable {
        byte[] plainText = trySkippedMessageKeys(state, header, cipherText, AD);
        if(plainText != null)
            return plainText;

        if(state.DHr == null ||
                !Arrays.equals(header.dh.getEncoded(), state.DHr.getEncoded())) {
            skipMessageKeys(state, header.PN);
            DHRatchet(keystoreAlias, state, header);
        }
        skipMessageKeys(state, header.N);
        Pair<byte[], byte[]> kdfCkOutput = Protocols.KDF_CK(state.CKr);
        Log.d(Ratchets.class.getName(), "Bob CKr: " +
                Base64.encodeToString(state.CKr, Base64.DEFAULT));
        state.CKr = kdfCkOutput.first;
        byte[] mk = kdfCkOutput.second;
        state.Nr += 1;
        return Protocols.DECRYPT(mk, cipherText, Protocols.CONCAT(AD, header));
    }

    private static void DHRatchet(String keystoreAlias,
                           States state, Headers header) throws GeneralSecurityException, IOException, InterruptedException {
        state.PN = state.Ns;
        state.Ns = 0;
        state.Nr = 0;
        state.DHr = header.dh;
        byte[] dh_out = Protocols.DH(state.DHs, state.DHr);
        Log.d(Ratchets.class.getName(), "Bob DH Out: " +
                Base64.encodeToString(dh_out, Base64.DEFAULT));
        Log.d(Ratchets.class.getName(), "Bob RK: " +
                Base64.encodeToString(state.RK, Base64.DEFAULT));
        Pair<byte[], byte[]> kdfRkOutput = Protocols.KDF_RK(state.RK, dh_out);
        state.RK = kdfRkOutput.first;
        state.CKr = kdfRkOutput.second;

        // TODO: should store the key in second
//        state.DHs = Protocols.GENERATE_DH(keystoreAlias);
        state.DHs = Protocols.GENERATE_DH(keystoreAlias).first;

        kdfRkOutput = Protocols.KDF_RK(state.RK, Protocols.DH(state.DHs, state.DHr));
        state.RK = kdfRkOutput.first;
        state.CKs = kdfRkOutput.second;
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
                Pair<byte[], byte[]> kdfCkOutput = Protocols.KDF_CK(state.CKr);
                state.CKr = kdfCkOutput.first;
                byte[] mk = kdfCkOutput.second;
                state.MKSKIPPED.put(new Pair<>(state.DHr, state.Nr), mk);
                state.Nr +=1;
            }
        }
    }

}
