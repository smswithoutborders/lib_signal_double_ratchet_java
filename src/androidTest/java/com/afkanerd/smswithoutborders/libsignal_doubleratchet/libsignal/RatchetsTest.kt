package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import android.content.Context;
import android.util.Log;
import android.util.Pair;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoHelpers;
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.KeystoreHelpers;
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityAES;
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityECDH;
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityRSA;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

@RunWith(AndroidJUnit4.class)
public class RatchetsTest {

    Context context;
    PublicKey dhPublicKeyBob;
    PublicKey bobDefaultPublicKeyEC;
    KeyPair bobKeyPair;

    String keystoreAliasAlice = "bobsKeystoreAlias";

    public RatchetsTest() throws GeneralSecurityException, IOException, InterruptedException {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();

        // starting constants
        KeystoreHelpers.removeAllFromKeystore(context);

//        String keystoreAliasBobEC = "bobsKeystoreAliasEC";
//        bobDefaultPublicKeyEC = SecurityECDH.generateECKeyPair(keystoreAliasBobEC, 256);
    }

//    @Test
//    public void encryptionTransmissionParamsChecks() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, NoSuchProviderException, CertificateException, KeyStoreException, IOException {
////        byte[] SK = SecurityAES.generateSecretKey(256).getEncoded();
////        byte[] encryptedSkEC = SecurityECDH.encryptWithECPublicKey(SK, bobDefaultPublicKeyEC);
////        int len = encryptedSkEC.length + dhPublicKeyBob.getEncoded().length;
////        Log.d(getClass().getName(), "Len EC: " + encryptedSkEC.length + ":" + len);
//
//        byte[] SK = CryptoHelpers.generateRandomBytes(32);
//        String keystoreAliasBob = "encryptionTransmissionParamsChecks";
//        // pub key len = 94
//        PublicKey bobDefaultPublicKeyRSA = SecurityRSA.generateKeyPair(keystoreAliasBob, 512);
//        byte[] encryptedSkRSA = SecurityRSA.encrypt(bobDefaultPublicKeyRSA, SK);
//        int lenRSA = encryptedSkRSA.length + bobDefaultPublicKeyRSA.getEncoded().length;
//        Log.d(getClass().getName(), "Len RSA: " + encryptedSkRSA.length + ":" + lenRSA);
//        KeystoreHelpers.removeAllFromKeystore(context);
//    }

    @Test
    public void completeRatchetTest() throws Throwable {
        // TODO: - Write test for all States
        byte[] SK = CryptoHelpers.generateRandomBytes(32);

        String keystoreAlias = "bobsKeystoreAlias";
        bobKeyPair = SecurityECDH.generateKeyPair(keystoreAlias).first;
        dhPublicKeyBob = bobKeyPair.getPublic();

        States stateAlice = new States(), stateBob = new States();

        String keystoreAliasAlice = "bob_session_0";
        Ratchets.ratchetInitAlice(keystoreAliasAlice, stateAlice, SK, dhPublicKeyBob);

        String keystoreAliasBob = "alice_session_0";
        Ratchets.ratchetInitBob(stateBob, SK, bobKeyPair);

        final byte[] plainText = CryptoHelpers.generateRandomBytes(130);
        final byte[] AD = CryptoHelpers.generateRandomBytes(128);

        Pair<Headers, byte[][]> encryptPayloadAlice = Ratchets.ratchetEncrypt(stateAlice, plainText, AD);
        Headers expectedHeadersAlice = new Headers(stateAlice.DHs, 0, 0);
        assertEquals(expectedHeadersAlice, encryptPayloadAlice.first);

//        Log.d(getClass().getName(), "H.size: " +
//                encryptPayloadAlice.first.getSerialized().length);
//
//        Log.d(getClass().getName(), "EM.size: " + encryptPayloadAlice.second.length);

        Log.d(getClass().getName(), "Decrypting 1");
        Pair<byte[], byte[]> decryptedPlainText = Ratchets.ratchetDecrypt(keystoreAliasBob,
                stateBob,
                encryptPayloadAlice.first,
                encryptPayloadAlice.second[0],
                AD,
                encryptPayloadAlice.second[1]);
        assertArrayEquals(plainText, decryptedPlainText.first);

        Pair<Headers, byte[][]> encryptPayloadBob = Ratchets.ratchetEncrypt(stateBob, plainText, AD);

        Log.d(getClass().getName(), "Decrypting 2");
        Pair<byte[], byte[]> decryptedPlainText1 = Ratchets.ratchetDecrypt(keystoreAliasAlice,
                stateAlice,
                encryptPayloadBob.first,
                encryptPayloadBob.second[0],
                AD,
                encryptPayloadAlice.second[1]);
        assertArrayEquals(plainText, decryptedPlainText1.first);

        // N1
        encryptPayloadAlice = Ratchets.ratchetEncrypt(stateAlice, plainText, AD);
        // N2
        Pair<Headers, byte[][]> encryptPayloadAlice1 = Ratchets.ratchetEncrypt(stateAlice, plainText, AD);

        // N2
        Log.d(getClass().getName(), "Decrypting 3");
        decryptedPlainText = Ratchets.ratchetDecrypt(keystoreAliasBob,
                stateBob,
                encryptPayloadAlice1.first,
                encryptPayloadAlice1.second[0], AD,
                encryptPayloadAlice1.second[1]);
        assertArrayEquals(plainText, decryptedPlainText.first);

        // N1
        decryptedPlainText = Ratchets.ratchetDecrypt(keystoreAliasBob, stateBob,
                encryptPayloadAlice.first, encryptPayloadAlice.second[0],
                AD,
                encryptPayloadAlice.second[1]);
        assertArrayEquals(plainText, decryptedPlainText.first);
    }
}

