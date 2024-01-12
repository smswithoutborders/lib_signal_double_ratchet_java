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
        byte[] SK = CryptoHelpers.generateRandomBytes(32);

        String keystoreAlias = "bobsKeystoreAlias";
        bobKeyPair = SecurityECDH.generateKeyPair(keystoreAlias).first;
        dhPublicKeyBob = bobKeyPair.getPublic();

        Ratchets ratchetAlice = new Ratchets(), ratchetBob = new Ratchets();
        States stateAlice = new States(), stateBob = new States();

        String keystoreAliasAlice = "bob_session_0";
        ratchetAlice.ratchetInitAlice(keystoreAliasAlice, stateAlice, SK, dhPublicKeyBob);

        String keystoreAliasBob = "alice_session_0";
        ratchetBob.ratchetInitBob(stateBob, SK, bobKeyPair);

        // assertions
        States expectedStateAlice = new States(), expectedStateBob = new States();

        // alice params
        String keystoreAliasAliceExpected = "bob_session_0_expected";
        expectedStateAlice.DHs = SecurityECDH.generateKeyPair(keystoreAliasAliceExpected).first;
        expectedStateAlice.DHr = dhPublicKeyBob;

        // bob params
        expectedStateBob.DHs = bobKeyPair;
        expectedStateBob.RK = SK;

        assertEquals(expectedStateAlice, stateAlice);
        assertEquals(expectedStateBob, stateBob);

        final byte[] plainText = CryptoHelpers.generateRandomBytes(130);
        final byte[] AD = CryptoHelpers.generateRandomBytes(16);

        Ratchets.EncryptPayload encryptPayloadAlice =
                ratchetAlice.ratchetEncrypt(stateAlice, plainText, AD);
        expectedStateAlice.Ns = 1;
        assertEquals(expectedStateAlice, stateAlice);
        Headers expectedHeadersAlice = new Headers(stateAlice.DHs, 0, 0);
        assertEquals(expectedHeadersAlice, encryptPayloadAlice.header);

        // TODO: Size of the Header (H) (documentation required)
        Log.d(getClass().getName(), "H.size: " +
                encryptPayloadAlice.header.getSerialized().length);
        // TODO: Size of the Encrypted Header (EH) (documentation required)

        // TODO: Size of the Encrypted Message (EM) (documentation required)
        Log.d(getClass().getName(), "EM.size: " + encryptPayloadAlice.cipherText.length);

        byte[] decryptedPlainText = ratchetBob.ratchetDecrypt(keystoreAliasBob, stateBob,
                encryptPayloadAlice.header, encryptPayloadAlice.cipherText,
                Protocols.CONCAT(AD, encryptPayloadAlice.header));
        expectedStateBob.PN = 0;
        expectedStateBob.Ns = 0;
        expectedStateBob.Nr = 1;
        expectedStateBob.DHr = stateAlice.DHs.getPublic();
        assertArrayEquals(expectedStateBob.DHr.getEncoded(), stateBob.DHr.getEncoded());
        assertEquals(expectedStateBob, stateBob);
        assertArrayEquals(plainText, decryptedPlainText);

        Ratchets.EncryptPayload encryptPayloadBob =
                ratchetBob.ratchetEncrypt(stateBob, plainText, AD);
        expectedStateBob.Ns = 1;
        assertEquals(expectedStateBob, stateBob);

        byte[] decryptedPlainText1 = ratchetAlice.ratchetDecrypt(keystoreAliasAlice, stateAlice,
                encryptPayloadBob.header, encryptPayloadBob.cipherText,
                Protocols.CONCAT(AD, encryptPayloadBob.header));
        expectedStateAlice.PN = 1;
        expectedStateAlice.Ns = 0;
        expectedStateAlice.Nr = 1;
        expectedStateAlice.DHr = stateBob.DHs.getPublic();
        assertArrayEquals(expectedStateAlice.DHr.getEncoded(), stateAlice.DHr.getEncoded());
        assertEquals(expectedStateAlice, stateAlice);
        assertArrayEquals(plainText, decryptedPlainText1);
    }
}

