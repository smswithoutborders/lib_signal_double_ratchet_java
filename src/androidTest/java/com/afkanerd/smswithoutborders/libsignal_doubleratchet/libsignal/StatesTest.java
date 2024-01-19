package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import static junit.framework.TestCase.assertEquals;

import android.util.Pair;

import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoHelpers;
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityECDH;

import org.json.JSONException;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

public class StatesTest {

    @Test
    public void canSerializeTest() throws GeneralSecurityException, IOException, InterruptedException, JSONException {
        String keystoreAlias = "canDeserializeTest";
        Pair<KeyPair, byte[] > keyPairPair = SecurityECDH.generateKeyPair(keystoreAlias);

        States states = new States();
        states.DHr = keyPairPair.first.getPublic();
        states.RK = CryptoHelpers.generateRandomBytes(32);
        states.CKs = CryptoHelpers.generateRandomBytes(32);
        states.CKr = CryptoHelpers.generateRandomBytes(32);
        String serializedStates = states.getSerializedStates();

        States outputState = new States(keyPairPair.first, serializedStates);
        assertEquals(states, outputState);
    }
}
