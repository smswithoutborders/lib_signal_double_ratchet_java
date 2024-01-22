package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import static junit.framework.TestCase.assertEquals;

import static org.junit.Assert.assertArrayEquals;

import android.util.Log;
import android.util.Pair;

import com.afkanerd.smswithoutborders.libsignal_doubleratchet.CryptoHelpers;
import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityECDH;
import com.google.common.primitives.Bytes;

import org.json.JSONException;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;

public class StatesTest {

    @Test
    public void canSerializeTest() throws GeneralSecurityException, IOException, InterruptedException, JSONException {
        String keystoreAlias = "canDeserializeTest";
        Pair<KeyPair, byte[] > keyPairPair = SecurityECDH.generateKeyPair(keystoreAlias);

        States states = new States();
        states.DHs = keyPairPair.first;
        states.DHr = keyPairPair.first.getPublic();
        states.RK = CryptoHelpers.generateRandomBytes(32);
        states.CKs = CryptoHelpers.generateRandomBytes(32);
        states.CKr = CryptoHelpers.generateRandomBytes(32);
        states.MKSKIPPED.put(new Pair<>(keyPairPair.first.getPublic(), 0),
                CryptoHelpers.generateRandomBytes(32));
        String serializedStates = states.getSerializedStates();
        Log.d(StatesTest.class.getName(), serializedStates);

        States outputState = new States(keyPairPair.first, serializedStates);
        Log.d(StatesTest.class.getName(), outputState.getSerializedStates());
        assertEquals(states, outputState);
    }

    @Test
    public void canPublicKeyForStateFromHeaderTest() throws GeneralSecurityException, IOException, InterruptedException, JSONException {
        String keystoreAlias = "canDeserializeTest";
        Pair<KeyPair, byte[] > keyPairPair = SecurityECDH.generateKeyPair(keystoreAlias);

        States states = new States();
        states.DHs = keyPairPair.first;
        states.DHr = keyPairPair.first.getPublic();
        states.RK = CryptoHelpers.generateRandomBytes(32);
        states.CKs = CryptoHelpers.generateRandomBytes(32);
        states.CKr = CryptoHelpers.generateRandomBytes(32);
        states.MKSKIPPED.put(new Pair<>(keyPairPair.first.getPublic(), 1),
                CryptoHelpers.generateRandomBytes(32));
        String serializedStates = states.getSerializedStates();
        Log.d(StatesTest.class.getName(), serializedStates);

        States outputState = new States(keyPairPair.first, serializedStates);
        Log.d(StatesTest.class.getName(), outputState.getSerializedStates());
        assertEquals(states, outputState);

        Headers headers = new Headers(keyPairPair.first, 0, 1);
        PublicKey publicKey = States.getADForHeaders(states, headers);

        assertEquals(keyPairPair.first.getPublic(), publicKey);
    }
}
