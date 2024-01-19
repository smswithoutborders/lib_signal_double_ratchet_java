package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import android.util.Pair;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityECDH;
import com.google.common.primitives.Bytes;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

@RunWith(AndroidJUnit4.class)
public class HeadersTest {

    @Test
    public void canDeserializeTest() throws GeneralSecurityException, IOException, InterruptedException, ClassNotFoundException {
        String keystoreAlias = "canDeserializeTest";
        Pair<KeyPair, byte[] > keyPairPair = SecurityECDH.generateKeyPair(keystoreAlias);
        Headers headers = new Headers(keyPairPair.first, 0, 0);
        byte[] output = headers.getSerialized();
        byte[] expectedCipherText = "Hello, world".getBytes(StandardCharsets.UTF_8);
        output = Bytes.concat(output, expectedCipherText);

        Headers expectedHeaders = new Headers();
        byte[] cipherText = expectedHeaders.deSerializeHeader(output);

        assertEquals(expectedHeaders, headers);
        assertArrayEquals(expectedCipherText, cipherText);
    }
}
