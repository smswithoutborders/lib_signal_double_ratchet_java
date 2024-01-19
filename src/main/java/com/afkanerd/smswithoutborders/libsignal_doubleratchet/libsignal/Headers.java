package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import android.util.Base64;
import android.util.Log;

import androidx.annotation.Nullable;

import com.afkanerd.smswithoutborders.libsignal_doubleratchet.SecurityECDH;
import com.google.common.primitives.Bytes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Headers {

    public PublicKey dh;
    public int PN;
    public int N;

    public Headers(KeyPair dhPair, int PN, int N) {
        this.dh = dhPair.getPublic();
        this.PN = PN;
        this.N = N;
    }

    public Headers() {}

    public byte[] deSerializeHeader(byte[] serializedHeader) throws NoSuchAlgorithmException, InvalidKeySpecException,
            NumberFormatException, IOException, ClassNotFoundException {
        byte[] bytesLen = new byte[4];
        System.arraycopy(serializedHeader, 0, bytesLen, 0, 4);
        int len = ByteBuffer.wrap(bytesLen).getInt();

        byte[] bytesPN = new byte[4];
        System.arraycopy(serializedHeader, 4, bytesPN, 0, 4);
        this.PN = ByteBuffer.wrap(bytesPN).getInt();

        byte[] bytesN = new byte[4];
        System.arraycopy(serializedHeader, 8, bytesN, 0, 4);
        this.N = ByteBuffer.wrap(bytesN).getInt();

        byte[] pubKey = new byte[len - 12];
        System.arraycopy(serializedHeader, 12, pubKey, 0, pubKey.length);
        this.dh = SecurityECDH.buildPublicKey(pubKey);

        if(serializedHeader.length > len) {
            byte[] buffer = new byte[serializedHeader.length - len];
            System.arraycopy(serializedHeader, 12 + pubKey.length, buffer, 0, buffer.length);
            return buffer;
        }
        return null;
    }

    @Override
    public boolean equals(@Nullable Object obj) {
        if(obj instanceof Headers) {
            Headers header = (Headers) obj;
            return Arrays.equals(header.dh.getEncoded(), this.dh.getEncoded()) &&
                    header.PN == this.PN &&
                    header.N == this.N;
        }
        return false;
    }

    public byte[] getSerialized() throws IOException {
        byte[] bytesPN = new byte[4];
        ByteBuffer.wrap(bytesPN).putInt(this.PN);

        byte[] bytesN = new byte[4];
        ByteBuffer.wrap(bytesN).putInt(this.N);

        byte[] pubKey = this.dh.getEncoded();

        int len = 4 + bytesPN.length + bytesN.length + pubKey.length;
        byte[] bytesLen = new byte[4];
        ByteBuffer.wrap(bytesLen).putInt(len);

        return Bytes.concat(bytesLen, bytesPN, bytesN, pubKey);
    }
}
