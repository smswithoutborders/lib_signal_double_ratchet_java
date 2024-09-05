package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import android.util.Pair;

import androidx.annotation.Nullable;

import com.google.common.primitives.Bytes;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Headers {

    public byte[] dh;
    public int PN;
    public int N;

    /**
     *
     * @param dhPair This is a public key
     * @param PN
     * @param N
     */
    public Headers(Pair<byte[], byte[]> dhPair, int PN, int N) {
        this.dh = dhPair.second;
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
        this.dh = pubKey;

        if(serializedHeader.length > len) {
            byte[] buffer = new byte[serializedHeader.length - len];
            System.arraycopy(serializedHeader, 12 + pubKey.length, buffer, 0, buffer.length);
            return buffer;
        }
        return null;
    }

    @Override
    public boolean equals(@Nullable Object obj) {
        if(obj instanceof Headers header) {
            return Arrays.equals(header.dh, this.dh) &&
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

        byte[] pubKey = this.dh;

        int len = 4 + bytesPN.length + bytesN.length + pubKey.length;
        byte[] bytesLen = new byte[4];
        ByteBuffer.wrap(bytesLen).putInt(len);

        return Bytes.concat(bytesLen, bytesPN, bytesN, pubKey);
    }
}
