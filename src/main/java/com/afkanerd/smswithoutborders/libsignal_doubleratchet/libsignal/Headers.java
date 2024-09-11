package com.afkanerd.smswithoutborders.libsignal_doubleratchet.libsignal;

import android.util.Pair;

import androidx.annotation.Nullable;

import com.google.common.primitives.Bytes;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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

    public Headers(byte[] dh, int PN, int N) {
        this.dh = dh;
        this.PN = PN;
        this.N = N;
    }

    public Headers() {}

    public static Headers deSerializeHeader(byte[] serializedHeader) throws NumberFormatException {
        byte[] bytesPN = new byte[4];
        System.arraycopy(serializedHeader, 0, bytesPN, 0, 4);
        int PN = ByteBuffer.wrap(bytesPN).order(ByteOrder.LITTLE_ENDIAN).getInt();

        byte[] bytesN = new byte[4];
        System.arraycopy(serializedHeader, 4, bytesN, 0, 4);
        int N = ByteBuffer.wrap(bytesN).order(ByteOrder.LITTLE_ENDIAN).getInt();

        byte[] pubKey = new byte[serializedHeader.length - 8];
        System.arraycopy(serializedHeader, 8, pubKey, 0, pubKey.length);

        return new Headers(pubKey, PN, N);
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
        ByteBuffer.wrap(bytesPN).order(ByteOrder.LITTLE_ENDIAN).putInt(this.PN);

        byte[] bytesN = new byte[4];
        ByteBuffer.wrap(bytesN).order(ByteOrder.LITTLE_ENDIAN).putInt(this.N);

        return Bytes.concat(bytesPN, bytesN, this.dh);
    }
}
